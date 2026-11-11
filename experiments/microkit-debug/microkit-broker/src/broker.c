/*
 * Broker PD: holds the monitor and carries out every composite step
 * (DESIGN.md section 3, PROTOCOL.md sections 3 and 4).
 *
 * Each accepted request is one step. The broker copies the request out of the
 * message registers first, lets monitor_step() decide and update the state, and
 * only then carries out the effect: delivering the email to the context, or
 * committing a call to the sink. It prints one TRACE record per step.
 */
#include <stdint.h>
#include <microkit.h>
#include "config.h"
#include "monitor.h"
#include "mr.h"
#include "protocol.h"
#include "topology.h"
#include "trace.h"
#include "util.h"

#ifndef CFG_POLICY
#error "CFG_POLICY must be set by the Makefile"
#endif
#ifndef CFG_INBOX_ALLOWED
#error "CFG_INBOX_ALLOWED must be set by the Makefile"
#endif

/* Patched in by the Microkit tool (broker.system). */
uintptr_t secret;
uintptr_t secret_prefill_size;
uintptr_t inbox;
uintptr_t inbox_prefill_size;
uintptr_t context;

static struct cap_params params;
static perms_t perms;            /* the monitor state */
static uint64_t steps;           /* composite steps taken so far */
static uint64_t inbox_consumed;  /* seq of the last email taken from the mailbox */
static int regions_ok;
static int runner_waiting;       /* READ_U answered R_NOT_READY; wake the runner on arrival */

/* Broker-owned copies: nothing below is read from shared memory twice. */
static struct value trusted;
static struct value email;
static struct call_args request;

/* Check the prefilled regions before trusting their length fields. */
static const char *region_error(void)
{
    const struct value *s = (const struct value *)secret;
    const struct mailbox *m = (const struct mailbox *)inbox;
    if (secret_prefill_size != sizeof(struct value) || s->length > MAX_VALUE) {
        return "secret region does not hold a value";
    }
    if (inbox_prefill_size != sizeof(struct mailbox) ||
        memcmp(m->magic, MAILBOX_MAGIC, sizeof(m->magic)) != 0 || m->length > MAX_VALUE) {
        return "inbox region does not hold a mailbox";
    }
    return 0;
}

/*
 * Take the next complete email from the mailbox into `email`.
 * Returns 1 if taken, 0 if none is ready, -1 if the mailbox is malformed.
 */
static int take_email(void)
{
    const volatile struct mailbox *m = (const volatile struct mailbox *)inbox;
    uint64_t seq = m->seq;
    if (seq == inbox_consumed) {
        return 0;
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint64_t length = m->length;
    if (length > MAX_VALUE) {
        return -1;
    }
    for (uint64_t i = 0; i < length; i++) {
        email.data[i] = m->data[i];
    }
    email.length = length;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (m->seq != seq) {
        return 0;  /* the writer replaced the email while we copied it */
    }
    inbox_consumed = seq;
    return 1;
}

/* Append to the context: fill the item, then publish it by incrementing count. */
static int deliver(const struct value *v)
{
    struct context *c = (struct context *)context;
    if (c->count >= MAX_CONTEXT) {
        return 0;
    }
    value_copy(&c->item[c->count], v);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    c->count++;
    return 1;
}

static uint64_t context_count(void)
{
    return ((const struct context *)context)->count;
}

static void error(microkit_channel ch, const char *what)
{
    tr_begin("ERR");
    tr_key("pd");
    tr_cstr(microkit_name);
    tr_key("error");
    tr_cstr(what);
    tr_key("channel");
    tr_uint(ch);
    tr_end();
}

static void trace_args(const struct call_args *call)
{
    tr_arr_begin();
    for (uint64_t i = 0; i < call->nargs; i++) {
        tr_bytes(call->data[i], call->length[i]);
    }
    tr_arr_end();
}

/* One TRACE record (PROTOCOL.md section 5), keys in the documented order. */
static void trace_step(const char *caller, const char *event, uint64_t tool,
                       const struct call_args *call, const struct value *value,
                       const struct monitor_step *r, perms_t before, int decided, int admitted,
                       int committed)
{
    tr_begin("TRACE");
    tr_key("step");
    tr_uint(steps);
    tr_key("caller");
    tr_cstr(caller);
    tr_key("event");
    tr_cstr(event);
    tr_key("tool");
    if (tool) {
        tr_tool(tool);
    } else {
        tr_null();
    }
    tr_key("args");
    if (call) {
        trace_args(call);
    } else {
        tr_null();
    }
    tr_key("value");
    if (value) {
        tr_value(value);
    } else {
        tr_null();
    }
    tr_key("decision");
    if (r->decision) {
        tr_cstr(r->decision == R_ALLOWED ? "Allowed" : "Denied");
    } else {
        tr_null();
    }
    tr_key("perms_before");
    tr_perms(before);
    tr_key("perms_decided");
    if (decided) {
        tr_perms(r->decided);
    } else {
        tr_null();
    }
    tr_key("perms_admitted");
    if (admitted) {
        tr_perms(r->admitted);
    } else {
        tr_null();
    }
    tr_key("perms_after");
    tr_perms(r->after);
    tr_key("context_len");
    tr_uint(context_count());
    tr_key("effect");
    if (committed) {
        tr_obj_begin();
        tr_key("tool");
        tr_tool(call->tool);
        tr_key("args");
        trace_args(call);
        tr_obj_end();
    } else {
        tr_null();
    }
    tr_end();
}

static microkit_msginfo reply(uint64_t result, unsigned count)
{
    return microkit_msginfo_new(result, (uint16_t)count);
}

static microkit_msginfo read_trusted(void)
{
    perms_t before = perms;
    value_copy(&trusted, (const struct value *)secret);
    struct monitor_step r = monitor_step(&params, perms, STEP_READ_T, 0, context_count() > 0);
    perms = r.after;
    steps++;
    trace_step("runner", "AReadT", 0, 0, &trusted, &r, before, 0, 0, 0);
    unsigned index = 0;
    mr_put_value(&index, trusted.data, trusted.length);
    return reply(R_ALLOWED, index);
}

static microkit_msginfo read_untrusted(microkit_channel ch, uint64_t tool)
{
    int taken = take_email();
    if (taken < 0) {
        error(ch, "inbox mailbox is malformed");
        return reply(R_ERROR, 0);
    }
    if (taken == 0) {
        /* Not a step: nothing was read. The runner retries when the email arrives. */
        runner_waiting = 1;
        tr_simple("NOTE", "event", "inbox not ready; runner waits");
        return reply(R_NOT_READY, 0);
    }
    perms_t before = perms;
    int context_before = context_count() > 0;
    /* Decide on the tool alone and update the state before any delivery (C-ReadU). */
    struct monitor_step r = monitor_step(&params, perms, STEP_READ_U, tool, context_before);
    perms = r.after;
    int allowed = r.decision == R_ALLOWED;
    if (allowed && !deliver(&email)) {
        error(ch, "context is full");
        return reply(R_ERROR, 0);
    }
    steps++;
    trace_step("runner", "AReadU", tool, 0, &email, &r, before, 1, allowed, 0);
    if (!allowed) {
        return reply(R_DENIED, 0);
    }
    unsigned index = 0;
    mr_put_value(&index, email.data, email.length);
    return reply(R_ALLOWED, index);
}

static microkit_msginfo call(const char *caller)
{
    perms_t before = perms;
    struct monitor_step r = monitor_step(&params, perms, STEP_CALL, request.tool, context_count() > 0);
    perms = r.after;
    int allowed = r.decision == R_ALLOWED;
    if (allowed) {
        /* The nested call reuses the message registers; request is our copy. */
        unsigned index = 0;
        mr_put_call(&index, &request);
        microkit_msginfo answer = microkit_ppcall(BROKER_CH_SINK, microkit_msginfo_new(OP_COMMIT, (uint16_t)index));
        if (microkit_msginfo_get_label(answer) != R_ALLOWED) {
            error(BROKER_CH_SINK, "sink did not accept the commit");
        }
    }
    steps++;
    trace_step(caller, "ACall", request.tool, &request, 0, &r, before, 1, 0, allowed);
    return reply(allowed ? R_ALLOWED : R_DENIED, 0);
}

static microkit_msginfo tau(void)
{
    perms_t before = perms;
    struct monitor_step r = monitor_step(&params, perms, STEP_TAU, 0, context_count() > 0);
    perms = r.after;
    steps++;
    trace_step("runner", "ATau", 0, 0, 0, &r, before, 0, 0, 0);
    return reply(R_ALLOWED, 0);
}

void init(void)
{
    params = cap_params(CFG_POLICY, CFG_INBOX_ALLOWED);
    perms = params.caps0;

    tr_begin("CONFIG");
    tr_key("pd");
    tr_cstr(microkit_name);
    tr_key("policy");
    tr_cstr(policy_name(CFG_POLICY));
    tr_key("initial_perms");
    tr_perms(perms);
    tr_end();

    const char *problem = region_error();
    if (problem) {
        tr_simple("ERR", "error", problem);
        return;
    }
    regions_ok = 1;
    const struct value *s = (const struct value *)secret;
    const struct mailbox *m = (const struct mailbox *)inbox;
    tr_begin("NOTE");
    tr_key("pd");
    tr_cstr(microkit_name);
    tr_key("event");
    tr_cstr("start");
    tr_key("secret_len");
    tr_uint(s->length);
    tr_key("inbox_seq");
    tr_uint(m->seq);
    tr_key("inbox_len");
    tr_uint(m->length);
    tr_key("context_count");
    tr_uint(context_count());
    tr_end();
}

void notified(microkit_channel ch)
{
#if !CFG_HOST_BACKEND
    if (ch == BROKER_CH_NET && runner_waiting) {
        runner_waiting = 0;
        microkit_notify(BROKER_CH_RUNNER);
    }
#else
    (void)ch;
#endif
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    uint64_t op = microkit_msginfo_get_label(msginfo);
    unsigned count = (unsigned)microkit_msginfo_get_count(msginfo);
    const char *caller = ch == BROKER_CH_RUNNER ? "runner" : ch == BROKER_CH_WORKER ? "worker" : 0;

    if (!regions_ok || !caller) {
        error(ch, regions_ok ? "request on an unexpected channel" : "regions failed their start-up check");
        return reply(R_ERROR, 0);
    }
    /* Only the runner advances the plan; calls are decided whoever makes them (Q1a). */
    if (op != OP_CALL && ch != BROKER_CH_RUNNER) {
        error(ch, "only the runner may read or take internal steps");
        return reply(R_ERROR, 0);
    }
    switch (op) {
    case OP_READ_T:
        if (count != 0) {
            break;
        }
        return read_trusted();
    case OP_READ_U: {
        uint64_t tool = count == 1 ? microkit_mr_get(0) : 0;
        if (!tool_name(tool)) {
            break;
        }
        return read_untrusted(ch, tool);
    }
    case OP_CALL:
        if (!mr_get_call(count, &request) || !tool_name(request.tool)) {
            break;
        }
        return call(caller);
    case OP_TAU:
        if (count != 0) {
            break;
        }
        return tau();
    default:
        break;
    }
    error(ch, "malformed request");
    return reply(R_ERROR, 0);
}
