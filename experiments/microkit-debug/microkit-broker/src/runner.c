/*
 * Runner PD: the trusted interpreter of the fixed plan e1_prog
 * (Email_Setting.thy): ReadT Secret; ReadU Mail Inbox; Assign Summary := Mail.
 *
 * Before each planned step the worker gets one turn (PROTOCOL.md section 1);
 * the runner takes the step when the worker signals that its turn is over.
 */
#include <stdint.h>
#include <microkit.h>
#include "mr.h"
#include "protocol.h"
#include "topology.h"
#include "trace.h"
#include "util.h"

#define PLAN_STEPS 3

/* Patched in by the Microkit tool (broker.system). */
uintptr_t plan_mem;

static int stopped;
static int waiting;  /* for the broker's signal that an email has arrived */

static struct plan_mem *mem(void)
{
    return (struct plan_mem *)plan_mem;
}

static void stop(const char *problem)
{
    stopped = 1;
    tr_simple("ERR", "error", problem);
}

/* Store a value from the reply's message registers into a plan variable. */
static int store_reply(microkit_msginfo answer, int var)
{
    struct value *v = &mem()->var[var];
    unsigned index = 0;
    uint64_t length;
    if (!mr_get_value(&index, (unsigned)microkit_msginfo_get_count(answer), v->data, MAX_VALUE, &length)) {
        return 0;
    }
    v->length = length;
    return 1;
}

static void read_trusted(void)
{
    microkit_msginfo answer = microkit_ppcall(RUNNER_CH_BROKER, microkit_msginfo_new(OP_READ_T, 0));
    if (microkit_msginfo_get_label(answer) != R_ALLOWED || !store_reply(answer, VAR_SECRET)) {
        stop("trusted read failed");
    }
}

/* Returns 0 if the email has not arrived yet; the runner then waits. */
static int read_untrusted(void)
{
    microkit_mr_set(0, TOOL_INBOX);
    microkit_msginfo answer = microkit_ppcall(RUNNER_CH_BROKER, microkit_msginfo_new(OP_READ_U, 1));
    switch (microkit_msginfo_get_label(answer)) {
    case R_ALLOWED:
        if (!store_reply(answer, VAR_MAIL)) {
            stop("malformed email in reply");
        }
        break;
    case R_DENIED:
        value_set_cstr(&mem()->var[VAR_MAIL], "Done");  /* okv = fail = Done */
        break;
    case R_NOT_READY:
        return 0;
    default:
        stop("untrusted read failed");
    }
    return 1;
}

static void assign_summary(void)
{
    value_copy(&mem()->var[VAR_SUMMARY], &mem()->var[VAR_MAIL]);
    microkit_msginfo answer = microkit_ppcall(RUNNER_CH_BROKER, microkit_msginfo_new(OP_TAU, 0));
    if (microkit_msginfo_get_label(answer) != R_ALLOWED) {
        stop("internal step was not acknowledged");
    }
}

static void finish(void)
{
    static const char *names[NUM_VARS] = { "Secret", "Mail", "Summary", "Result" };
    tr_begin("MEM");
    tr_key("pc");
    tr_uint(mem()->pc);
    tr_key("memory");
    tr_obj_begin();
    for (int i = 0; i < NUM_VARS; i++) {
        tr_key(names[i]);
        tr_value(&mem()->var[i]);
    }
    tr_obj_end();
    tr_end();
    tr_begin("DONE");
    tr_end();
}

void init(void)
{
    /* Every variable starts as Data 0, as in Email_Setting.thy. */
    mem()->pc = 0;
    for (int i = 0; i < NUM_VARS; i++) {
        value_set_cstr(&mem()->var[i], "Data 0");
    }
    tr_begin("NOTE");
    tr_key("pd");
    tr_cstr(microkit_name);
    tr_key("event");
    tr_cstr("start");
    tr_key("pc");
    tr_uint(mem()->pc);
    tr_end();
    microkit_notify(RUNNER_CH_WORKER);  /* the worker's turn before step 1 */
}

void notified(microkit_channel ch)
{
    /* The worker ends its turn; or the broker reports that the email has arrived. */
    microkit_channel expected = waiting ? RUNNER_CH_BROKER : RUNNER_CH_WORKER;
    if (ch != expected || stopped || mem()->pc >= PLAN_STEPS) {
        return;
    }
    waiting = 0;
    switch (mem()->pc) {
    case 0: read_trusted(); break;
    case 1: waiting = !read_untrusted(); break;
    default: assign_summary(); break;
    }
    if (stopped || waiting) {
        return;
    }
    mem()->pc++;
    if (mem()->pc < PLAN_STEPS) {
        microkit_notify(RUNNER_CH_WORKER);  /* the worker's turn before the next step */
    } else {
        finish();
    }
}
