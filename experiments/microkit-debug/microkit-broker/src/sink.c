/*
 * Sink PD: the fake Fetch tool, standing for the attacker's server.
 * Each committed call becomes one OBS record: the attacker's view. The record goes
 * to the debug console and, from T8b, into obs_out for the net PD to transmit.
 */
#include <stdint.h>
#include <microkit.h>
#include "mr.h"
#include "protocol.h"
#include "topology.h"
#include "trace.h"
#include "util.h"

/* Patched in by the Microkit tool (broker.system). */
uintptr_t obs_out;

/* Append the line just printed; the net PD sends it to the attacker's socket. */
static void forward_last_line(void)
{
    struct obs_log *log = (struct obs_log *)obs_out;
    size_t n;
    const char *line = tr_last_line(&n);
    if (n == 0 || log->length + n > OBS_LOG_CAPACITY) {
        tr_simple("ERR", "error", "OBS line not forwarded (obs_out full)");
        return;
    }
    memcpy(&log->data[log->length], line, n);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    log->length += n;
#if !CFG_HOST_BACKEND
    microkit_notify(SINK_CH_NET);
#endif
}

void init(void)
{
    tr_simple("NOTE", "event", "start");
}

void notified(microkit_channel ch)
{
    (void)ch;
}

microkit_msginfo protected(microkit_channel ch, microkit_msginfo msginfo)
{
    static struct call_args call;
    if (ch != SINK_CH_BROKER || microkit_msginfo_get_label(msginfo) != OP_COMMIT ||
        !mr_get_call((unsigned)microkit_msginfo_get_count(msginfo), &call) || !tool_name(call.tool)) {
        tr_simple("ERR", "error", "malformed commit");
        return microkit_msginfo_new(R_ERROR, 0);
    }
    tr_begin("OBS");
    tr_key("tool");
    tr_tool(call.tool);
    tr_key("args");
    tr_arr_begin();
    for (uint64_t i = 0; i < call.nargs; i++) {
        tr_bytes(call.data[i], call.length[i]);
    }
    tr_arr_end();
    tr_end();
    forward_last_line();
    return microkit_msginfo_new(R_ALLOWED, 0);
}
