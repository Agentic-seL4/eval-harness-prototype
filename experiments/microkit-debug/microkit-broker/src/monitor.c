#include "config.h"
#include "monitor.h"
#include "protocol.h"

static int held(perms_t caps, uint64_t tool)
{
    return tool < 32 && ((caps >> tool) & 1u);
}

struct cap_params cap_params(int policy, int inbox_allowed)
{
    struct cap_params p;
    p.caps0 = TOOL_BIT(TOOL_FETCH) | (inbox_allowed ? TOOL_BIT(TOOL_INBOX) : 0);
    p.grant_on_t = 0;
    p.revoke_on_u = policy == POLICY_FENCED ? TOOL_BIT(TOOL_FETCH) : 0;
    p.late_fetch = policy == POLICY_LATE;
    return p;
}

int cap_decide(perms_t caps, uint64_t tool, perms_t *next)
{
    *next = caps;
    return held(caps, tool) ? R_ALLOWED : R_DENIED;
}

perms_t cap_obs(const struct cap_params *p, perms_t caps, int event)
{
    switch (event) {
    case EV_READ_T: return caps | p->grant_on_t;
    case EV_READ_U: return caps & ~p->revoke_on_u;
    default: return caps;
    }
}

struct monitor_step monitor_step(const struct cap_params *p, perms_t caps, int step,
                                 uint64_t tool, int context_before)
{
    struct monitor_step r = { 0, caps, caps, caps };
    switch (step) {
    case STEP_READ_T:
        r.after = cap_obs(p, caps, EV_READ_T);
        break;
    case STEP_READ_U:
        /* C-ReadU: decide on the tool alone, then update before delivery. */
        r.decision = cap_decide(caps, tool, &r.decided);
        r.admitted = r.decision == R_ALLOWED ? cap_obs(p, r.decided, EV_READ_U) : r.decided;
        r.after = r.admitted;
        break;
    case STEP_CALL:
        /* C-Call: a call changes the state only through the decision. */
        r.decision = cap_decide(caps, tool, &r.decided);
        r.after = r.decided;
        break;
    default: /* STEP_TAU: no decision, no update */
        break;
    }
    if (p->late_fetch && context_before && held(r.after, TOOL_FETCH)) {
        r.after &= ~TOOL_BIT(TOOL_FETCH);
    }
    return r;
}
