/*
 * The capability monitor of Agent_Compose.thy (capDecide, capObs) as pure C,
 * with the parameters of the email instances E1L (Email_Leak.thy) and E1F
 * (Email_Fenced.thy). No Microkit dependency: tests/test_monitor.py builds this
 * file on the host and compares it with email-fence/core.py.
 */
#pragma once

#include <stdint.h>

/* The capability set C: a bit mask over TOOL_BIT(tool). */
typedef uint32_t perms_t;

/* The labels capObs distinguishes. */
#define EV_READ_T 1  /* AReadT v */
#define EV_READ_U 2  /* AReadU t v, applied only after an allowed read */
#define EV_NEW 3     /* ANew: leaves C unchanged */

struct cap_params {
    perms_t caps0;        /* initial capabilities */
    perms_t grant_on_t;   /* grantOn v; the email instances grant nothing for any v */
    perms_t revoke_on_u;  /* revokeOnU */
    int late_fetch;       /* core.py's deliberately late revocation, not a paper monitor */
};

/*
 * Parameters for a build policy: open is E1L ({Fetch, Inbox}, no revocation),
 * fenced is E1F (revokeOnU = {Fetch}), late is E1L plus the late runtime bug.
 * Without Inbox, the initial set is {Fetch} (email-fence's denied-inbox fixture).
 */
struct cap_params cap_params(int policy, int inbox_allowed);

/*
 * capDecide with the email instances' contract (always true, so the arguments are
 * not consulted): Allowed iff the tool is held. The state is never changed.
 * Returns R_ALLOWED or R_DENIED; unknown tools are never held.
 */
int cap_decide(perms_t caps, uint64_t tool, perms_t *next);

/* capObs: grantOn on a trusted read, minus revokeOnU on an untrusted read. */
perms_t cap_obs(const struct cap_params *p, perms_t caps, int event);

/* The broker's composite steps (fig:compose; PROTOCOL.md section 4). */
#define STEP_READ_T 1
#define STEP_READ_U 2
#define STEP_CALL 3
#define STEP_TAU 4

struct monitor_step {
    int decision;      /* R_ALLOWED, R_DENIED, or 0 for READ_T and TAU */
    perms_t decided;   /* state returned by cap_decide (READ_U, CALL) */
    perms_t admitted;  /* state after cap_obs on an allowed READ_U */
    perms_t after;     /* state at the end of the step, after any late revocation */
};

/*
 * The monitor's half of one composite step from state caps. context_before is
 * nonzero if the context was non-empty when the step began (the late policy's
 * trigger). The caller carries out the effects: delivery after an allowed read,
 * dispatch after an allowed call.
 */
struct monitor_step monitor_step(const struct cap_params *p, perms_t caps, int step,
                                 uint64_t tool, int context_before);
