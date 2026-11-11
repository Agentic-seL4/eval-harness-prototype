/*
 * Build-time configuration (PROTOCOL.md section 6). The Makefile passes
 * CFG_POLICY and CFG_INBOX_ALLOWED to the broker and CFG_MODE to the worker.
 */
#pragma once

#define POLICY_OPEN 0
#define POLICY_FENCED 1
#define POLICY_LATE 2

#define MODE_REFERENCE 0
#define MODE_INJECTED 1

static inline const char *policy_name(int policy)
{
    switch (policy) {
    case POLICY_OPEN: return "open";
    case POLICY_FENCED: return "fenced";
    case POLICY_LATE: return "late";
    default: return "unknown";
    }
}

static inline const char *mode_name(int mode)
{
    return mode == MODE_INJECTED ? "injected" : mode == MODE_REFERENCE ? "reference" : "unknown";
}

/*
 * Confinement tests (T9). These select a worker that deliberately misbehaves, so
 * we can observe that the kernel or the broker stops it and the secret never
 * reaches the sink. They exist only to evaluate the confinement of our own QEMU
 * prototype; none is an attack on anything outside it. CFG_ATTACK selects one.
 *
 *   NONE            the honest scripted worker (the default; T7/T8 behaviour)
 *   UNINJECTED      calls Fetch[Secret] with no injection, before the email is read
 *                   -- allowed under every policy (Q2: a malicious agent, not an
 *                      injection; relative security does not cover it)
 *   LIB_CHANNEL     asks libmicrokit to call a channel the worker does not hold
 *                   -- the library refuses (advisory check inside the PD)
 *   RAW_SINK        ignores the library and invokes the kernel on a slot it lacks
 *                   -- the kernel faults the worker (the real boundary)
 *   FORGE_ORIGIN    sends a trusted READ_T as if it were the runner
 *                   -- the broker rejects it: the caller channel is unforgeable
 *   WRITE_CONTEXT   writes a forged email into its read-only context mapping
 *                   -- the kernel faults the worker
 *   UNMAPPED        reads an address it has no mapping for
 *                   -- the kernel faults the worker
 *   MALFORMED       sends a structurally invalid request to the broker
 *                   -- the broker rejects it
 */
#define ATTACK_NONE 0
#define ATTACK_UNINJECTED 1
#define ATTACK_LIB_CHANNEL 2
#define ATTACK_RAW_SINK 3
#define ATTACK_FORGE_ORIGIN 4
#define ATTACK_WRITE_CONTEXT 5
#define ATTACK_UNMAPPED 6
#define ATTACK_MALFORMED 7

static inline const char *attack_name(int attack)
{
    switch (attack) {
    case ATTACK_NONE: return "none";
    case ATTACK_UNINJECTED: return "uninjected-leak";
    case ATTACK_LIB_CHANNEL: return "undeclared-channel-lib";
    case ATTACK_RAW_SINK: return "undeclared-channel-raw";
    case ATTACK_FORGE_ORIGIN: return "forge-origin";
    case ATTACK_WRITE_CONTEXT: return "write-readonly";
    case ATTACK_UNMAPPED: return "read-unmapped";
    case ATTACK_MALFORMED: return "malformed-request";
    default: return "unknown";
    }
}
