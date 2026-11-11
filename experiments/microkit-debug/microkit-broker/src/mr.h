/*
 * Values and call arguments in message registers (PROTOCOL.md section 3).
 * A value is its length, then its bytes packed eight per word, little-endian.
 */
#pragma once

#include <stdint.h>
#include "protocol.h"

/* Microkit passes at most 64 words with a call or a reply. */
#define MR_LIMIT 64

/* A call's tool and arguments, copied out of the message registers. */
struct call_args {
    uint64_t tool;
    uint64_t nargs;
    uint64_t length[MAX_ARGS];
    uint8_t data[MAX_ARGS][MAX_ARG];
};

/* Write a value at *index; returns 0 if it would not fit. */
int mr_put_value(unsigned *index, const uint8_t *data, uint64_t length);
/* Read a value at *index of a message with count registers; returns 0 if malformed
 * or longer than max. */
int mr_get_value(unsigned *index, unsigned count, uint8_t *data, uint64_t max, uint64_t *length);

/* OP_CALL / OP_COMMIT payload: MR0 tool, MR1 nargs, then each argument. */
int mr_put_call(unsigned *index, const struct call_args *call);
/* Returns 0 unless the message is exactly one well-formed call payload. */
int mr_get_call(unsigned count, struct call_args *call);
