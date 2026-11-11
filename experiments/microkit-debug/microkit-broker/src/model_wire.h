/* Version 1 model transport; byte strings are hex encoded, '-' means empty. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include "protocol.h"
#define MODEL_LINE_MAX 2048
struct model_frame { uint64_t seq; uint64_t length; uint8_t data[MODEL_LINE_MAX]; };
_Static_assert(sizeof(struct model_frame) <= 4096, "model mailbox fits a page");
size_t model_request(uint8_t *out, uint64_t id, uint64_t pc, uint64_t q,
                     const struct value *secret_value, const struct value *email);
/* 0 none, 1 Fetch, -1 invalid/error. No guest effect is performed here. */
int model_response(const uint8_t *line, size_t n, uint64_t id,
                   uint8_t *argument, uint64_t *length);
