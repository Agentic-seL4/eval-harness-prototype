/*
 * Trace records (PROTOCOL.md section 5): one line per record, a tag, a space
 * and a JSON object. A record is built in a buffer and printed whole by
 * tr_end(); a record that does not fit is replaced by an ERR record.
 *
 *     tr_begin("NOTE");
 *     tr_key("pd"); tr_cstr(microkit_name);
 *     tr_key("event"); tr_cstr("start");
 *     tr_end();
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "protocol.h"

void tr_begin(const char *tag);
void tr_key(const char *key);
void tr_bytes(const uint8_t *s, size_t n);
void tr_cstr(const char *s);
void tr_value(const struct value *v);
void tr_uint(uint64_t n);
void tr_null(void);
void tr_obj_begin(void);
void tr_obj_end(void);
void tr_arr_begin(void);
void tr_arr_end(void);
/* A permission set as a sorted list of tool names. */
void tr_perms(uint32_t mask);
/* A tool name, or null for an unknown tool. */
void tr_tool(uint64_t tool);
void tr_end(void);

/* The last record printed by tr_end(), newline included; length 0 if it failed. */
const char *tr_last_line(size_t *line_length);

/* The common case: NOTE or ERR with this PD's name and one string field. */
void tr_simple(const char *tag, const char *key, const char *text);

const char *tool_name(uint64_t tool);
