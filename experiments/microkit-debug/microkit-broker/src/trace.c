#include <microkit.h>
#include "trace.h"
#include "util.h"

#define LINE_MAX 8192
#define DEPTH_MAX 8

static char line[LINE_MAX];
static size_t length;
static int broken;  /* overflow or unbalanced nesting */
static size_t printed;  /* length of the last record printed, 0 if none */
static unsigned depth;
static uint8_t in_array[DEPTH_MAX];
static uint8_t has_items[DEPTH_MAX];

static void put(char c)
{
    /* Keep two bytes for the final newline and terminator. */
    if (length + 2 < LINE_MAX) {
        line[length++] = c;
    } else {
        broken = 1;
    }
}

static void put_raw(const char *s)
{
    while (*s) {
        put(*s++);
    }
}

/* Inside an array, separate this value from the previous one. */
static void before_value(void)
{
    if (depth > 0 && in_array[depth - 1]) {
        if (has_items[depth - 1]) {
            put(',');
        }
        has_items[depth - 1] = 1;
    }
}

static void push(char c, int array)
{
    before_value();
    put(c);
    if (depth < DEPTH_MAX) {
        in_array[depth] = array;
        has_items[depth] = 0;
        depth++;
    } else {
        broken = 1;
    }
}

static void pop(char c)
{
    put(c);
    if (depth > 0) {
        depth--;
    } else {
        broken = 1;
    }
}

void tr_begin(const char *tag)
{
    printed = 0;
    length = 0;
    broken = 0;
    depth = 0;
    put_raw(tag);
    put(' ');
    push('{', 0);
}

void tr_key(const char *key)
{
    if (depth == 0 || in_array[depth - 1]) {
        broken = 1;
        return;
    }
    if (has_items[depth - 1]) {
        put(',');
    }
    has_items[depth - 1] = 1;
    put('"');
    put_raw(key);
    put_raw("\":");
}

void tr_bytes(const uint8_t *s, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    before_value();
    put('"');
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') {
            put('\\');
            put((char)c);
        } else if (c >= 0x20 && c <= 0x7e) {
            put((char)c);
        } else {
            put_raw("\\u00");
            put(hex[c >> 4]);
            put(hex[c & 15]);
        }
    }
    put('"');
}

void tr_cstr(const char *s)
{
    tr_bytes((const uint8_t *)s, cstr_len(s));
}

void tr_value(const struct value *v)
{
    tr_bytes(v->data, v->length <= MAX_VALUE ? v->length : MAX_VALUE);
}

void tr_uint(uint64_t n)
{
    char digits[21];
    int i = 20;
    digits[i] = '\0';
    do {
        digits[--i] = (char)('0' + n % 10);
        n /= 10;
    } while (n);
    before_value();
    put_raw(&digits[i]);
}

void tr_null(void)
{
    before_value();
    put_raw("null");
}

void tr_obj_begin(void)
{
    push('{', 0);
}

void tr_obj_end(void)
{
    pop('}');
}

void tr_arr_begin(void)
{
    push('[', 1);
}

void tr_arr_end(void)
{
    pop(']');
}

const char *tool_name(uint64_t tool)
{
    switch (tool) {
    case TOOL_INBOX: return "Inbox";
    case TOOL_FETCH: return "Fetch";
    default: return 0;
    }
}

void tr_perms(uint32_t mask)
{
    /* Alphabetical, as core.py sorts permission sets. */
    static const uint64_t order[] = { TOOL_FETCH, TOOL_INBOX };
    tr_arr_begin();
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        if (mask & TOOL_BIT(order[i])) {
            tr_cstr(tool_name(order[i]));
        }
    }
    tr_arr_end();
}

void tr_tool(uint64_t tool)
{
    const char *name = tool_name(tool);
    if (name) {
        tr_cstr(name);
    } else {
        tr_null();
    }
}

void tr_end(void)
{
    pop('}');
    if (broken || depth != 0) {
        microkit_dbg_puts("ERR {\"pd\":\"");
        microkit_dbg_puts(microkit_name);
        microkit_dbg_puts("\",\"error\":\"trace record too long or malformed\"}\n");
        return;
    }
    line[length++] = '\n';
    line[length] = '\0';
    printed = length;
    microkit_dbg_puts(line);
}

const char *tr_last_line(size_t *line_length)
{
    *line_length = printed;
    return line;
}

void tr_simple(const char *tag, const char *key, const char *text)
{
    tr_begin(tag);
    tr_key("pd");
    tr_cstr(microkit_name);
    tr_key(key);
    tr_cstr(text);
    tr_end();
}
