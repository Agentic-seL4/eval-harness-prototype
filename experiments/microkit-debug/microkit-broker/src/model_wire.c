#include <stddef.h>
#include "model_wire.h"
#include "util.h"

static void number(uint8_t *out, size_t *n, uint64_t v)
{
    char buf[20]; size_t k = 0;
    do { buf[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (k) { out[(*n)++] = (uint8_t)buf[--k]; }
}
static void hex(uint8_t *out, size_t *n, const struct value *v)
{
    const char *digits = "0123456789abcdef";
    if (!v->length) { out[(*n)++] = '-'; }
    for (uint64_t i = 0; i < v->length; i++) {
        out[(*n)++] = digits[v->data[i] >> 4];
        out[(*n)++] = digits[v->data[i] & 15];
    }
}
size_t model_request(uint8_t *out, uint64_t id, uint64_t pc, uint64_t q,
                     const struct value *s, const struct value *e)
{
    if (!id || s->length > MAX_VALUE || e->length > MAX_VALUE) { return 0; }
    size_t n = 0;
    memcpy(out, "REQ 1 ", 6); n = 6;
    number(out, &n, id); out[n++] = ' '; number(out, &n, pc);
    out[n++] = ' '; number(out, &n, q); out[n++] = ' ';
    hex(out, &n, s); out[n++] = ' '; hex(out, &n, e); out[n++] = '\n';
    return n;
}
static int digit(uint8_t c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return -1;
}
int model_response(const uint8_t *line, size_t n, uint64_t id,
                   uint8_t *argument, uint64_t *length)
{
    uint8_t prefix[32]; size_t p = 6;
    memcpy(prefix, "RES 1 ", 6); number(prefix, &p, id); prefix[p++] = ' ';
    if (n <= p || n > MODEL_LINE_MAX || memcmp(line, prefix, p)) { return -1; }
    if (n == p + 5 && !memcmp(line + p, "NONE\n", 5)) { *length = 0; return 0; }
    if (n < p + 8 || memcmp(line + p, "FETCH ", 6) || line[n-1] != '\n') { return -1; }
    p += 6;
    if (n == p + 2 && line[p] == '-') { *length = 0; return 1; }
    size_t bytes = n - p - 1;
    if ((bytes & 1) || bytes > 2 * MAX_ARG) { return -1; }
    for (size_t i = 0; i < bytes / 2; i++) {
        int a = digit(line[p+2*i]), b = digit(line[p+2*i+1]);
        if (a < 0 || b < 0) { return -1; }
        argument[i] = (uint8_t)(a * 16 + b);
    }
    *length = bytes / 2;
    return 1;
}
