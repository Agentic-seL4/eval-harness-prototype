#include "util.h"

/* The compiler may emit calls to these for struct copies and initialisation. */
void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = dst;
    while (n--) {
        *d++ = (unsigned char)c;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++) {
        if (*x != *y) {
            return *x < *y ? -1 : 1;
        }
    }
    return 0;
}

size_t cstr_len(const char *s)
{
    size_t n = 0;
    while (s[n]) {
        n++;
    }
    return n;
}

void value_set_cstr(struct value *v, const char *s)
{
    size_t n = cstr_len(s);
    if (n > MAX_VALUE) {
        n = MAX_VALUE;
    }
    v->length = n;
    memcpy(v->data, s, n);
}

void value_copy(struct value *dst, const struct value *src)
{
    uint64_t n = src->length <= MAX_VALUE ? src->length : MAX_VALUE;
    dst->length = n;
    memcpy(dst->data, src->data, n);
}

int value_contains(const struct value *v, const char *needle)
{
    size_t n = cstr_len(needle);
    uint64_t length = v->length <= MAX_VALUE ? v->length : MAX_VALUE;
    if (n == 0) {
        return 1;
    }
    for (uint64_t i = 0; i + n <= length; i++) {
        if (memcmp(&v->data[i], needle, n) == 0) {
            return 1;
        }
    }
    return 0;
}
