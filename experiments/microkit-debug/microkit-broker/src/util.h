/* Freestanding helpers: libmicrokit provides no C library. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "protocol.h"

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int memcmp(const void *a, const void *b, size_t n);

size_t cstr_len(const char *s);

/* Set a value from a C string, truncated to MAX_VALUE bytes. */
void value_set_cstr(struct value *v, const char *s);
/* Copy a value, clamping a corrupt length to MAX_VALUE. */
void value_copy(struct value *dst, const struct value *src);
/* Nonzero if the value contains the C string needle. */
int value_contains(const struct value *v, const char *needle);
