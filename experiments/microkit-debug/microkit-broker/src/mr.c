#include <microkit.h>
#include "mr.h"

int mr_put_value(unsigned *index, const uint8_t *data, uint64_t length)
{
    uint64_t words = (length + 7) / 8;
    if (*index + 1 + words > MR_LIMIT) {
        return 0;
    }
    microkit_mr_set((uint8_t)(*index)++, length);
    for (uint64_t w = 0; w < words; w++) {
        uint64_t word = 0;
        for (uint64_t b = 0; b < 8 && w * 8 + b < length; b++) {
            word |= (uint64_t)data[w * 8 + b] << (8 * b);
        }
        microkit_mr_set((uint8_t)(*index)++, word);
    }
    return 1;
}

int mr_get_value(unsigned *index, unsigned count, uint8_t *data, uint64_t max, uint64_t *length)
{
    if (*index >= count) {
        return 0;
    }
    uint64_t n = microkit_mr_get((uint8_t)(*index)++);
    if (n > max) {
        return 0;
    }
    uint64_t words = (n + 7) / 8;
    if (*index + words > count) {
        return 0;
    }
    for (uint64_t w = 0; w < words; w++) {
        uint64_t word = microkit_mr_get((uint8_t)(*index)++);
        for (uint64_t b = 0; b < 8 && w * 8 + b < n; b++) {
            data[w * 8 + b] = (uint8_t)(word >> (8 * b));
        }
    }
    *length = n;
    return 1;
}

int mr_put_call(unsigned *index, const struct call_args *call)
{
    if (call->nargs > MAX_ARGS || *index + 2 > MR_LIMIT) {
        return 0;
    }
    microkit_mr_set((uint8_t)(*index)++, call->tool);
    microkit_mr_set((uint8_t)(*index)++, call->nargs);
    for (uint64_t i = 0; i < call->nargs; i++) {
        if (!mr_put_value(index, call->data[i], call->length[i])) {
            return 0;
        }
    }
    return 1;
}

int mr_get_call(unsigned count, struct call_args *call)
{
    unsigned index = 0;
    if (count < 2 || count > MR_LIMIT) {
        return 0;
    }
    call->tool = microkit_mr_get(index++);
    call->nargs = microkit_mr_get(index++);
    if (call->nargs > MAX_ARGS) {
        return 0;
    }
    for (uint64_t i = 0; i < call->nargs; i++) {
        if (!mr_get_value(&index, count, call->data[i], MAX_ARG, &call->length[i])) {
            return 0;
        }
    }
    return index == count;
}
