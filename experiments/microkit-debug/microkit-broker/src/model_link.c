/* Untrusted serial adapter. No inbox, context, plan or sink mappings. */
#include <stdint.h>
#include <microkit.h>
#include "util.h"
#include "model_wire.h"
#include "topology.h"
#include "trace.h"
uintptr_t uart_regs, model_req, model_reply;
static uint8_t line[MODEL_LINE_MAX];
static uint64_t used, seen;
static int active, failed;
static volatile uint32_t *reg(uintptr_t n) { return (volatile uint32_t *)(uart_regs+n); }
static void fail(const char *reason)
{
    if (!failed) { tr_simple("ERR", "error", reason); }
    failed = 1;
}
static void send_request(void)
{
    const volatile struct model_frame *r = (const volatile struct model_frame *)model_req;
    uint64_t seq = r->seq;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    uint64_t n = r->length;
    if (active || seq != seen + 1 || !n || n > MODEL_LINE_MAX) { fail("invalid model request"); return; }
    seen = seq; active = 1;
    for (uint64_t i = 0; i < n; i++) {
        while (*reg(0x18) & (1u << 5)) { }
        *reg(0) = r->data[i];
    }
}
static void receive(void)
{
    *reg(0x44) = (1u << 4) | (1u << 6); /* clear before draining */
    while (!(*reg(0x18) & (1u << 4))) {
        uint8_t c = *reg(0) & 255;
        if (failed) { continue; }
        if (!active) { fail("unsolicited or duplicate model reply"); continue; }
        if (used >= MODEL_LINE_MAX) { fail("model reply exceeds line limit"); continue; }
        line[used++] = c;
        if (c == '\n') {
            struct model_frame *r = (struct model_frame *)model_reply;
            memcpy(r->data, line, used); r->length = used;
            __atomic_thread_fence(__ATOMIC_RELEASE); r->seq = seen;
            used = 0; active = 0;
            microkit_notify(NET_CH_WORKER);
        }
    }
}
void init(void)
{
    *reg(0x38) = (1u << 4) | (1u << 6);
    *reg(0x30) = 1u | (1u << 8) | (1u << 9);
    tr_simple("NOTE", "event", "model link started");
}
void notified(microkit_channel ch)
{
    if (failed) { return; }
    if (ch == NET_CH_WORKER) { send_request(); }
    else if (ch == NET_IRQ_UART) { receive(); microkit_irq_ack(ch); }
}
