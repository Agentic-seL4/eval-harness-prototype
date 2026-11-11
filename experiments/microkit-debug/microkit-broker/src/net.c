/*
 * Net PD: the attacker's side of the system (T8b, DESIGN.md section 10).
 *
 * It drives QEMU's second PL011 UART, which QEMU connects to a TCP socket on the
 * host. Received bytes are split into lines; each line is one email, published to
 * the inbox mailbox for the broker. The sink's OBS lines are sent back on the same
 * UART, so the attacker's view is exactly their connection.
 *
 * Untrusted but confined: it maps the UART, the inbox and the sink's obs_out
 * (read-only), and can only notify the broker. It never sees the secret, plan
 * memory or context (flow-policy.json).
 */
#include <stdint.h>
#include <microkit.h>
#include "protocol.h"
#include "topology.h"
#include "trace.h"

/* PL011 registers (ARM PrimeCell UART, as emulated by QEMU). */
#define UART_DR 0x000
#define UART_FR 0x018
#define UART_CR 0x030
#define UART_IMSC 0x038
#define UART_ICR 0x044
#define FR_RXFE (1u << 4)
#define FR_TXFF (1u << 5)
#define CR_UARTEN (1u << 0)
#define CR_TXE (1u << 8)
#define CR_RXE (1u << 9)
#define INT_RX (1u << 4)
#define INT_RT (1u << 6)

/* Patched in by the Microkit tool (broker.system). */
uintptr_t uart_regs;
uintptr_t inbox;
uintptr_t obs_out;

static uint8_t line[MAX_VALUE];
static uint64_t line_length;
static int line_too_long;
static uint64_t sent;  /* bytes of obs_out already transmitted */

static volatile uint32_t *reg(uintptr_t offset)
{
    return (volatile uint32_t *)(uart_regs + offset);
}

static void put_byte(uint8_t c)
{
    while (*reg(UART_FR) & FR_TXFF) {
    }
    *reg(UART_DR) = c;
}

static void note(const char *event, uint64_t n)
{
    tr_begin("NOTE");
    tr_key("pd");
    tr_cstr(microkit_name);
    tr_key("event");
    tr_cstr(event);
    tr_key("bytes");
    tr_uint(n);
    tr_end();
}

/* Publish one email: data and length first, then seq, then tell the broker. */
static void publish(void)
{
    volatile struct mailbox *m = (volatile struct mailbox *)inbox;
    for (uint64_t i = 0; i < line_length; i++) {
        m->data[i] = line[i];
    }
    m->length = line_length;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    m->seq = m->seq + 1;
    note("email received", line_length);
    microkit_notify(NET_CH_BROKER);
}

static void receive(void)
{
    /* Clear the interrupt before draining, not after: a byte that arrives after the
     * last read then raises a new interrupt. Clearing afterwards could discard that
     * byte's interrupt, and the PL011 raises another only when the FIFO next goes
     * from empty to non-empty, so reception would stall. */
    *reg(UART_ICR) = INT_RX | INT_RT;
    while (!(*reg(UART_FR) & FR_RXFE)) {
        uint8_t c = (uint8_t)(*reg(UART_DR) & 0xff);
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            if (line_too_long) {
                note("email discarded: longer than MAX_VALUE", line_length);
            } else {
                publish();
            }
            line_length = 0;
            line_too_long = 0;
        } else if (line_length < MAX_VALUE) {
            line[line_length++] = c;
        } else {
            line_too_long = 1;
        }
    }
}

static void transmit(void)
{
    const volatile struct obs_log *log = (const volatile struct obs_log *)obs_out;
    uint64_t end = log->length;
    if (end > OBS_LOG_CAPACITY) {
        end = OBS_LOG_CAPACITY;
    }
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    while (sent < end) {
        put_byte(log->data[sent++]);
    }
}

void init(void)
{
    /* Leave the FIFO off (LCR_H as reset): changing LCR_H.FEN flushes the receive
     * FIFO, which lost the first byte of an email that arrived before init. Without
     * the FIFO each byte raises its own interrupt; QEMU delivers the next byte only
     * once this one is read, so nothing is dropped. */
    *reg(UART_IMSC) = INT_RX | INT_RT;
    *reg(UART_CR) = CR_UARTEN | CR_TXE | CR_RXE;
    tr_simple("NOTE", "event", "start");
    receive();  /* bytes that arrived before the interrupt was enabled */
}

void notified(microkit_channel ch)
{
    switch (ch) {
    case NET_IRQ_UART:
        receive();
        microkit_irq_ack(ch);
        break;
    case NET_CH_SINK:
        transmit();
        break;
    default:
        break;
    }
}
