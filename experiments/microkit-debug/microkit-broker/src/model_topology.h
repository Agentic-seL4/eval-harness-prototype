/*
 * Channel identifiers, as seen from each PD. They must match broker.system;
 * the static checker (T5) compares the two.
 */
#pragma once

#define RUNNER_CH_BROKER 0  /* call: READ_T, READ_U, CALL, TAU; notified: retry READ_U */
#define RUNNER_CH_WORKER 1  /* notify: turn / done */

#define WORKER_CH_BROKER 0  /* call: CALL */
#define WORKER_CH_RUNNER 1  /* notify: done / turn */

#define BROKER_CH_RUNNER 1  /* called by the runner */
#define BROKER_CH_WORKER 2  /* called by the worker */
#define BROKER_CH_SINK 3    /* call: COMMIT */

#define SINK_CH_BROKER 0    /* called by the broker */

#define NET_IRQ_UART 0      /* second PL011 UART, interrupt 40 (SPI 8) */
#define WORKER_CH_NET 2
#define NET_CH_WORKER 1
