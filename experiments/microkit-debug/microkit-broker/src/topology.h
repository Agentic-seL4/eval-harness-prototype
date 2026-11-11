/*
 * Channel identifiers, as seen from each PD. They must match broker.system;
 * the static checker (T5) compares the two.
 */
#pragma once
#if defined(CFG_HOST_BACKEND) && CFG_HOST_BACKEND
#include "model_topology.h"
#else

#define RUNNER_CH_BROKER 0  /* call: READ_T, READ_U, CALL, TAU; notified: retry READ_U */
#define RUNNER_CH_WORKER 1  /* notify: turn / done */

#define WORKER_CH_BROKER 0  /* call: CALL */
#define WORKER_CH_RUNNER 1  /* notify: done / turn */

#define BROKER_CH_RUNNER 1  /* called by the runner */
#define BROKER_CH_WORKER 2  /* called by the worker */
#define BROKER_CH_SINK 3    /* call: COMMIT */
#define BROKER_CH_NET 4     /* notified: an email has arrived */

#define SINK_CH_BROKER 0    /* called by the broker */
#define SINK_CH_NET 1       /* notify: new OBS lines in obs_out */

#define NET_CH_BROKER 1     /* notify: an email is in the mailbox */
#define NET_CH_SINK 2       /* notified: new OBS lines to transmit */
#define NET_IRQ_UART 0      /* second PL011 UART, interrupt 40 (SPI 8) */

#endif
