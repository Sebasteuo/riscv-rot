#ifndef ATTEST_H
#define ATTEST_H

#include <stdint.h>
#include "hpm.h"

/*
 * Runtime attestation sampling (OE3).
 *
 * Samples are taken at command boundaries rather than on a timer. Each
 * sample holds the counter deltas accumulated since the previous
 * command, which is exactly the work the monitored system performed to
 * prepare this one.
 *
 * Two properties follow from that choice. The measurement points are
 * semantic rather than arbitrary, so every sample covers one complete
 * unit of work. And the sequence is deterministic: the same command
 * sequence yields the same samples, with no timer jitter involved.
 *
 * Counting only advances while the processor is in U-mode, since the
 * instruction counters run with MINH set. A sample therefore describes
 * the monitored system and not the crypto core.
 */

/* Number of counters carried in one sample */
#define ATTEST_FEATURES 6

/*
 * Buffer depth. A full test run produces around 150 command windows:
 * the lockout wait in test 6 and the session exhaustion in test 10 are
 * retry loops that each contribute dozens of windows on their own.
 * 256 covers that with margin.
 */
#define ATTEST_MAX_SAMPLES 256

typedef struct {
    uint32_t cmd;                      /* which command closed this window */
    uint64_t delta[ATTEST_FEATURES];   /* counter deltas since last sample */
} attest_sample_t;

/* Reset the baseline and discard any stored samples */
void attest_init(void);

/*
 * Take a sample. Called at the start of command processing, before the
 * command itself runs, so the deltas cover only U-mode execution.
 */
void attest_sample(uint32_t cmd);

/* How many samples were dropped because the buffer was full */
uint32_t attest_dropped(void);

/* How many samples were dropped because the buffer was full */
uint32_t attest_dropped(void);

/* How many samples are currently stored */
uint32_t attest_count(void);

/* Read one sample. Returns 0 if the index is out of range. */
const attest_sample_t *attest_get(uint32_t index);

/* Print every stored sample over UART, one row per sample */
void attest_dump(void);

#endif /* ATTEST_H */
