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

/*
 * Measurement window (OE3).
 *
 * attest_window_open() latches the counters and stores the nonce that
 * came with the request. attest_window_close() reports the deltas
 * accumulated since. Whatever the client did in between falls inside a
 * single window, even if other commands were processed meanwhile.
 */
void attest_window_open(const uint8_t *nonce, uint32_t nonce_len);

/* Returns 0 if no window is open. Otherwise fills out[] and returns 1. */
int attest_window_close(uint64_t out[ATTEST_FEATURES]);

/*
 * Measurement point selection.
 *
 * The application carries more measurement points than any single
 * attestation uses. Which ones fire is derived from the nonce, so it
 * changes with every challenge.
 *
 * This is the mitigation ConFirm (ICCAD 2015) describes for the
 * compensation attack: an adversary who knows where the measurement
 * points sit can alter the flow between two of them and make it up
 * afterwards, so the totals still match. Points that move with the
 * challenge remove the fixed target that attack needs.
 *
 * It is a mitigation rather than a fix. An adversary who compromises
 * every path still passes; what changes is that they can no longer
 * pick a quiet stretch and work inside it.
 */
void attest_set_selection(const uint8_t *nonce, uint32_t nonce_len);

/* Whether measurement point n fires under the current challenge */
int attest_point_selected(uint32_t point);

/* Which application the challenge says is being measured */
void attest_set_app(uint32_t app_id);
uint32_t attest_get_app(void);

/* Whether a window is currently open */
int attest_window_active(void);

/* The nonce of the current or last window */
const uint8_t *attest_window_nonce(void);

/* Print every stored sample over UART, one row per sample */
void attest_dump(void);

#endif /* ATTEST_H */
