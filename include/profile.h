/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
#ifndef PROFILE_H
#define PROFILE_H

#include <stdint.h>
#include "attest.h"

/*
 * Per-application behaviour profiles (OE3).
 *
 * The verdict is not "is this a healthy program" but "is this what
 * this program normally does". Comparing a window against the whole
 * space of possible programs is the wrong question. Eleven Embench
 * workloads already span nearly the entire range of every ratio, so
 * anything falls inside it. An attacker does not swap the program for
 * a different one, they perturb the one already running.
 *
 * Ratios rather than raw counts. A workload doing twice the work has
 * twice every counter, so absolute values carry the size of the run as
 * much as its shape. Ratios cancel that out and stay comparable across
 * intensities.
 *
 * The application identifier travels in the challenge, not in a field
 * the client fills in. A compromised client could lie about which
 * application it is and be measured against the wrong profile. The
 * verifier stating what it expects to see closes that.
 */

/*
 * Ratios are held as parts per ten thousand rather than per thousand.
 * Several workloads have indirect jump ratios below 0.005, which
 * rounds to 4 or 5 per thousand: a 15 percent tolerance on 4 leaves
 * less than one unit of room, so rounding alone triggers a deviation.
 * The extra digit removes that.
 */
#define PROFILE_SCALE 10000

typedef struct {
    uint16_t store_load;    /* stores per 10000 loads */
    uint16_t branch_load;   /* taken branches per 10000 loads */
    uint16_t jump_load;     /* indirect jumps per 10000 loads */
    uint16_t tolerance;     /* allowed deviation, parts per 10000 */
} profile_t;

typedef enum {
    PROFILE_OK = 0,
    PROFILE_DEVIATION_STORE,
    PROFILE_DEVIATION_BRANCH,
    PROFILE_DEVIATION_JUMP,
    PROFILE_UNKNOWN_APP,
} profile_verdict_t;

/* Compute the ratios of a window */
void profile_ratios(const uint64_t delta[ATTEST_FEATURES],
                    profile_t *out);

/*
 * Compare a window against the profile of the application the
 * challenge named. Returns PROFILE_OK when every ratio sits inside
 * the tolerance.
 */
profile_verdict_t profile_check(uint32_t app_id,
                                const uint64_t delta[ATTEST_FEATURES]);

/* Human-readable form of a verdict, for the UART log */
/* Report what one verdict costs, in retired instructions. Compiled only
 * when COST_REPORT is defined, which the measure-verdict target does.
 */
void profile_cost_report(void);

const char *profile_verdict_name(profile_verdict_t v);

/* How many profiles are compiled in */
uint32_t profile_count(void);

#endif /* PROFILE_H */
