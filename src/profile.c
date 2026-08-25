#include "profile.h"
#include "uart.h"

/*
 * Profiles measured on this platform. Every figure comes from a real
 * run of the workload, not from an estimate: see docs/tfg for the
 * measurement procedure.
 *
 * Tolerance is set at 15 percent. That is wide enough to absorb the
 * effect of different input sizes on the same workload, and narrow
 * enough to catch the overflow scenario, which moves branch/load by
 * 39 percent and jump/load by 89 percent. It can be narrow because
 * repeated runs of the same workload were measured to be identical:
 * there is no natural variance to leave room for.
 */

#define TOL 2000   /* 20 percent, in parts per 10000 */

static const profile_t profiles[] = {
    /*                store  branch   jump   per 10000 loads */
    /*  0: vulnerable */ { 3850, 1549,  235, TOL },
    /*  1: aha-mont64 */ { 4879, 1494,   43, TOL },
    /*  2: crc32      */ { 5007, 1666, 1666, TOL },
    /*  3: depthconv  */ { 3911,  354,  331, TOL },
    /*  4: edn        */ { 2562,  745,    2, TOL },
    /*  5: huffbench  */ { 2983, 1520,    4, TOL },
    /*  6: matmult-int*/ { 1972, 1377,    0, TOL },
    /*  7: md5sum     */ { 3239, 1280,    3, TOL },
    /*  8: nettle-aes */ { 1616,  228,    3, TOL },
    /*  9: nettle-sha */ { 2041,  449,   29, TOL },
    /* 10: nsichneu   */ { 2054, 1011,    0, TOL },
    /* 11: picojpeg   */ { 5797, 1107,  587, TOL },
};

#define PROFILE_COUNT (sizeof(profiles) / sizeof(profiles[0]))

uint32_t profile_count(void)
{
    return (uint32_t)PROFILE_COUNT;
}

void profile_ratios(const uint64_t delta[ATTEST_FEATURES], profile_t *out)
{
    uint64_t load = delta[0] ? delta[0] : 1;

    out->store_load  = (uint16_t)((delta[1] * PROFILE_SCALE) / load);
    out->branch_load = (uint16_t)((delta[2] * PROFILE_SCALE) / load);
    out->jump_load   = (uint16_t)((delta[3] * PROFILE_SCALE) / load);
    out->tolerance   = 0;
}

/*
 * Deviation is measured against the expected value rather than as an
 * absolute difference, so a ratio of 3 and a ratio of 300 are held to
 * the same relative standard.
 *
 * When the expected value is zero the comparison falls back to an
 * absolute floor: a workload that never makes indirect jumps should
 * not be flagged for making one, but making hundreds is a real change.
 */
static int within(uint16_t expected, uint16_t seen, uint16_t tol)
{
    uint32_t diff;
    uint32_t allowed;

    diff = (seen > expected) ? (uint32_t)(seen - expected)
                             : (uint32_t)(expected - seen);

    /*
     * Relative tolerance alone does not work at the bottom of the
     * range. Several workloads sit at 2 or 3 indirect jumps per ten
     * thousand loads, where 20 percent is less than one unit, so any
     * rounding at all reads as a deviation.
     *
     * The floor is what makes small ratios usable: below it, a change
     * is not a signal. The overflow scenario moves jump/load from 235
     * to 26, which is far outside both bounds, so the floor does not
     * blunt detection where it matters.
     */
    allowed = ((uint32_t)expected * tol) / PROFILE_SCALE;
    if (allowed < 25) {
        allowed = 25;
    }

    return diff <= allowed;
}

profile_verdict_t profile_check(uint32_t app_id,
                                const uint64_t delta[ATTEST_FEATURES])
{
    const profile_t *p;
    profile_t seen;

    if (app_id >= PROFILE_COUNT) {
        return PROFILE_UNKNOWN_APP;
    }

    p = &profiles[app_id];
    profile_ratios(delta, &seen);

    if (!within(p->store_load, seen.store_load, p->tolerance)) {
        return PROFILE_DEVIATION_STORE;
    }
    if (!within(p->branch_load, seen.branch_load, p->tolerance)) {
        return PROFILE_DEVIATION_BRANCH;
    }
    if (!within(p->jump_load, seen.jump_load, p->tolerance)) {
        return PROFILE_DEVIATION_JUMP;
    }

    return PROFILE_OK;
}

const char *profile_verdict_name(profile_verdict_t v)
{
    switch (v) {
    case PROFILE_OK:                return "nominal";
    case PROFILE_DEVIATION_STORE:   return "store ratio off";
    case PROFILE_DEVIATION_BRANCH:  return "branch ratio off";
    case PROFILE_DEVIATION_JUMP:    return "jump ratio off";
    case PROFILE_UNKNOWN_APP:       return "unknown application";
    default:                        return "unknown";
    }
}
