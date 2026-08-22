#ifndef HPM_H
#define HPM_H

#include <stdint.h>

/*
 * Architectural event counters.
 *
 * qemu-ccore exposes custom events in the 0xF0-0xF5 range, outside the
 * SBI v0.3 encoding. Event selectors are WARL and platform-defined per
 * the RISC-V privileged specification.
 */

#define HPM_EVENT_LOAD_RETIRED    0xF0
#define HPM_EVENT_STORE_RETIRED   0xF1
#define HPM_EVENT_BRANCH_TAKEN    0xF2
#define HPM_EVENT_JUMP_INDIRECT   0xF3
#define HPM_EVENT_TRAP_TAKEN      0xF4
#define HPM_EVENT_PRIV_SWITCH     0xF5

/* Physical counter indices, kept in sync with hpm_init() */
#define HPM_CTR_PRIV    3
#define HPM_CTR_TRAP    4
#define HPM_CTR_LOAD    5
#define HPM_CTR_STORE   6
#define HPM_CTR_JUMP    7
#define HPM_CTR_BRANCH  8


/*
 * Privilege-mode inhibit bits in mhpmeventN, from the Sscofpmf
 * extension. Setting MINH stops the counter while in M-mode, which is
 * how the crypto core keeps its own execution out of the measurement.
 */
#define HPM_MINH  (1ULL << 62)
#define HPM_SINH  (1ULL << 61)
#define HPM_UINH  (1ULL << 60)

/* Run the counter unit tests */
void hpm_selftest(void);

/* Number of counters currently mapped */
#define HPM_MAPPED_COUNTERS 6

/* Map available events to physical counters and reset them */
void hpm_init(void);

/* Read a physical counter (index 3 and up) */
uint64_t hpm_read(int ctr_idx);

/* Print the mapped counters over UART */
void hpm_dump(const char *label);

#endif
