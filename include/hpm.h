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

/* Map available events to physical counters and reset them */
void hpm_init(void);

/* Read a physical counter (index 3 and up) */
uint64_t hpm_read(int ctr_idx);

/* Print the mapped counters over UART */
void hpm_dump(const char *label);

#endif
