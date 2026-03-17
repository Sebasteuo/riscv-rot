/* ==========================================================================
 * pmp.h - Physical Memory Protection (PMP) definitions
 * ==========================================================================
 *
 * PMP is how RISC-V protects memory at the hardware level. The basic
 * idea is that from M-mode we set up rules that say which memory
 * regions can be accessed and by whom. Then when we drop to U-mode,
 * the processor enforces those rules on every memory access.
 *
 * If U-mode code tries to touch a region it should not, the processor
 * fires an exception (trap) and blocks it. This is done in hardware
 * so there is no way to bypass it from software.
 *
 * PMP uses pairs of CSR registers to define each region:
 *   pmpaddr[i] has the address/boundary info
 *   pmpcfg[i]  has the permissions (read, write, execute)
 *
 * There can be up to 16 PMP regions. The permissions for each one
 * are packed 8 bits at a time into the pmpcfg registers.
 *
 * Each 8-bit config has these fields:
 *   bit 0 (R)      read
 *   bit 1 (W)      write
 *   bit 2 (X)      execute
 *   bits 3-4 (A)   how to match the address
 *     00 = OFF     disabled
 *     01 = TOR     top of range (uses previous entry as base)
 *     10 = NA4     naturally aligned 4 bytes
 *     11 = NAPOT   naturally aligned power of two
 *   bit 7 (L)      lock (applies to M-mode too, cannot change until reset)
 *
 * We use NAPOT mode which lets us protect power-of-2 sized regions.
 * The encoding for pmpaddr in NAPOT mode is a bit weird:
 *   pmpaddr = (base >> 2) | ((size/2 - 1) >> 2)
 *
 * So for 4KB at 0x80100000 that gives us:
 *   (0x80100000 >> 2) | ((0x1000/2 - 1) >> 2) = 0x200401FF
 *
 * I had to read the RISC-V privileged spec a few times to get
 * this encoding right, it is not the most intuitive thing.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef PMP_H
#define PMP_H

#include <stdint.h>

/* pmpcfg permission bits */
#define PMP_R       0x01
#define PMP_W       0x02
#define PMP_X       0x04

/* address matching modes, go in bits 3-4 */
#define PMP_A_OFF   0x00
#define PMP_A_TOR   0x08
#define PMP_A_NA4   0x10
#define PMP_A_NAPOT 0x18

/* lock bit, careful with this one, it locks M-mode out too */
#define PMP_L       0x80

/*
 * Memory layout for the project
 *
 * I picked 0x80100000 for the secret zone because it is far enough
 * from our firmware code (which starts at 0x80000000) that there
 * is no overlap. 4KB is plenty for storing a few crypto keys.
 *
 * 0x80200000 is where we will put the U-mode test code later on.
 */
#define SECRET_BASE  0x80100000UL
#define SECRET_SIZE  0x1000UL       /* 4KB */
#define USER_BASE    0x80200000UL

/* configures PMP from M-mode to lock down the secret zone */
void pmp_setup(void);

#endif /* PMP_H */
