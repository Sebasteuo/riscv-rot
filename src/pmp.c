/* ==========================================================================
 * pmp.c - PMP configuration
 * ==========================================================================
 *
 * 6 PMP regions, NO catch-all. Any address not matched by a region is
 * denied for U-mode (PMP default) and allowed for M-mode (M-mode ignores
 * unlocked entries). This gives true isolation, so U-mode can only touch
 * what it is explicitly granted.
 *
 *   Region 0: secret zone (0x80200000)  seeds, password, PCR, auth state.
 *             No access for U-mode.
 *   Region 1: Secure Storage MMIO (0x10200000)  no access for U-mode.
 *   Region 2: UART (0x10000000)  R+W for U-mode.
 *   Region 3: shared zone (0x80300000)  R+W for U-mode (no execute).
 *   Region 4: shared code (0x80080000)  R+X (uart, sha256, hmac). U-mode
 *             executes these but cannot write them.
 *   Region 5: U-mode region (0x80090000, 512 KB)  R+W+X.
 *             U-mode code, data, stack and the benchmark heap.
 *
 * Everything else (M-mode code at 0x80000000, M-mode stack, M-mode data)
 * has no matching region: U-mode is denied, M-mode keeps full access.
 * This satisfies SRS-F-001: an execute region for the crypto core that
 * U-mode cannot reach, R/W exclusive Secure Storage, a shared R/W zone,
 * and no access to the rest of memory.
 *
 * The base addresses 0x80080000 and 0x80090000 must match the regions
 * defined in scripts/virt.ld (.text.shared and .text.umode).
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "pmp.h"
#include "uart.h"
#include "secure_storage.h"

#define SHARED_CODE_BASE  0x80080000UL
#define UMODE_BASE        0x80090000UL
#define REGION_64KB       0x10000UL

/*
 * The U-mode region grew when the Embench suite was added. Its code,
 * data and heap now span roughly 400 KB. PMP in NAPOT mode only
 * accepts power-of-two sizes, so the next one up is 512 KB.
 */
#define REGION_512KB      0x80000UL

static uint64_t napot_addr(uint64_t base, uint64_t size)
{
    return (base >> 2) | ((size / 2 - 1) >> 2);
}

void pmp_setup(void)
{
    uint64_t addr0, addr1, addr2, addr3, addr4, addr5;
    uint64_t cfg;

    uart_puts("[PMP] Configuring memory protection...\n");

    /* Region 0: secret zone (seeds, password, PCR, auth state) */
    addr0 = napot_addr(SECRET_BASE, SECRET_SIZE);
    /* Region 1: Secure Storage MMIO */
    addr1 = napot_addr(SS_MMIO_BASE, 0x1000UL);
    /* Region 2: UART */
    addr2 = napot_addr(0x10000000UL, 0x1000UL);
    /* Region 3: shared zone */
    addr3 = napot_addr(SHARED_BASE, SHARED_SIZE);
    /* Region 4: shared code (uart, sha256, hmac), 64 KB */
    addr4 = napot_addr(SHARED_CODE_BASE, REGION_64KB);
    /* Region 5: U-mode code + data + stack, 512 KB */
    addr5 = napot_addr(UMODE_BASE, REGION_512KB);

    asm volatile("csrw pmpaddr0, %0" :: "r"(addr0));
    asm volatile("csrw pmpaddr1, %0" :: "r"(addr1));
    asm volatile("csrw pmpaddr2, %0" :: "r"(addr2));
    asm volatile("csrw pmpaddr3, %0" :: "r"(addr3));
    asm volatile("csrw pmpaddr4, %0" :: "r"(addr4));
    asm volatile("csrw pmpaddr5, %0" :: "r"(addr5));

    /*
     * pmpcfg0 packs regions 0-5 (one byte each, low to high):
     *   r0: NAPOT, no perms        secret zone blocked for U
     *   r1: NAPOT, no perms        Secure Storage blocked for U
     *   r2: NAPOT + R + W          UART
     *   r3: NAPOT + R + W          shared zone (no execute)
     *   r4: NAPOT + R + X          shared code (no write)
     *   r5: NAPOT + R + W + X      U-mode owns its memory
     * No region 6/7: the rest is denied for U, allowed for M (default).
     */
    cfg = ((uint64_t)(PMP_A_NAPOT) << 0)
        | ((uint64_t)(PMP_A_NAPOT) << 8)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W) << 16)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W) << 24)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_X) << 32)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W | PMP_X) << 40);

    asm volatile("csrw pmpcfg0, %0" :: "r"(cfg));

    uart_puts("[PMP] Region 0 (secret zone):    NO access for U-mode\n");
    uart_puts("[PMP] Region 1 (Secure Storage): NO access for U-mode\n");
    uart_puts("[PMP] Region 2 (UART):           R+W\n");
    uart_puts("[PMP] Region 3 (shared zone):    R+W (no exec)\n");
    uart_puts("[PMP] Region 4 (shared code):    R+X (no write)\n");
    uart_puts("[PMP] Region 5 (U-mode memory):  R+W+X\n");
    uart_puts("[PMP] No catch-all: M-mode code/stack unreachable from U-mode\n");
    uart_puts("[PMP] Memory protection configured successfully\n");
}
