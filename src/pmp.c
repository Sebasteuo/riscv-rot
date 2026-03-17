/* ==========================================================================
 * pmp.c - PMP configuration
 * ==========================================================================
 *
 * Here we configure the PMP registers to protect sensitive memory
 * regions. This all runs in M-mode since only M-mode can write to
 * PMP CSRs.
 *
 * We set up 4 regions:
 *
 *   Region 0 protects the secret zone in RAM at 0x80100000 (4KB).
 *     No permissions for U-mode, only M-mode can touch it.
 *
 *   Region 1 protects the Secure Storage MMIO device at 0x10200000.
 *     No permissions for U-mode either. We do not want unprivileged
 *     code talking directly to the storage device.
 *
 *   Region 2 opens the UART at 0x10000000 for U-mode so it can
 *     still print debug messages.
 *
 *   Region 3 is the catch-all that opens everything else for U-mode
 *     with full read/write/execute.
 *
 * PMP checks in order (0, 1, 2, 3...) and the first match wins.
 * The two blocked regions go first so they take priority over the
 * catch-all at the end.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "pmp.h"
#include "uart.h"
#include "secure_storage.h"

/* -------------------------------------------------------------------------
 * napot_addr - encode a base+size pair into NAPOT format for pmpaddr
 *
 * The formula from the spec:
 *   pmpaddr = (base >> 2) | ((size/2 - 1) >> 2)
 * ------------------------------------------------------------------------- */
static uint64_t napot_addr(uint64_t base, uint64_t size)
{
    return (base >> 2) | ((size / 2 - 1) >> 2);
}

/* -------------------------------------------------------------------------
 * pmp_setup - configure PMP regions
 * ------------------------------------------------------------------------- */
void pmp_setup(void)
{
    uint64_t addr0, addr1, addr2, addr3;
    uint64_t cfg;

    uart_puts("[PMP] Configuring memory protection...\n");

    /*
     * Region 0: secret zone in RAM
     * 4KB at 0x80100000, no permissions for U-mode
     */
    addr0 = napot_addr(SECRET_BASE, SECRET_SIZE);

    /*
     * Region 1: Secure Storage MMIO device
     * 4KB at 0x10200000, no permissions for U-mode
     * We do not want U-mode talking to the storage device directly,
     * it has to go through M-mode (via ecall) to access secrets
     */
    addr1 = napot_addr(SS_MMIO_BASE, 0x1000UL);

    /*
     * Region 2: UART
     * 4KB at 0x10000000, read+write so U-mode can print
     */
    addr2 = napot_addr(0x10000000UL, 0x1000UL);

    /*
     * Region 3: everything else
     * Full access for U-mode so it can run its code
     */
    addr3 = 0x1FFFFFFFFFFFFFFFUL;

    /* write addresses to pmpaddr CSRs */
    asm volatile("csrw pmpaddr0, %0" :: "r"(addr0));
    asm volatile("csrw pmpaddr1, %0" :: "r"(addr1));
    asm volatile("csrw pmpaddr2, %0" :: "r"(addr2));
    asm volatile("csrw pmpaddr3, %0" :: "r"(addr3));

    /*
     * Build pmpcfg0
     * 4 regions now, each 8 bits, packed into one 64-bit value
     *
     * byte 0 (region 0): NAPOT, no R/W/X = secret RAM blocked
     * byte 1 (region 1): NAPOT, no R/W/X = Secure Storage MMIO blocked
     * byte 2 (region 2): NAPOT + R + W = UART open
     * byte 3 (region 3): NAPOT + R + W + X = everything else open
     */
    cfg = ((uint64_t)(PMP_A_NAPOT) << 0)
        | ((uint64_t)(PMP_A_NAPOT) << 8)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W) << 16)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W | PMP_X) << 24);

    asm volatile("csrw pmpcfg0, %0" :: "r"(cfg));

    /* print what we configured */
    uart_puts("[PMP] Region 0 (secret RAM):     addr=");
    uart_put_hex(addr0);
    uart_puts(" NO access for U-mode\n");

    uart_puts("[PMP] Region 1 (Secure Storage): addr=");
    uart_put_hex(addr1);
    uart_puts(" NO access for U-mode\n");

    uart_puts("[PMP] Region 2 (UART):           addr=");
    uart_put_hex(addr2);
    uart_puts(" R+W for U-mode\n");

    uart_puts("[PMP] Region 3 (everything else): full access for U-mode\n");
    uart_puts("[PMP] Memory protection configured successfully\n");
}
