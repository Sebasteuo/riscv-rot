/* ==========================================================================
 * pmp.c - PMP configuration
 * ==========================================================================
 *
 * 5 PMP regions configured:
 *   Region 0: secret RAM (0x80100000) - blocked for U-mode
 *   Region 1: Secure Storage MMIO (0x10200000) - blocked for U-mode
 *   Region 2: UART (0x10000000) - R+W for U-mode
 *   Region 3: Shared memory (0x80300000) - R+W for U-mode (no execute)
 *   Region 4: Everything else - full access for U-mode
 *
 * The shared zone is the mailbox where U-mode leaves data for the
 * crypto core to process. U-mode can read and write there but cannot
 * execute code from it (no X permission).
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include "pmp.h"
#include "uart.h"
#include "secure_storage.h"

static uint64_t napot_addr(uint64_t base, uint64_t size)
{
    return (base >> 2) | ((size / 2 - 1) >> 2);
}

void pmp_setup(void)
{
    uint64_t addr0, addr1, addr2, addr3, addr4;
    uint64_t cfg;

    uart_puts("[PMP] Configuring memory protection...\n");

    /* Region 0: secret zone in RAM, no access for U-mode */
    addr0 = napot_addr(SECRET_BASE, SECRET_SIZE);

    /* Region 1: Secure Storage MMIO, no access for U-mode */
    addr1 = napot_addr(SS_MMIO_BASE, 0x1000UL);

    /* Region 2: UART, read+write for U-mode */
    addr2 = napot_addr(0x10000000UL, 0x1000UL);

    /* Region 3: Shared memory zone, read+write for U-mode (no execute) */
    addr3 = napot_addr(SHARED_BASE, SHARED_SIZE);

    /* Region 4: everything else, full access */
    addr4 = 0x1FFFFFFFFFFFFFFFUL;

    /* write addresses to pmpaddr CSRs */
    asm volatile("csrw pmpaddr0, %0" :: "r"(addr0));
    asm volatile("csrw pmpaddr1, %0" :: "r"(addr1));
    asm volatile("csrw pmpaddr2, %0" :: "r"(addr2));
    asm volatile("csrw pmpaddr3, %0" :: "r"(addr3));
    asm volatile("csrw pmpaddr4, %0" :: "r"(addr4));

    /*
     * Build pmpcfg0 - 5 regions packed into one 64-bit value
     *
     * byte 0 (region 0): NAPOT, no R/W/X = secret RAM blocked
     * byte 1 (region 1): NAPOT, no R/W/X = Secure Storage blocked
     * byte 2 (region 2): NAPOT + R + W = UART open
     * byte 3 (region 3): NAPOT + R + W = shared memory open (no X)
     * byte 4 (region 4): NAPOT + R + W + X = everything else open
     */
    cfg = ((uint64_t)(PMP_A_NAPOT) << 0)
        | ((uint64_t)(PMP_A_NAPOT) << 8)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W) << 16)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W) << 24)
        | ((uint64_t)(PMP_A_NAPOT | PMP_R | PMP_W | PMP_X) << 32);

    asm volatile("csrw pmpcfg0, %0" :: "r"(cfg));

    uart_puts("[PMP] Region 0 (secret RAM):     addr=");
    uart_put_hex(addr0);
    uart_puts(" NO access\n");

    uart_puts("[PMP] Region 1 (Secure Storage): addr=");
    uart_put_hex(addr1);
    uart_puts(" NO access\n");

    uart_puts("[PMP] Region 2 (UART):           addr=");
    uart_put_hex(addr2);
    uart_puts(" R+W\n");

    uart_puts("[PMP] Region 3 (Shared memory):  addr=");
    uart_put_hex(addr3);
    uart_puts(" R+W (no exec)\n");

    uart_puts("[PMP] Region 4 (everything else): full access\n");
    uart_puts("[PMP] Memory protection configured successfully\n");
}
