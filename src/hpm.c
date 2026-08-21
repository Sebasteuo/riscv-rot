#include "hpm.h"
#include "uart.h"

/*
 * Raw CSR numbers. The assembler does not always accept the mhpmevent3
 * and mhpmcounter3 mnemonics, so the encodings are used directly.
 */
#define CSR_MHPMEVENT3    0x323
#define CSR_MHPMEVENT4    0x324
#define CSR_MHPMCOUNTER3  0xB03
#define CSR_MHPMCOUNTER4  0xB04
#define CSR_MCOUNTINHIBIT 0x320

void hpm_init(void)
{
    uint64_t inhibit;

    uart_puts("[HPM] Mapping architectural events...\n");

    /* Counter 3 <- PRIV_SWITCH */
    asm volatile("csrw 0x323, %0" :: "r"((uint64_t)HPM_EVENT_PRIV_SWITCH));

    /* Counter 4 <- TRAP_TAKEN */
    asm volatile("csrw 0x324, %0" :: "r"((uint64_t)HPM_EVENT_TRAP_TAKEN));

    /* Start from zero */
    asm volatile("csrw 0xB03, zero");
    asm volatile("csrw 0xB04, zero");

    /* Clear the inhibit bits for counters 3 and 4 if set */
    asm volatile("csrr %0, 0x320" : "=r"(inhibit));
    inhibit &= ~((1UL << 3) | (1UL << 4));
    asm volatile("csrw 0x320, %0" :: "r"(inhibit));

    uart_puts("[HPM]   counter 3 = PRIV_SWITCH (0xF5)\n");
    uart_puts("[HPM]   counter 4 = TRAP_TAKEN  (0xF4)\n");
    uart_puts("[HPM] Counters ready\n");
}

uint64_t hpm_read(int ctr_idx)
{
    uint64_t v = 0;

    switch (ctr_idx) {
    case 3:
        asm volatile("csrr %0, 0xB03" : "=r"(v));
        break;
    case 4:
        asm volatile("csrr %0, 0xB04" : "=r"(v));
        break;
    default:
        break;
    }
    return v;
}

void hpm_dump(const char *label)
{
    uart_puts("[HPM] === ");
    uart_puts(label);
    uart_puts(" ===\n");

    uart_puts("[HPM]  PRIV_SWITCH (ctr3): ");
    uart_put_dec(hpm_read(3));
    uart_puts("\n");

    uart_puts("[HPM]  TRAP_TAKEN  (ctr4): ");
    uart_put_dec(hpm_read(4));
    uart_puts("\n");
}
