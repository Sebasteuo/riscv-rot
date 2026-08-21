#include "hpm.h"
#include "uart.h"

/*
 * Raw CSR numbers. The assembler does not always accept the mhpmeventN
 * and mhpmcounterN mnemonics, so the encodings are used directly.
 *
 * mhpmevent3..8   = 0x323..0x328
 * mhpmcounter3..8 = 0xB03..0xB08
 */

/* Counter index -> event mapping, kept in sync with hpm_init() */
static const struct {
    int         ctr;
    unsigned    event;
    const char *name;
} hpm_map[HPM_MAPPED_COUNTERS] = {
    { 3, HPM_EVENT_PRIV_SWITCH,   "PRIV_SWITCH  " },
    { 4, HPM_EVENT_TRAP_TAKEN,    "TRAP_TAKEN   " },
    { 5, HPM_EVENT_LOAD_RETIRED,  "LOAD_RETIRED " },
    { 6, HPM_EVENT_STORE_RETIRED, "STORE_RETIRED" },
    { 7, HPM_EVENT_JUMP_INDIRECT, "JUMP_INDIRECT" },
    { 8, HPM_EVENT_BRANCH_TAKEN,  "BRANCH_TAKEN " },
};

void hpm_init(void)
{
    uint64_t inhibit;

    uart_puts("[HPM] Mapping architectural events...\n");

    /* Select which event each counter tracks */
    asm volatile("csrw 0x323, %0" :: "r"((uint64_t)HPM_EVENT_PRIV_SWITCH));
    asm volatile("csrw 0x324, %0" :: "r"((uint64_t)HPM_EVENT_TRAP_TAKEN));
    asm volatile("csrw 0x325, %0" :: "r"((uint64_t)HPM_EVENT_LOAD_RETIRED));
    asm volatile("csrw 0x326, %0" :: "r"((uint64_t)HPM_EVENT_STORE_RETIRED));
    asm volatile("csrw 0x327, %0" :: "r"((uint64_t)HPM_EVENT_JUMP_INDIRECT));
    asm volatile("csrw 0x328, %0" :: "r"((uint64_t)HPM_EVENT_BRANCH_TAKEN));

    /* Start from zero */
    asm volatile("csrw 0xB03, zero");
    asm volatile("csrw 0xB04, zero");
    asm volatile("csrw 0xB05, zero");
    asm volatile("csrw 0xB06, zero");
    asm volatile("csrw 0xB07, zero");
    asm volatile("csrw 0xB08, zero");

    /* Clear the inhibit bits for counters 3 through 7 */
    asm volatile("csrr %0, 0x320" : "=r"(inhibit));
    inhibit &= ~((1UL << 3) | (1UL << 4) | (1UL << 5) |
                 (1UL << 6) | (1UL << 7) | (1UL << 8));
    asm volatile("csrw 0x320, %0" :: "r"(inhibit));

    uart_puts("[HPM]   ctr3 = PRIV_SWITCH    ctr4 = TRAP_TAKEN\n");
    uart_puts("[HPM]   ctr5 = LOAD_RETIRED   ctr6 = STORE_RETIRED\n");
    uart_puts("[HPM]   ctr7 = JUMP_INDIRECT  ctr8 = BRANCH_TAKEN\n");
    uart_puts("[HPM] Counters ready\n");
}

uint64_t hpm_read(int ctr_idx)
{
    uint64_t v = 0;

    switch (ctr_idx) {
    case 3: asm volatile("csrr %0, 0xB03" : "=r"(v)); break;
    case 4: asm volatile("csrr %0, 0xB04" : "=r"(v)); break;
    case 5: asm volatile("csrr %0, 0xB05" : "=r"(v)); break;
    case 6: asm volatile("csrr %0, 0xB06" : "=r"(v)); break;
    case 7: asm volatile("csrr %0, 0xB07" : "=r"(v)); break;
    case 8: asm volatile("csrr %0, 0xB08" : "=r"(v)); break;
    default: break;
    }
    return v;
}

void hpm_dump(const char *label)
{
    int i;

    uart_puts("[HPM] === ");
    uart_puts(label);
    uart_puts(" ===\n");

    for (i = 0; i < HPM_MAPPED_COUNTERS; i++) {
        uart_puts("[HPM]  ");
        uart_puts(hpm_map[i].name);
        uart_puts(" (ctr");
        uart_put_dec((uint64_t)hpm_map[i].ctr);
        uart_puts("): ");
        uart_put_dec(hpm_read(hpm_map[i].ctr));
        uart_puts("\n");
    }
}
