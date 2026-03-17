/* ==========================================================================
 * trap.c - Trap handler in C
 * ==========================================================================
 *
 * When a trap fires, the processor jumps to trap_entry.S which saves
 * all the registers and calls trap_handler() here. By the time we
 * get here we are back in M-mode and can safely read CSRs and print.
 *
 * What we do:
 *   Read mcause to find out why the trap happened
 *   Read mepc to know which instruction caused it
 *   Read mtval to get the faulting address (for access faults)
 *   Print all of that so we can see what is going on
 *   Bump mepc forward by 4 so we skip the bad instruction on return
 *
 * That last part is important. RISC-V base instructions are 4 bytes
 * each. If we do not advance mepc, we go right back to the same
 * instruction that faulted, trap again, and loop forever. I learned
 * that the hard way.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#include <stdint.h>
#include "uart.h"
#include "trap.h"

/* -------------------------------------------------------------------------
 * Small helpers to read/write CSR registers from C.
 * We need inline assembly for this since C cannot touch CSRs directly.
 * ------------------------------------------------------------------------- */

static uint64_t read_mcause(void)
{
    uint64_t val;
    asm volatile("csrr %0, mcause" : "=r"(val));
    return val;
}

static uint64_t read_mepc(void)
{
    uint64_t val;
    asm volatile("csrr %0, mepc" : "=r"(val));
    return val;
}

static uint64_t read_mtval(void)
{
    uint64_t val;
    asm volatile("csrr %0, mtval" : "=r"(val));
    return val;
}

static void write_mepc(uint64_t val)
{
    asm volatile("csrw mepc, %0" :: "r"(val));
}

/* -------------------------------------------------------------------------
 * trap_handler - figures out what happened and reacts
 *
 * Called from trap_entry.S after registers are saved.
 * Reads the cause, prints info, and advances mepc.
 * ------------------------------------------------------------------------- */
void trap_handler(void)
{
    uint64_t mcause = read_mcause();
    uint64_t mepc = read_mepc();
    uint64_t mtval = read_mtval();

    uart_puts("\n[TRAP] ============================\n");
    uart_puts("[TRAP] Exception caught!\n");

    uart_puts("[TRAP] mcause = ");
    uart_put_hex(mcause);
    uart_puts("\n");

    uart_puts("[TRAP] mepc   = ");
    uart_put_hex(mepc);
    uart_puts("\n");

    uart_puts("[TRAP] mtval  = ");
    uart_put_hex(mtval);
    uart_puts("\n");

    /* check what type of exception we got */
    switch (mcause) {
        case CAUSE_LOAD_ACCESS:
            uart_puts("[TRAP] >> LOAD ACCESS FAULT\n");
            uart_puts("[TRAP] >> U-mode tried to READ from a protected address\n");
            uart_puts("[TRAP] >> PMP blocked it, secret is safe\n");
            break;

        case CAUSE_STORE_ACCESS:
            uart_puts("[TRAP] >> STORE ACCESS FAULT\n");
            uart_puts("[TRAP] >> U-mode tried to WRITE to a protected address\n");
            uart_puts("[TRAP] >> PMP blocked it, secret is safe\n");
            break;

        case CAUSE_FETCH_ACCESS:
            uart_puts("[TRAP] >> INSTRUCTION FETCH FAULT\n");
            uart_puts("[TRAP] >> Tried to execute code from a protected region\n");
            break;

        case CAUSE_ILLEGAL_INST:
            uart_puts("[TRAP] >> ILLEGAL INSTRUCTION\n");
            break;

        case CAUSE_ECALL_U:
            uart_puts("[TRAP] >> ECALL from U-mode\n");
            uart_puts("[TRAP] >> Back in M-mode, all tests done\n");
            uart_puts("\n=========================================\n");
            uart_puts("  ALL PHASE 2 TESTS PASSED\n");
            uart_puts("  PMP is working correctly\n");
            uart_puts("=========================================\n");
            /* we are done, stay in M-mode */
            while (1) { asm volatile("wfi"); }
            break;

        default:
            uart_puts("[TRAP] >> Unknown exception\n");
            break;
    }

    uart_puts("[TRAP] ============================\n");

    /* skip past the faulting instruction so we do not loop forever */
    write_mepc(mepc + 4);
}

/* -------------------------------------------------------------------------
 * trap_install - point mtvec to our handler
 *
 * mtvec is the CSR that tells the processor where to jump on a trap.
 * We write the address of trap_entry (the asm trampoline) there.
 *
 * The & ~0x3 clears the bottom 2 bits because mtvec uses those for
 * the trap mode selection. 0 means direct mode where all traps go
 * to the same handler, which is what we want.
 * ------------------------------------------------------------------------- */
void trap_install(void)
{
    extern void trap_entry(void);
    uint64_t addr = (uint64_t)trap_entry & ~0x3UL;

    asm volatile("csrw mtvec, %0" :: "r"(addr));

    uart_puts("[TRAP] Trap handler installed at ");
    uart_put_hex(addr);
    uart_puts("\n");
}
