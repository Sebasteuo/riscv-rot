/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * trap.h - Trap handler definitions
 * ==========================================================================
 *
 * A "trap" in RISC-V is what happens when the processor runs into
 * something it cannot handle normally. Could be an illegal memory
 * access, a bad instruction, or an explicit system call (ecall).
 * When that happens the processor stops what it is doing, switches
 * to M-mode and jumps to a handler we set up ahead of time.
 *
 * There are two flavours of traps:
 *   Exceptions happen because of the current instruction
 *     (like trying to read protected memory)
 *   Interrupts come from external events
 *     (like a timer going off or a device signaling something)
 *
 * We mostly care about exceptions here. When U-mode code tries to
 * access the secret zone, PMP fires a "load access fault" or
 * "store access fault" and we end up in the trap handler.
 *
 * What the processor does automatically when a trap fires:
 *   - Stashes the faulting instruction address in mepc
 *   - Puts the reason in mcause
 *   - Puts the faulting memory address (if relevant) in mtval
 *   - Flips to M-mode
 *   - Jumps to whatever address is in the mtvec CSR
 *
 * So before we drop to U-mode, we need to point mtvec to our
 * handler so the processor knows where to go.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */

#ifndef TRAP_H
#define TRAP_H

#include <stdint.h>

/*
 * Exception cause codes from the RISC-V privileged spec.
 * These are the values we will find in mcause when a trap fires.
 */
#define CAUSE_MISALIGNED_FETCH    0
#define CAUSE_FETCH_ACCESS        1
#define CAUSE_ILLEGAL_INST        2
#define CAUSE_BREAKPOINT          3
#define CAUSE_MISALIGNED_LOAD     4
#define CAUSE_LOAD_ACCESS         5
#define CAUSE_MISALIGNED_STORE    6
#define CAUSE_STORE_ACCESS        7
#define CAUSE_ECALL_U             8
#define CAUSE_ECALL_S             9
#define CAUSE_ECALL_M             11

/* point mtvec to our trap handler so the processor knows where to go */
void trap_install(void);

#endif /* TRAP_H */
