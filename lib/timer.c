/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
/* ==========================================================================
 * timer.c - Machine timer (mtime) helpers for performance measurement
 * ==========================================================================
 * Reads the RISC-V machine timer from the CLINT MMIO register and converts
 * elapsed ticks to microseconds, checking against the SRS timing limits.
 * QEMU virt timebase = 10 MHz, CLINT at 0x02000000, mtime at offset 0xBFF8.
 *
 * Author: Sebastian Alba
 * Project: Root of Trust Firmware for RISC-V with PMP isolation
 * ========================================================================== */
#include "timer.h"
#include "uart.h"

#define MTIME_ADDR    0x0200BFF8UL
#define TICKS_PER_US  10UL
#define TICKS_PER_MS  10000UL

uint64_t timer_now(void)
{
    return *(volatile uint64_t *)MTIME_ADDR;
}

void timer_report(uint64_t start, uint64_t end, uint64_t limit_ms)
{
    uint64_t ticks = end - start;
    uint64_t us = ticks / TICKS_PER_US;
    uint64_t limit_ticks = limit_ms * TICKS_PER_MS;

    uart_put_dec(ticks);
    uart_puts(" ticks = ");
    uart_put_dec(us);
    uart_puts(" us (limit ");
    uart_put_dec(limit_ms);
    uart_puts(" ms) -> ");
    if (ticks <= limit_ticks) {
        uart_puts("PASS\n");
    } else {
        uart_puts("FAIL\n");
    }
}
