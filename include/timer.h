#ifndef TIMER_H
#define TIMER_H
#include <stdint.h>
/*
 * Timing helpers based on the RISC-V machine timer (mtime). On the QEMU
 * virt machine the timebase runs at 10 MHz (verified in the QEMU fork:
 * RISCV_ACLINT_DEFAULT_TIMEBASE_FREQ = 10000000). mtime advances at this
 * fixed, known frequency, so it is the correct reference for SRS-P-001 and
 * SRS-P-002, unlike the mcycle counter. 10 ticks = 1 us, 10000 ticks = 1 ms.
 */
uint64_t timer_now(void);
void timer_report(uint64_t start, uint64_t end, uint64_t limit_ms);
#endif /* TIMER_H */
