#ifndef TIMER_H
#define TIMER_H
#include <stdint.h>
/*
 * Timing helpers based on the RISC-V machine timer (mtime). On the QEMU
 * virt machine the timebase runs at 10 MHz (verified in the QEMU fork:
 * RISCV_ACLINT_DEFAULT_TIMEBASE_FREQ = 10000000). mtime advances at this
 * fixed, known frequency. 10 ticks = 1 us, 10000 ticks = 1 ms.
 *
 * One caveat, measured rather than assumed. Without -icount, QEMU drives
 * both this counter and minstret from the host clock, so the same binary
 * reports figures that differ by tens of per cent between runs. The tick
 * is also 100 ns, so it cannot resolve anything that takes a few hundred
 * instructions. Short intervals belong in retired instructions, not here.
 */
uint64_t timer_now(void);
void timer_report(uint64_t start, uint64_t end, uint64_t limit_ms);
#endif /* TIMER_H */
