# Silicon cross-check: qemu-ccore vs. SiFive U74

The same crc32 and beebsc objects the platform builds, linked into two
firmwares that run the same measured window (body_crc32(1, gsf), gsf 1..3):

- qbench: qemu-ccore, events 0xF0/0xF1/0xF6/0xF3, six counters, one pass
- ../../unmatched-fw/bench: FU740 U74 hart, events 0x200/0x400/0x4000/0x10000,
  two counters, two passes (deterministic workload composes cleanly)

Result: identical counts, twelve for twelve.

           load   store  branch  jalr
  g1 U74   6163   3088   1029    1027
  g1 QEMU  6163   3088   1029    1027
  g2 U74   12316  6169   2055    2053
  g2 QEMU  12316  6169   2055    2053
  g3 U74   18469  9250   3081    3079
  g3 QEMU  18469  9250   3081    3079

For architectural events, qemu-ccore counts exactly what the U74 counts,
not merely proportionally. The branch event had to be "conditional branch
retired" (0xF6) to match. "branch taken" does not.

## How these are built

Every program here is a freestanding M-mode binary linked at 0x80000000.
The line was missing from this file until 28 Oct 2026 and had to be
recovered from the architecture attributes of an old .elf, so it is
written down now:

    riscv64-unknown-elf-gcc -march=rv64gc -mabi=lp64d -mcmodel=medany \
        -O2 -nostdlib -ffreestanding -fno-builtin -Wall \
        -T q.ld -o NAME.elf qstart.S NAME.c
    riscv64-unknown-elf-objcopy -O binary NAME.elf NAME.bin

medany is not optional. With the default code model the link fails with
"relocation truncated to fit: R_RISCV_HI20", because 0x80000000 sits at
the edge of what a lui and addi pair can reach and .rodata falls outside.

To run one:

    $HOME/qemu-ccore/build/qemu-system-riscv64 -machine virt -cpu rv64 \
        -m 128M -nographic -bios NAME.bin -smp 1

## qbranch: does 0xF2 count taken branches or all retired ones?

The U74 has no taken-branch event, so the silicon comparison reads
retired conditional branches while the classifier uses taken ones. That
substitution only holds if the two events really are different, and this
program measures the difference instead of assuming it.

0xF2 and 0xF6 are programmed at the same time, on counters 3 and 4, so
one loop gives both numbers and no counter is ever reprogrammed. Two
loops, so the answer is checked from both sides:

    loop A, empty, volatile index    taken=999   retired=1001  difference 2
    loop B, half the branches skip   taken=1499  retired=2000  difference 501

In both cases the difference is exactly the number of branches that were
not taken, and the disassembly of qmain says where each one comes from:

    loop A   one entry guard at 0x1a6, never taken, plus 1000 back-edge
             tests at 0x1b6 of which 999 are taken
    loop B   1000 tests of if (gate & 1) at 0x1e6, 500 taken, plus 1000
             back-edge tests at 0x1f4, 999 taken

Loop B has no entry guard because its index is not volatile, which is
why it reads 2000 and not 2001.

So the two events are distinct and 0xF2 counts only the branches that are
taken. The condition in loop B reads a volatile, so the compiler cannot
work out the parity, unroll the loop or fold the body into a conditional
move. Loop A needs its volatile index as well: without it the empty loop
disappears at -O2 and both counters read zero.
