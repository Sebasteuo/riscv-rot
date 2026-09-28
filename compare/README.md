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
retired" (0xF6) to match; "branch taken" does not.
