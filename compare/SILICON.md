# Eleven-benchmark cross-check: qemu-ccore vs. SiFive U74

Same objects the platform builds, linked into a bare-metal firmware for
each side, same measured window (body(lsf, gsf) for gsf 1..3).

Events: integer load retired, integer store retired, conditional branch
retired, JALR retired.

  qemu-ccore  0xF0, 0xF1, 0xF6, 0xF3   six counters, one pass
  U74 hart    0x200, 0x400, 0x4000, 0x10000   two counters, two passes

## Result

load, branch, jalr: 99 of 99 figures identical.
store: 33 of 33 differ by exactly one, always one fewer on silicon.

The store offset is the emit-versus-retire difference: qemu-ccore counts
the store on entry to gen_store, the U74 counts it at retirement. One
store is always in flight when the counter is read. Constant across
values ranging from 262 to 1.5 million, which is what a systematic
offset looks like and noise does not.

## What had to be fixed to get here

- BRANCH_RETIRED (0xF6) added to qemu-ccore. The classifier's
  BRANCH_TAKEN has no U74 equivalent; retired conditional branches do.
- .bss zeroed at boot on the board. QEMU hands over cleared memory;
  DRAM does not. nsichneu's working variables are globals and its
  control flow depends on them, so it was the one benchmark that
  diverged until this was fixed.
- md5sum called with its real three-argument signature. The platform
  declares body_md5sum with two and gets away with it under QEMU; on
  silicon the leftover register made len huge, malloc returned NULL and
  md5 memcpy'd through it. This is a latent defect in the platform.

## The store offset, isolated

A probe with three stores and nothing else:

  qemu-ccore  3
  U74 hart    2

qemu-ccore counts a store when gen_store emits it; the U74 counts it at
retirement. The last store before the csrr that reads the counter has
been emitted but not retired, so the emulator includes it and the core
does not. This accounts for all 33 offsets in the table above,
independently of whether the benchmark issues 262 stores or 1.5
million.
