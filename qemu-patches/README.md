# QEMU changes this firmware needs

Upstream QEMU does not emulate two things the firmware uses, so the
measurements in this project were taken on a patched emulator. These are
the seven commits that make the difference, exported as a patch series.

| Patch | What it adds |
|---|---|
| 0001 | a Secure Storage MMIO device at 0x10200000 with 8 slots of 64 bytes |
| 0002 | file backed persistence for that device, so keys survive a restart |
| 0003 | six event selectors in the range 0xF0 to 0xF5, outside the SBI encoding, and the first two events |
| 0004 | code comments in English |
| 0005 | loads, stores and indirect jumps counted from a TCG helper, so the counts follow executed instructions rather than translated ones |
| 0006 | taken conditional branches, counted after the branch taken label |
| 0007 | a seventh event, 0xF6, for conditional branches retired whether taken or not, which is the definition the SiFive U74 exposes |

## What these patches are, and what they are not

They are an exact record of what was changed and why. Read them to see
the delta without downloading a full emulator tree.

They are not a build recipe for today's QEMU. The series was written on a
tree from April 2026 and upstream has moved since, so the hunks no longer
apply cleanly. Rebasing them onto current QEMU would produce different
code from the one the measurements were taken on, which is worse than
leaving them as they are.

## The tree the measurements used

The complete emulator, with these patches already applied on the base
they were written against, is the `tfg-counters` branch of the SECCE
repository at gitlab.com/secce/qemu-ccore. That tree is the reference for
reproducing the emulator figures in the thesis.
