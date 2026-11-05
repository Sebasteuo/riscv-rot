#!/bin/bash
# Builds an attack image for the selected scenario and counter pair. The first
# argument selects the scenario, from 0 to 4. The second selects the counter
# pair, with 0 for loads and stores and 1 for branches and jumps. An optional
# third argument specifies a directory where the resulting image is copied.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: $0 <scenario 0-4> <counter pair 0|1> [output directory]" >&2
    exit 1
fi

LOAD_ADDR=0x80000000
ADDR=$(riscv64-unknown-elf-nm atk.elf | awk '/ D cfg$/{print $1}')
OFF=$(( 0x$ADDR - LOAD_ADDR ))
CFG=$(( ($2 << 4) | $1 ))

cp atk.bin atk-run.bin
printf "\\x$(printf %02x $CFG)" | dd of=atk-run.bin bs=1 seek=$OFF conv=notrunc 2>/dev/null
SZ=$(stat -c%s atk-run.bin)
PAD=$(( (SZ + 4095) / 4096 * 4096 ))
truncate -s $PAD atk-run.bin

sed 's|fw.bin|atk-run.bin|' fw.its > atk-run.its
mkimage -f atk-run.its atk-run.itb > /dev/null

if [ $# -eq 3 ]; then
    cp atk-run.itb "$3"
fi

echo "wrote cfg=0x$(printf %02x $CFG) at offset $OFF for scenario $1 using counter pair $2"
