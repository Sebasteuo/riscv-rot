#!/bin/bash
# uso: ./mk.sh <escenario 0-4> <par 0=load/store 1=branch/jalr>
ADDR=$(riscv64-unknown-elf-nm atk.elf | awk '/ D cfg$/{print $1}')
OFF=$(( 0x$ADDR - 0x80000000 ))
CFG=$(( ($2 << 4) | $1 ))
cp atk.bin atk-run.bin
printf "\\x$(printf %02x $CFG)" | dd of=atk-run.bin bs=1 seek=$OFF conv=notrunc 2>/dev/null
SZ=$(stat -c%s atk-run.bin); PAD=$(( (SZ+4095)/4096*4096 ))
truncate -s $PAD atk-run.bin
sed 's|fw.bin|atk-run.bin|' fw.its > atk-run.its
mkimage -f atk-run.its atk-run.itb > /dev/null
cp atk-run.itb /media/psf/iCloud/
echo "cfg=0x$(printf %02x $CFG) en offset $OFF  escenario=$1  par=$2"
