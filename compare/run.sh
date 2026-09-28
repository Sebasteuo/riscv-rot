#!/bin/bash
# uso: ./run.sh <escenario 0-4> <par 0|1>
ADDR=$(riscv64-unknown-elf-nm qatk.elf | awk '/ D cfg$/{print $1}')
OFF=$(( 0x$ADDR - 0x80000000 ))
CFG=$(( ($2 << 4) | $1 ))
riscv64-unknown-elf-objcopy -O binary qatk.elf qatk.bin
printf "\\x$(printf %02x $CFG)" | dd of=qatk.bin bs=1 seek=$OFF conv=notrunc 2>/dev/null
timeout 30 $HOME/qemu-ccore/build/qemu-system-riscv64 \
  -machine virt -cpu rv64 -m 128M -nographic -bios qatk.bin -smp 1 2>&1 \
  | grep -E "scenario|a=|sanity"
