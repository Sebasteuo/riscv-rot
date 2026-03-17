# ==========================================================================
# Makefile - Build automation for the Root of Trust firmware
# ==========================================================================
#
# Available commands
#   make        compile the firmware and generate firmware.elf
#   make run    compile and run on our custom QEMU (with Secure Storage device)
#   make clean  delete generated files
#
# Author: Sebastian Alba
# Project: Root of Trust Firmware for RISC-V with PMP isolation
# ==========================================================================

CROSS = riscv64-linux-gnu-
CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

# path to our custom QEMU with the Secure Storage MMIO device
QEMU = $(HOME)/qemu-ccore/build/qemu-system-riscv64

CFLAGS = -march=rv64g -mabi=lp64d -nostdlib -nostartfiles -ffreestanding -g -O0 -static -mcmodel=medany -Iinclude
LDFLAGS = -T scripts/virt.ld -nostdlib -static -Wl,--no-dynamic-linker

SRCS_C = src/main.c src/uart.c src/pmp.c src/trap.c src/user.c src/switch.c src/secure_storage.c
SRCS_S = src/start.S src/trap_entry.S
TARGET = firmware

all: $(TARGET).elf

$(TARGET).elf: $(SRCS_S) $(SRCS_C)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS_S) $(SRCS_C)
	$(OBJDUMP) -d $@ > $(TARGET).dump

clean:
	rm -f $(TARGET).elf $(TARGET).dump

run: $(TARGET).elf
	$(QEMU) -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -smp 1

.PHONY: all clean run
