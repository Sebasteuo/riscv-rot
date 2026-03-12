# ==========================================================================
# Makefile - Build automation for the Root of Trust firmware
# ==========================================================================
#
# Instead of typing long commands every time we want to compile,
# we just type "make" and this file handles everything.
#
# Available commands
#   make        compile the firmware and generate firmware.elf
#   make run    compile and run on QEMU
#   make clean  delete generated files
#
# Author: Sebastian Alba
# Project: Root of Trust Firmware for RISC-V with PMP isolation
# ==========================================================================

# Cross-compilation toolchain prefix
# We compile on ARM but the code needs to run on RISC-V,
# so we use a cross-compiler that generates code for a different architecture
CROSS = riscv64-linux-gnu-
CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

# Compilation flags
# -march=rv64g       compile for RISC-V 64-bit with general extensions
# -mabi=lp64d        ABI with 64-bit long and pointers
# -nostdlib           do not use the standard library, there is no OS
# -nostartfiles       do not use standard startup files, we have our own start.S
# -ffreestanding      freestanding mode, do not assume there is an OS underneath
# -g                  include debug info so we can debug if needed
# -O0                 no optimizations, keeps the code predictable when debugging
# -static             fully static executable, no dynamic dependencies
# -mcmodel=medany     allows accessing high addresses like 0x80000000
# -Iinclude           look for header files in the include/ folder
CFLAGS = -march=rv64g -mabi=lp64d -nostdlib -nostartfiles -ffreestanding -g -O0 -static -mcmodel=medany -Iinclude

# Linker flags
LDFLAGS = -T scripts/virt.ld -nostdlib -static -Wl,--no-dynamic-linker

# Source files
SRCS_C = src/main.c src/uart.c
SRCS_S = src/start.S
TARGET = firmware

# Main rule, compiles the firmware
all: $(TARGET).elf

$(TARGET).elf: $(SRCS_S) $(SRCS_C)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS_S) $(SRCS_C)
	$(OBJDUMP) -d $@ > $(TARGET).dump

# Deletes generated files so we can start fresh
clean:
	rm -f $(TARGET).elf $(TARGET).dump

# Compiles and launches QEMU with our firmware
# -machine virt    generic RISC-V virtual machine
# -cpu rv64        64-bit processor
# -m 128M          give it 128 MB of RAM
# -nographic       no graphical window, everything goes through the terminal
# -bios none       do not load any BIOS, jump straight to our code
# -kernel          load our ELF as if it were the kernel
# -smp 1           single processor core
run: $(TARGET).elf
	qemu-system-riscv64 -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -smp 1

.PHONY: all clean run
