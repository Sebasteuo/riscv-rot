SHELL := /bin/bash
# ==========================================================================
# Makefile - Build automation for the Root of Trust firmware
# ==========================================================================
#
# Available commands
#   make        compile the firmware and generate firmware.elf
#   make run    compile and run on our custom QEMU (with Secure Storage device)
#   make clean  delete generated files
#
# Sources are compiled to separate object files under build/ so the linker
# script can place each one in the right memory region (M-mode code,
# shared code, or U-mode code) for PMP isolation.
#
# Author: Sebastian Alba
# Project: Root of Trust Firmware for RISC-V with PMP isolation
# ==========================================================================

CROSS   = riscv64-linux-gnu-
CC      = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
OBJDUMP = $(CROSS)objdump

# path to our custom QEMU with the Secure Storage MMIO device
QEMU = $(HOME)/qemu-ccore/build/qemu-system-riscv64

CFLAGS  = -march=rv64gc -mabi=lp64d -nostdlib -nostartfiles -ffreestanding -g -O0 -static -mcmodel=medany -Iinclude
LDFLAGS = -T scripts/virt.ld -nostdlib -static -Wl,--no-dynamic-linker

BUILD  = build
TARGET = firmware

# object files (order here does not matter, the linker script decides placement)
OBJS = \
  $(BUILD)/start.o \
  $(BUILD)/trap_entry.o \
  $(BUILD)/main.o \
  $(BUILD)/pmp.o \
  $(BUILD)/trap.o \
  $(BUILD)/switch.o \
  $(BUILD)/secure_storage.o \
  $(BUILD)/pcr.o \
  $(BUILD)/keygen.o \
  $(BUILD)/aes128.o \
  $(BUILD)/timer.o \
  $(BUILD)/uart.o \
  $(BUILD)/sha256.o \
  $(BUILD)/hmac.o \
  $(BUILD)/user.o \
  $(BUILD)/tpm2_api.o

all: $(TARGET).elf

$(BUILD):
	mkdir -p $(BUILD)

# compile rules: C from src/, C from lib/, and assembly from src/
$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: lib/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.S | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS)
	$(OBJDUMP) -d $@ > $(TARGET).dump

clean:
	rm -rf $(BUILD) $(TARGET).elf $(TARGET).dump test_output.log

# automated test: run the firmware, capture output, and decide pass/fail.
# The firmware ends in an idle wfi loop and never exits on its own, so we
# run it under a timeout and redirect to a log, then grep for the expected
# results. Exit code 0 means all checks passed, non-zero means a failure.
test: $(TARGET).elf
	@echo "=== Running firmware test suite ==="
	@rm -f secure_storage.bin test_output.log
	@timeout 20 $(QEMU) -machine virt -cpu rv64 -m 128M -nographic \
		-bios none -kernel $(TARGET).elf -smp 1 < /dev/null > test_output.log 2>&1; true
	@echo ""
	@pass=1; \
	if grep -q "ALL TESTS PASSED" test_output.log; then \
		echo "  [OK] ALL TESTS PASSED found"; \
	else \
		echo "  [FAIL] 'ALL TESTS PASSED' not found"; pass=0; \
	fi; \
	if grep -q "All 32 tests complete" test_output.log; then \
		echo "  [OK] 32 tests completed"; \
	else \
		echo "  [FAIL] did not complete 32 tests"; pass=0; \
	fi; \
	tfail=$$(grep "us (limit" test_output.log | grep -c "FAIL"); \
	if [ "$$tfail" -eq 0 ]; then \
		echo "  [OK] no timing limit violations (SRS-P-001/P-002)"; \
	else \
		echo "  [FAIL] $$tfail timing limit violation(s)"; pass=0; \
	fi; \
	isol=$$(grep -c "ACCESS FAULT" test_output.log); \
	if [ "$$isol" -ge 3 ]; then \
		echo "  [OK] PMP isolation faults present ($$isol access faults: Test 1/2/32)"; \
	else \
		echo "  [FAIL] expected PMP isolation faults not observed ($$isol)"; pass=0; \
	fi; \
	echo ""; \
	if [ "$$pass" -eq 1 ]; then \
		echo "=== RESULT: PASS ==="; \
		rm -f test_output.log; \
		exit 0; \
	else \
		echo "=== RESULT: FAIL (see test_output.log) ==="; \
		exit 1; \
	fi

run: $(TARGET).elf
	$(QEMU) -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -smp 1

.PHONY: all clean run test
