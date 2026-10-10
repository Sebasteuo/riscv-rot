# The test recipe below leans on bash behavior (the $$(...) captures and
# the multi-line if blocks). On Ubuntu /bin/sh is dash, and under dash the
# QEMU run ended up writing an empty log and every check broke, so we pin
# the shell to bash explicitly.
SHELL := /bin/bash
# ==========================================================================
# Makefile - Build automation for the Root of Trust firmware
# ==========================================================================
#
# Available commands
#   make        compile the firmware and generate firmware.elf
#   make run    compile and run on our custom QEMU (with Secure Storage device)
#   make test   compile, run the full suite under QEMU, and report pass/fail
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

# Compiler flags. Every one of these matters in bare-metal:
#   -march=rv64gc -mabi=lp64d   target ISA and ABI (SRS-L-001)
#   -nostdlib -nostartfiles     no libc and no crt0: start.S is our startup
#   -ffreestanding              tells GCC there is no OS underneath
#   -g -O0                      debug info and no optimizations, so the
#                               disassembly in firmware.dump stays readable
#   -static                     fully static binary, nothing dynamic
#   -mcmodel=medany             PC-relative addressing, needed because the
#                               image is linked high in memory (0x80000000)
CFLAGS  = -march=rv64gc -mabi=lp64d -nostdlib -nostartfiles -ffreestanding -g -O0 -static -mcmodel=medany -Iinclude

# link against our memory map (virt.ld) and keep the ELF fully static
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
  $(BUILD)/tpm2_api.o \
  $(BUILD)/hpm.o \
  $(BUILD)/hpm_test.o \
  $(BUILD)/attest.o \
  $(BUILD)/client_app.o \
  $(BUILD)/attack.o \
  $(BUILD)/profile.o \
  $(BUILD)/board.o \
  $(BUILD)/beebsc.o \
  $(BUILD)/aha_mont64__mont64.o \
  $(BUILD)/crc32__crc_32.o \
  $(BUILD)/depthconv__depthconv.o \
  $(BUILD)/edn__libedn.o \
  $(BUILD)/huffbench__libhuffbench.o \
  $(BUILD)/matmult_int__matmult-int.o \
  $(BUILD)/md5sum__md5.o \
  $(BUILD)/nettle_aes__nettle-aes.o \
  $(BUILD)/nettle_sha256__nettle-sha256.o \
  $(BUILD)/nsichneu__libnsichneu.o \
  $(BUILD)/picojpeg__libpicojpeg.o \
  $(BUILD)/picojpeg__picojpeg_test.o \
  $(BUILD)/qrduino__qrencode.o \
  $(BUILD)/qrduino__qrframe.o \
  $(BUILD)/qrduino__qrtest.o \
  $(BUILD)/sglib_combined__combined.o \
  $(BUILD)/slre__libslre.o \
  $(BUILD)/statemate__libstatemate.o \
  $(BUILD)/tarfind__tarfind.o \
  $(BUILD)/ud__libud.o \
  $(BUILD)/wikisort__libwikisort.o \
  $(BUILD)/xgboost__testbench.o \
  $(BUILD)/xgboost__xgboost.o

all: $(TARGET).elf

$(BUILD)/attack.o: src/attack.c | $(BUILD)
	$(CC) $(CFLAGS) -fno-stack-protector -c $< -o $@

$(BUILD)/board.o: lib/embench/board.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -c $< -o $@

$(BUILD)/beebsc.o: lib/embench/beebsc.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -c $< -o $@

$(BUILD)/aha_mont64__mont64.o: src/bench/aha_mont64__mont64.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_aha_mont64 -Dinitialise_benchmark=init_aha_mont64 \
	  -Dverify_benchmark=verify_aha_mont64 -Dwarm_caches=warm_aha_mont64 \
	  -Dbenchmark_body=body_aha_mont64 \
	  -c $< -o $@

$(BUILD)/crc32__crc_32.o: src/bench/crc32__crc_32.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_crc32 -Dinitialise_benchmark=init_crc32 \
	  -Dverify_benchmark=verify_crc32 -Dwarm_caches=warm_crc32 \
	  -Dbenchmark_body=body_crc32 \
	  -c $< -o $@

$(BUILD)/depthconv__depthconv.o: src/bench/depthconv__depthconv.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_depthconv -Dinitialise_benchmark=init_depthconv \
	  -Dverify_benchmark=verify_depthconv -Dwarm_caches=warm_depthconv \
	  -Dbenchmark_body=body_depthconv \
	  -c $< -o $@

$(BUILD)/edn__libedn.o: src/bench/edn__libedn.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_edn -Dinitialise_benchmark=init_edn \
	  -Dverify_benchmark=verify_edn -Dwarm_caches=warm_edn \
	  -Dbenchmark_body=body_edn \
	  -c $< -o $@

$(BUILD)/huffbench__libhuffbench.o: src/bench/huffbench__libhuffbench.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_huffbench -Dinitialise_benchmark=init_huffbench \
	  -Dverify_benchmark=verify_huffbench -Dwarm_caches=warm_huffbench \
	  -Dbenchmark_body=body_huffbench \
	  -c $< -o $@

$(BUILD)/matmult_int__matmult-int.o: src/bench/matmult_int__matmult-int.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_matmult_int -Dinitialise_benchmark=init_matmult_int \
	  -Dverify_benchmark=verify_matmult_int -Dwarm_caches=warm_matmult_int \
	  -Dbenchmark_body=body_matmult_int \
	  -c $< -o $@

$(BUILD)/md5sum__md5.o: src/bench/md5sum__md5.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_md5sum -Dinitialise_benchmark=init_md5sum \
	  -Dverify_benchmark=verify_md5sum -Dwarm_caches=warm_md5sum \
	  -Dbenchmark_body=body_md5sum \
	  -c $< -o $@

$(BUILD)/nettle_aes__nettle-aes.o: src/bench/nettle_aes__nettle-aes.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_nettle_aes -Dinitialise_benchmark=init_nettle_aes \
	  -Dverify_benchmark=verify_nettle_aes -Dwarm_caches=warm_nettle_aes \
	  -Dbenchmark_body=body_nettle_aes \
	  -c $< -o $@

$(BUILD)/nettle_sha256__nettle-sha256.o: src/bench/nettle_sha256__nettle-sha256.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_nettle_sha256 -Dinitialise_benchmark=init_nettle_sha256 \
	  -Dverify_benchmark=verify_nettle_sha256 -Dwarm_caches=warm_nettle_sha256 \
	  -Dbenchmark_body=body_nettle_sha256 \
	  -Dsha256_init=nettle_sha256_init \
	  -Dsha256_update=nettle_sha256_update \
	  -Dsha256_digest=nettle_sha256_digest \
	  -c $< -o $@

$(BUILD)/nsichneu__libnsichneu.o: src/bench/nsichneu__libnsichneu.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_nsichneu -Dinitialise_benchmark=init_nsichneu \
	  -Dverify_benchmark=verify_nsichneu -Dwarm_caches=warm_nsichneu \
	  -Dbenchmark_body=body_nsichneu \
	  -c $< -o $@

$(BUILD)/picojpeg__libpicojpeg.o: src/bench/picojpeg__libpicojpeg.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_picojpeg -Dinitialise_benchmark=init_picojpeg \
	  -Dverify_benchmark=verify_picojpeg -Dwarm_caches=warm_picojpeg \
	  -Dbenchmark_body=body_picojpeg \
	  -c $< -o $@

$(BUILD)/picojpeg__picojpeg_test.o: src/bench/picojpeg__picojpeg_test.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_picojpeg -Dinitialise_benchmark=init_picojpeg \
	  -Dverify_benchmark=verify_picojpeg -Dwarm_caches=warm_picojpeg \
	  -Dbenchmark_body=body_picojpeg \
	  -c $< -o $@

$(BUILD)/qrduino__qrencode.o: src/bench/qrduino__qrencode.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_qrduino -Dinitialise_benchmark=init_qrduino \
	  -Dverify_benchmark=verify_qrduino -Dwarm_caches=warm_qrduino \
	  -Dbenchmark_body=body_qrduino \
	  -c $< -o $@

$(BUILD)/qrduino__qrframe.o: src/bench/qrduino__qrframe.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_qrduino -Dinitialise_benchmark=init_qrduino \
	  -Dverify_benchmark=verify_qrduino -Dwarm_caches=warm_qrduino \
	  -Dbenchmark_body=body_qrduino \
	  -c $< -o $@

$(BUILD)/qrduino__qrtest.o: src/bench/qrduino__qrtest.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_qrduino -Dinitialise_benchmark=init_qrduino \
	  -Dverify_benchmark=verify_qrduino -Dwarm_caches=warm_qrduino \
	  -Dbenchmark_body=body_qrduino \
	  -c $< -o $@

$(BUILD)/sglib_combined__combined.o: src/bench/sglib_combined__combined.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_sglib_combined -Dinitialise_benchmark=init_sglib_combined \
	  -Dverify_benchmark=verify_sglib_combined -Dwarm_caches=warm_sglib_combined \
	  -Dbenchmark_body=body_sglib_combined \
	  -c $< -o $@

$(BUILD)/slre__libslre.o: src/bench/slre__libslre.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_slre -Dinitialise_benchmark=init_slre \
	  -Dverify_benchmark=verify_slre -Dwarm_caches=warm_slre \
	  -Dbenchmark_body=body_slre \
	  -c $< -o $@

$(BUILD)/statemate__libstatemate.o: src/bench/statemate__libstatemate.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_statemate -Dinitialise_benchmark=init_statemate \
	  -Dverify_benchmark=verify_statemate -Dwarm_caches=warm_statemate \
	  -Dbenchmark_body=body_statemate \
	  -c $< -o $@

$(BUILD)/tarfind__tarfind.o: src/bench/tarfind__tarfind.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_tarfind -Dinitialise_benchmark=init_tarfind \
	  -Dverify_benchmark=verify_tarfind -Dwarm_caches=warm_tarfind \
	  -Dbenchmark_body=body_tarfind \
	  -c $< -o $@

$(BUILD)/ud__libud.o: src/bench/ud__libud.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_ud -Dinitialise_benchmark=init_ud \
	  -Dverify_benchmark=verify_ud -Dwarm_caches=warm_ud \
	  -Dbenchmark_body=body_ud \
	  -c $< -o $@

$(BUILD)/wikisort__libwikisort.o: src/bench/wikisort__libwikisort.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_wikisort -Dinitialise_benchmark=init_wikisort \
	  -Dverify_benchmark=verify_wikisort -Dwarm_caches=warm_wikisort \
	  -Dbenchmark_body=body_wikisort \
	  -c $< -o $@

$(BUILD)/xgboost__testbench.o: src/bench/xgboost__testbench.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_xgboost -Dinitialise_benchmark=init_xgboost \
	  -Dverify_benchmark=verify_xgboost -Dwarm_caches=warm_xgboost \
	  -Dbenchmark_body=body_xgboost \
	  -c $< -o $@

$(BUILD)/xgboost__xgboost.o: src/bench/xgboost__xgboost.c | $(BUILD)
	$(CC) $(CFLAGS) -Ilib/embench -Isrc/bench -DGLOBAL_SCALE_FACTOR=1 \
	  -Dbenchmark=bench_xgboost -Dinitialise_benchmark=init_xgboost \
	  -Dverify_benchmark=verify_xgboost -Dwarm_caches=warm_xgboost \
	  -Dbenchmark_body=body_xgboost \
	  -c $< -o $@


$(BUILD):
	mkdir -p $(BUILD)

# compile rules: C from src/, C from lib/, and assembly from src/
$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: lib/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.S | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# link with our script, then dump a full disassembly next to the ELF.
# The dump is handy for checking what ended up at which address.
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
	if grep -q "All 36 tests complete" test_output.log; then \
		echo "  [OK] 36 tests completed"; \
	else \
		echo "  [FAIL] did not complete 36 tests"; pass=0; \
	fi; \
	if grep -qF "[HPMTEST] 4 of 4 passed" test_output.log; then \
		echo "  [OK] 4 of 4 counter unit tests passed"; \
	else \
		echo "  [FAIL] counter unit tests did not all pass"; pass=0; \
	fi; \
	if grep -q "unexpected" test_output.log; then \
		echo "  [FAIL] a U-mode test reported an unexpected result"; pass=0; \
	else \
		echo "  [OK] no U-mode test reported an unexpected result"; \
	fi; \
	tfail=$$(grep "us (limit" test_output.log | grep -c "FAIL"); \
	if [ "$$tfail" -eq 0 ]; then \
		echo "  [OK] no timing limit violations (SRS-P-001/P-002)"; \
	else \
		echo "  [FAIL] $$tfail timing limit violation(s)"; pass=0; \
	fi; \
	isol=$$(grep -c "ACCESS FAULT" test_output.log); \
	if [ "$$isol" -ge 3 ]; then \
		echo "  [OK] PMP isolation faults present ($$isol access faults from U-mode isolation tests)"; \
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

# interactive run (quit QEMU with Ctrl-A then X)
run: $(TARGET).elf
	$(QEMU) -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -smp 1

# these targets are commands, not files
.PHONY: all clean run test

# ---------------------------------------------------------------------------
# Two-stage secure boot (OE1)
#
# Stage-1 is a minimal bootloader that verifies an Ed25519 signature over
# the SHA-256 digest of Stage-2 before transferring control. The keypair
# lives in keys/ and is generated on first build; the private half is
# gitignored and never enters the device.
# ---------------------------------------------------------------------------

KEYDIR    = keys
KEYPREFIX = $(KEYDIR)/stage2
S1BUILD   = build/stage1

S1_CFLAGS = -march=rv64gc -mabi=lp64d -nostdlib -nostartfiles \
	-ffreestanding -O2 -static -mcmodel=medany \
	-ffunction-sections -fdata-sections \
	-Iinclude -Ilib/tweetnacl

S1_OBJS = $(S1BUILD)/stage1_start.o \
	$(S1BUILD)/stage1_main.o \
	$(S1BUILD)/sha256.o \
	$(S1BUILD)/uart.o \
	$(S1BUILD)/tweetnacl.o \
	$(S1BUILD)/elf64.o \
	$(S1BUILD)/timer.o

# Generate the signing keypair once
$(KEYPREFIX).pub:
	@mkdir -p $(KEYDIR)
	python3 tools/sign_image.py keygen $(KEYPREFIX)

# Embed the public key into a header Stage-1 includes
$(S1BUILD)/pubkey.h: $(KEYPREFIX).pub
	@mkdir -p $(S1BUILD)
	@python3 -c "import sys; \
	 k=open('$(KEYPREFIX).pub','rb').read(); \
	 print(', '.join('0x%02X'%b for b in k))" > $@

$(S1BUILD):
	mkdir -p $(S1BUILD)

$(S1BUILD)/stage1_start.o: src/stage1_start.S | $(S1BUILD)
	$(CC) $(S1_CFLAGS) -c $< -o $@

$(S1BUILD)/stage1_main.o: src/stage1_main.c $(S1BUILD)/pubkey.h | $(S1BUILD)
	$(CC) $(S1_CFLAGS) \
	  -DPUBKEY_PLACEHOLDER="$$(cat $(S1BUILD)/pubkey.h)" -c $< -o $@

$(S1BUILD)/sha256.o: lib/sha256.c | $(S1BUILD)
	$(CC) $(S1_CFLAGS) -c $< -o $@

$(S1BUILD)/uart.o: src/uart.c | $(S1BUILD)
	$(CC) $(S1_CFLAGS) -c $< -o $@

$(S1BUILD)/tweetnacl.o: lib/tweetnacl/tweetnacl.c | $(S1BUILD)
	$(CC) $(S1_CFLAGS) -c $< -o $@

$(S1BUILD)/elf64.o: src/elf64.c | $(S1BUILD)
	$(CC) $(S1_CFLAGS) -c $< -o $@

$(S1BUILD)/timer.o: lib/timer.c | $(S1BUILD)
	$(CC) $(S1_CFLAGS) -c $< -o $@

stage1.elf: $(S1_OBJS)
	$(CC) $(S1_CFLAGS) -T scripts/stage1.ld -Wl,--gc-sections \
	  -Wl,--no-dynamic-linker -o $@ $(S1_OBJS)
	riscv64-linux-gnu-size $@

# Stage-2 is the existing firmware, stripped to a raw binary and signed
stage2.img: $(TARGET).elf $(KEYPREFIX).pub
	python3 tools/sign_image.py sign $(KEYPREFIX) $(TARGET).elf $@ 1

secureboot: stage1.elf stage2.img

run-secureboot: secureboot
	$(QEMU) -machine virt -cpu rv64 -m 128M -nographic \
	  -bios stage1.elf \
	  -device loader,file=stage2.img,addr=0x80200000 \
	  -smp 1

clean-secureboot:
	rm -rf $(S1BUILD) stage1.elf stage2.img

.PHONY: secureboot run-secureboot clean-secureboot
