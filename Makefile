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

# Stage-2 is the existing firmware with its symbol and debug sections
# removed, then signed. Only the loadable segments ever get copied, so
# hashing and signing the symbol table would cost boot time for nothing.
stage2.img: $(TARGET).elf $(KEYPREFIX).pub | $(S1BUILD)
	cp $(TARGET).elf $(S1BUILD)/stage2_stripped.elf
	riscv64-linux-gnu-strip $(S1BUILD)/stage2_stripped.elf
	python3 tools/sign_image.py sign $(KEYPREFIX) $(S1BUILD)/stage2_stripped.elf $@ 1

secureboot: stage1.elf stage2.img

run-secureboot: secureboot
	$(QEMU) -machine virt -cpu rv64 -m 128M -nographic \
	  -bios stage1.elf \
	  -device loader,file=stage2.img,addr=0x84000000 \
	  -icount shift=0 \
	  -smp 1

clean-secureboot:
	rm -rf $(S1BUILD) stage1.elf stage2.img

.PHONY: secureboot run-secureboot clean-secureboot

# ---------------------------------------------------------------------------
# Behaviour profiles (OE3)
#
# The profile table compiled into src/profile.c comes from a measured run.
# These targets record that run and refit from it, so the table in the
# firmware can always be traced back to data kept in the repository.
#
#   make profiles        record a run into data/run.log and print the table
#   make check-profiles  refit from a fresh run and fail on any difference
#
# The run is deterministic, so the recorded log is committed and the check
# target is what proves the table still matches the firmware that produced
# it.
# ---------------------------------------------------------------------------
profiles: $(TARGET).elf
	@rm -f secure_storage.bin
	@timeout 40 $(QEMU) -machine virt -cpu rv64 -m 128M -nographic \
		-bios none -kernel $(TARGET).elf -smp 1 < /dev/null \
		> data/run.log 2>&1; true
	@echo "recorded $$(grep -c 'Window closed' data/run.log) windows in data/run.log"
	@python3 tools/fit_profiles.py data/run.log

check-profiles: $(TARGET).elf
	@echo "=== Checking the profile table against a fresh run ==="
	@rm -f secure_storage.bin
	@timeout 40 $(QEMU) -machine virt -cpu rv64 -m 128M -nographic \
		-bios none -kernel $(TARGET).elf -smp 1 < /dev/null \
		> /tmp/run_check.log 2>&1; true
	@python3 tools/fit_profiles.py /tmp/run_check.log \
		| grep -oE '\{ *[0-9]+, *[0-9]+, *[0-9]+, *[0-9]+ *\}' \
		| tr -d ' ' | sort > /tmp/profiles_fresh.txt
	@grep -oE '\{ *[0-9]+, *[0-9]+, *[0-9]+, *[0-9]+ *\}' src/profile.c \
		| tr -d ' ' | sort > /tmp/profiles_repo.txt
	@if diff -q /tmp/profiles_repo.txt /tmp/profiles_fresh.txt > /dev/null; then \
		echo "  [OK] src/profile.c matches a fresh run"; \
		echo ""; echo "=== RESULT: PASS ==="; \
	else \
		echo "  [FAIL] src/profile.c does not match a fresh run"; \
		diff /tmp/profiles_repo.txt /tmp/profiles_fresh.txt; \
		echo ""; echo "=== RESULT: FAIL ==="; exit 1; \
	fi

# ---------------------------------------------------------------------------
# Secure boot chain regression (OE1)
#
# The test suite boots firmware.elf directly and never calls elf_load, so
# it cannot see a broken handover. A load address collision once left the
# chain jumping to address zero while the suite still reported 36 of 36.
# This target boots through Stage-1 and requires all three markers, since
# a valid signature on its own says nothing about Stage-2 being reached.
#
# No -icount here. The regression needs the chain to complete, not timing
# to be reproducible, and emulating the whole suite instruction by
# instruction takes orders of magnitude longer.
# ---------------------------------------------------------------------------
test-chain: secureboot
	@echo "=== Running the secure boot chain ==="
	@rm -f secure_storage.bin chain_output.log
	@timeout 40 $(QEMU) -machine virt -cpu rv64 -m 128M -nographic \
		-bios stage1.elf \
		-device loader,file=stage2.img,addr=0x84000000 \
		-smp 1 < /dev/null > chain_output.log 2>&1; true
	@echo ""
	@pass=1; \
	if grep -q "Secure Boot PASSED" chain_output.log; then \
		echo "  [OK] the signature check passed"; \
	else \
		echo "  [FAIL] the signature check did not pass"; pass=0; \
	fi; \
	if grep -q "Entry point 0x80000000" chain_output.log; then \
		echo "  [OK] the entry point validated to the expected address"; \
	else \
		echo "  [FAIL] the entry point is wrong or was rejected"; pass=0; \
	fi; \
	if grep -q "ALL TESTS PASSED" chain_output.log; then \
		echo "  [OK] Stage-2 was reached and ran its suite"; \
	else \
		echo "  [FAIL] Stage-2 was never reached or did not finish"; pass=0; \
	fi; \
	echo ""; \
	if [ $$pass -eq 1 ]; then \
		echo "=== RESULT: PASS ==="; \
	else \
		echo "=== RESULT: FAIL ==="; exit 1; \
	fi

.PHONY: profiles check-profiles test-chain

# ---------------------------------------------------------------------------
# Loader rejection tests (OE1)
#
# A signature makes an image authentic, not well formed. Each case here
# changes one field of a good image, signs it, and requires the loader to
# refuse it with the error that field feeds. A good image runs first as
# the control.
# ---------------------------------------------------------------------------
test-reject: secureboot
	@python3 tools/test_reject.py $(KEYPREFIX)

.PHONY: test-reject

# ---------------------------------------------------------------------------
# Verdict cost
#
# What one classifier verdict costs, in retired instructions, which is the
# figure that compares against the board. The -icount flag is what makes the
# count real, and the define keeps the measurement out of every other build,
# so the default binary stays the one the other figures were taken from.
# ---------------------------------------------------------------------------
EXTRA_CFLAGS ?=
CFLAGS += $(EXTRA_CFLAGS)

measure-verdict:
	@touch src/profile.c src/main.c
	@$(MAKE) --no-print-directory EXTRA_CFLAGS=-DCOST_REPORT $(TARGET).elf > /dev/null
	@rm -f secure_storage.bin
	@timeout 120 $(QEMU) -machine virt -cpu rv64 -m 128M -nographic -bios none -kernel $(TARGET).elf -icount shift=0 -smp 1 < /dev/null > /tmp/verdict.log 2>&1; true
	@grep COST /tmp/verdict.log || echo "  no figure came back"
	@touch src/profile.c src/main.c
	@$(MAKE) --no-print-directory $(TARGET).elf > /dev/null

.PHONY: measure-verdict
