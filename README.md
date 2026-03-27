# Root of Trust Firmware for RISC-V

A bare-metal security firmware that emulates TPM 2.0 functions using RISC-V Physical Memory Protection (PMP). No OS, no standard library — just firmware running directly on the processor with hardware-enforced isolation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: RISC-V](https://img.shields.io/badge/Platform-RISC--V%20RV64-green.svg)]()
[![QEMU: Custom Fork](https://img.shields.io/badge/QEMU-Custom%20Fork-orange.svg)](https://gitlab.com/secce/qemu-ccore)

## Quick Start

### Option 1: Docker (recommended, zero setup)
```bash
git clone https://gitlab.com/secce/riscv-rot.git && cd riscv-rot
docker build -t riscv-rot .
docker run --rm -it riscv-rot
```

### Option 2: Native build
```bash
# Install cross-compiler
sudo apt install gcc-riscv64-linux-gnu

# Build custom QEMU (one time only)
git clone --depth 1 https://gitlab.com/secce/qemu-ccore.git ~/qemu-ccore
cd ~/qemu-ccore && ./configure --target-list=riscv64-softmmu
cd build && ninja -j$(nproc) && cd ~

# Build and run the firmware
git clone https://gitlab.com/secce/riscv-rot.git && cd riscv-rot
make && make run
```

You should see `ALL TESTS PASSED` at the end.

## What is this?

A TPM (Trusted Platform Module) is a security chip found in most modern computers. It stores cryptographic keys, measures firmware integrity, and provides attestation so a remote party can verify your system has not been tampered with.

This project implements those same functions in firmware for RISC-V processors, using PMP (Physical Memory Protection) to create a hardware barrier between the security core and untrusted code. The crypto core runs in M-mode (highest privilege), and all external access goes through a controlled shared memory interface.

## Architecture

![Architecture Diagram](docs/architecture.png)

## Features

**Core Security**
- PMP isolation with 5 hardware-enforced memory regions
- SHA-256 implementation (FIPS 180-4) with no external dependencies
- AES-128 encryption (FIPS 197) for sealed data protection
- HMAC-SHA256 key derivation following NIST SP 800-108
- Endorsement Key (EK) and Storage Root Key (SRK) generation per TPM 2.0 spec
- Platform Configuration Registers (PCR0, PCR1, PCR2) for integrity measurement
- Custom QEMU MMIO device for persistent secure storage (8 slots × 64 bytes)

**Authentication & Access Control**
- Password-based authentication before any service access
- Dictionary Attack Lockout: 3 failed attempts triggers a cooldown period
- Authenticated Countdown Timers: session tokens with limited TTL
- Automatic session expiration and forced re-authentication

**Integrity & Attestation**
- Secure Boot: firmware hash compared against golden values at startup
- Measured Launch: ELF header validation (magic, class, architecture)
- Binary whitelist: SHA-256 hashes of approved code sections
- TPM2_Quote: HMAC-SHA256 signature of all PCRs for remote attestation
- Real binary measurement: actual firmware code measured, not dummy data

**Anti-Rollback & Sealed Storage**
- Monotonic NV Counters that only increment (anti-rollback protection)
- Sealed Storage with AES-128 encryption bound to PCR state
- If firmware is modified, PCRs change, AES key changes, sealed data stays locked

**Supply Chain Security**
- Multi-vendor key registration
- Component signature verification (HMAC-SHA256 per vendor)
- Unauthorized or tampered components are rejected

## TPM 2.0 API

The project includes a standard-compliant API that follows TPM 2.0 command naming:
```c
#include "tpm2_api.h"

/* Start a session (authenticate + get token) */
TPM2_Startup(password, password_len);

/* Measure a binary into PCR2 */
TPM2_PCR_Extend(2, firmware_binary, binary_size);

/* Get a signed attestation of all PCRs */
uint8_t signature[32];
TPM2_Quote(signature);

/* Seal secret data to current platform state */
TPM2_Seal(secret, secret_len);

/* Unseal (only works if firmware has not changed) */
uint8_t recovered[32];
TPM2_Unseal(recovered, 32);

/* Read/increment anti-rollback counter */
uint32_t counter;
TPM2_NV_Read(&counter);
TPM2_NV_Increment(expected_version, &new_value);

/* Validate an ELF binary */
TPM2_ELF_Validate(elf_header);

/* Verify supply chain signature */
TPM2_VerifySignature(vendor_id, signature, component, component_len);

/* End session */
TPM2_Shutdown();
```

All functions return `TPM2_RC_SUCCESS` (0) on success, or a specific error code.

## Python Tools

### Remote Attestation Verifier

Verifies that a device is authentic by checking its Quote signature:
```bash
python3 tools/verify_quote.py --demo     # quick test with example values
python3 tools/verify_quote.py            # interactive mode, paste QEMU output
```

### Management Dashboard

Parses firmware output and displays the complete RoT state:
```bash
make run 2>&1 | tee output.txt
# (kill QEMU with Ctrl+A, X)
python3 tools/rot_manager.py --parse output.txt     # dashboard view
python3 tools/rot_manager.py --report output.txt    # JSON export
```

## Project Structure

| Path | Description |
|------|-------------|
| `src/start.S` | Bootstrap in assembly: stack, BSS, jump to main |
| `src/main.c` | Boot sequence, firmware measurement, Secure Boot check |
| `src/uart.c` | Serial output via MMIO |
| `src/pmp.c` | Configures 5 PMP regions |
| `src/trap.c` | Trap handler: auth, sessions, crypto services, ELF, supply chain |
| `src/trap_entry.S` | Asm trampoline: save regs, call C handler, restore, mret |
| `src/switch.c` | M-mode to U-mode transition using mret |
| `src/user.c` | U-mode test suite (31 tests) |
| `src/secure_storage.c` | MMIO device driver for Secure Storage |
| `src/pcr.c` | PCR extend operations |
| `src/keygen.c` | HMAC-SHA256 KDF for key derivation |
| `src/tpm2_api.c` | TPM 2.0 compatible client library |
| `include/tpm2_api.h` | TPM 2.0 API definitions and documentation |
| `include/aes128.h` | AES-128 block cipher interface |
| `lib/sha256.c` | Standalone SHA-256 (FIPS 180-4) |
| `lib/aes128.c` | Standalone AES-128 (FIPS 197) |
| `tools/verify_quote.py` | Remote attestation verifier |
| `tools/rot_manager.py` | Management dashboard and JSON reporter |
| `scripts/virt.ld` | Linker script with section symbols |
| `docs/architecture.png` | Architecture diagram |
| `Makefile` | Build rules for cross-compilation and QEMU |
| `Dockerfile` | Container build for reproducible environment |

## Memory Map

| Address | Region | U-mode Access |
|---------|--------|---------------|
| `0x10000000` | UART (serial port) | Read + Write |
| `0x10200000` | Secure Storage MMIO device | **Blocked** by PMP |
| `0x80000000` | Firmware code and data | Read + Write + Execute |
| `0x80100000` | Secret zone, 4KB | **Blocked** by PMP |
| `0x80300000` | Shared memory zone, 4KB | Read + Write (no execute) |

## Secure Storage Slots

| Slot | Content | Size |
|------|---------|------|
| 0 | Endorsement Key (EK) | 32 bytes |
| 1 | Storage Root Key (SRK) | 32 bytes |
| 2 | PCR0 snapshot (.text hash) | 32 bytes |
| 3 | PCR1 snapshot (.rodata hash) | 32 bytes |
| 4 | PCR2 snapshot (host measurements) | 32 bytes |
| 5 | Monotonic NV Counter | 4 bytes |
| 6 | Sealed Data (AES-128 encrypted) | up to 32 bytes |
| 7 | Seal Policy (PCR state hash) | 32 bytes |

## Test Suite (31 tests)

| # | Test | What it proves |
|---|------|---------------|
| 1-2 | PMP read/write blocked | Hardware isolation works |
| 3 | Measure without auth | Auth is required |
| 4 | Wrong password ×3 | Dictionary attack lockout triggers |
| 5 | Measure while locked | Lockout rejects everything |
| 6 | Wait for lockout expiry | Cooldown timer works |
| 7 | Correct password | Authentication succeeds |
| 8 | Start session | Token-based sessions work |
| 9 | Measure with token | Service calls consume TTL |
| 10 | Exhaust TTL | Session expires correctly |
| 11 | Measure after expiry | Must re-authenticate |
| 12 | Re-auth + new session | Session renewal works |
| 13-15 | NV counter read/increment | Monotonic counter works |
| 16 | Rollback attempt | Anti-rollback rejects downgrade |
| 17 | Read counter after rollback | Counter unchanged |
| 18-19 | TPM2_Quote ×2 | Same PCRs produce same signature |
| 20 | Seal data | AES-128 encryption to PCR state |
| 21 | Unseal data | Decryption succeeds, data matches |
| 22 | Unseal after PCR change | PCR mismatch blocks decryption |
| 23-24 | Measure real firmware | Actual code bytes measured |
| 25 | Valid RISC-V ELF | ELF header accepted |
| 26 | ARM ELF rejected | Wrong architecture blocked |
| 27 | Whitelist register + verify | Section hash approved after registration |
| 28 | Register 3 vendors | Supply chain vendors registered |
| 29 | Verify signed component | Valid signature accepted |
| 30 | Tampered signature | Bad signature rejected |
| 31 | Unknown vendor | Unregistered vendor rejected |

## Custom QEMU Device

The project includes a fork of QEMU with a custom Secure Storage MMIO device at `0x10200000`. The device has 6 registers (CMD, STATUS, SLOT_ID, OFFSET, SIZE, DATA) and supports WRITE, READ, ERASE, and CHECK operations. Data is transferred 4 bytes at a time through the DATA register. The fork lives at [gitlab.com/secce/qemu-ccore](https://gitlab.com/secce/qemu-ccore).

## References

- TCG TPM 2.0 Library Specification v185 (Parts 0, 1, and 3)
- RISC-V Privileged Specification v1.12
- NIST SP 800-108 Rev. 1 (Key Derivation Functions)
- NIST SP 800-155 (BIOS Integrity Measurement Guidelines)
- NIST SP 800-193 (Platform Firmware Resiliency Guidelines)
- FIPS 180-4 (Secure Hash Standard, SHA-256)
- FIPS 197 (Advanced Encryption Standard, AES)
- Sailer et al., "Design and Implementation of a TCG-based IMA", USENIX Security 2004

## Author

**Sebastian Alba** — Computer Engineering, Instituto Tecnológico de Costa Rica

Supervisor: Dr.-Ing. Jeferson González Gómez, SECCE Research Group
