# Root of Trust Firmware for RISC-V with PMP Isolation

This project implements a bare-metal security firmware for RISC-V processors that emulates core TPM 2.0 functions. It uses Physical Memory Protection (PMP) to create hardware-enforced isolation between the crypto core and unprivileged code. The firmware runs on a custom QEMU fork where we added a Secure Storage MMIO device for persistent key storage.

The idea is to build something similar to what a TPM chip does, but entirely in firmware using the protection mechanisms that RISC-V already provides. No OS, no standard library, just our code running directly on the processor.

## Architecture

![Architecture Diagram](docs/architecture.png)

## What it does

The firmware boots in M-mode (the highest privilege level in RISC-V) and sets up the entire security environment before dropping to U-mode. Here is what happens at boot:

1. The bootstrap code (start.S) initializes the stack and jumps to main()
2. The trap handler is installed to catch PMP violations and ecall requests
3. PMP is configured with 5 protection regions that define who can access what
4. The Secure Storage MMIO device is initialized (8 slots of 64 bytes each)
5. The firmware measures its own code and data sections using SHA-256, recording the hashes in PCR0 and PCR1
6. The Endorsement Key (EK) and Storage Root Key (SRK) are derived from fixed seeds using an HMAC-SHA256 KDF, following the TPM 2.0 spec (Section 8.4.9)
7. All keys and PCR values are stored in the Secure Storage device
8. The firmware drops to U-mode where it runs security tests and demonstrates the shared memory interface

Once in U-mode, the code tries to read and write the secret zone to prove that PMP blocks both attempts. Then it uses the shared memory zone to request the crypto core to measure a simulated firmware binary, demonstrating the host-to-core communication channel.

## Building and running

You need the RISC-V cross-compiler and our custom QEMU fork that includes the Secure Storage device:
```bash
# Install the cross-compiler
sudo apt install gcc-riscv64-linux-gnu

# Clone and build the custom QEMU (only need to do this once)
git clone --depth 1 https://gitlab.com/secce/qemu-ccore.git ~/qemu-ccore
cd ~/qemu-ccore
./configure --target-list=riscv64-softmmu
cd build && ninja -j$(nproc)

# Clone and run the firmware
git clone https://gitlab.com/secce/riscv-rot.git
cd riscv-rot
make clean && make && make run
```

## Project structure

| Path | Description |
|------|-------------|
| `src/start.S` | Bootstrap in assembly: stack, BSS, jump to main |
| `src/main.c` | Orchestrates all setup steps |
| `src/uart.c` | Serial output via MMIO |
| `src/pmp.c` | Configures 5 PMP regions |
| `src/trap.c` | Handles PMP faults and ecall requests |
| `src/trap_entry.S` | Asm trampoline: save regs, call C handler, restore, mret |
| `src/switch.c` | M-mode to U-mode transition using mret |
| `src/user.c` | U-mode tests and shared memory client |
| `src/secure_storage.c` | Talks to MMIO device via registers |
| `src/pcr.c` | PCR extend operations |
| `src/keygen.c` | HMAC-SHA256 KDF for key derivation |
| `include/` | Header files for all modules |
| `lib/sha256.c` | Standalone SHA-256 (FIPS 180-4) |
| `scripts/virt.ld` | Linker script with section symbols |
| `docs/architecture.png` | Architecture diagram |
| `Makefile` | Build rules for cross-compilation and QEMU |
| `Dockerfile` | Container build for reproducible environment |

## Memory map

| Address | What lives here | U-mode access |
|---------|----------------|---------------|
| 0x10000000 | UART (serial port) | Read + Write |
| 0x10200000 | Secure Storage MMIO device | Blocked by PMP |
| 0x80000000 | Firmware (.text, .rodata, .data, .bss, stack) | Read + Write + Execute |
| 0x80100000 | Secret zone, 4KB (crypto keys in RAM) | Blocked by PMP |
| 0x80200000 | U-mode code | Read + Write + Execute |
| 0x80300000 | Shared memory zone, 4KB (host to core mailbox) | Read + Write, no execute |

## Secure Storage slots

| Slot | Content | Description |
|------|---------|-------------|
| 0 | EK | Endorsement Key, device identity (32 bytes) |
| 1 | SRK | Storage Root Key, master vault key (32 bytes) |
| 2 | PCR0 | Hash of firmware .text section |
| 3 | PCR1 | Hash of firmware .rodata section |
| 4 | PCR2 | Accumulated host binary measurements |
| 5 to 7 | Empty | Available for future use |

## Custom QEMU device

We forked QEMU and added a Secure Storage MMIO device at address 0x10200000. The device exposes 6 registers (CMD, STATUS, SLOT_ID, OFFSET, SIZE, DATA) and supports WRITE, READ, ERASE, and CHECK commands. The firmware sends data 4 bytes at a time through the DATA register. The fork lives at [gitlab.com/secce/qemu-ccore](https://gitlab.com/secce/qemu-ccore).

## References

- TPM 2.0 Library Specification v185, Trusted Computing Group
- RISC-V Privileged Specification
- NIST SP 800-108 Rev. 1, Key Derivation Functions
- FIPS 180-4, Secure Hash Standard (SHA-256)

## Author

Sebastian Alba, CE-1114, Instituto Tecnologico de Costa Rica

Supervisor: Dr.-Ing. Jeferson Gonzalez Gomez, SECCE Research Group
