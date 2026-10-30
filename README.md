# Root of Trust Firmware for RISC-V

Bare-metal security firmware for RISC-V. It implements TPM 2.0 style
services with Physical Memory Protection for isolation, verifies the next
boot stage against a signature, and answers attestation requests at
runtime using hardware event counters. No operating system and no
standard library, just firmware running on the processor.

Built as a graduation project at Instituto Tecnologico de Costa Rica.

## What the firmware does

The crypto core runs in machine mode and configures PMP so that nothing
below it can reach the secrets. User mode talks to the core through a
shared memory mailbox: it writes a command, raises an ecall, and the core
answers.

On top of that base the project adds three things.

**A two stage secure boot.** A small first stage verifies an Ed25519
signature over the second stage before handing control to it. The public
key lives in the read only section of the first stage, so replacing it
means replacing the stage that holds it.

**Runtime attestation from event counters.** The firmware programs the
hardware performance counters, opens a measurement window around the code
it observes, and compares three ratios against a per application profile.
The verdict is computed inside the root of trust, not on a remote
verifier, and it gates access to sealed secrets.

**A measurement campaign on emulator and on silicon.** Every count was
taken twice, once under QEMU with instruction accounting and once on a
HiFive Unmatched board with four SiFive U74 cores, and the two were
compared figure by figure.

## Quick start

```bash
sudo apt install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu make \
  git ninja-build libglib2.0-dev libpixman-1-dev libslirp-dev python3 \
  python3-venv pkg-config

# the firmware needs a patched QEMU, see qemu-patches/README.md
git clone https://gitlab.com/secce/qemu-ccore.git ~/qemu-ccore
cd ~/qemu-ccore && git checkout tfg-counters
mkdir -p build && cd build
../configure --target-list=riscv64-softmmu && ninja -j$(nproc)

# build and run the firmware
cd ~ && git clone https://github.com/Sebasteuo/riscv-rot.git
cd riscv-rot && make && make run
```

The firmware runs 36 tests and you should see `ALL TESTS PASSED` at the
end. Exit QEMU with Ctrl-A then X. For a pass or fail exit code, useful
in CI, run `make test` instead.

## Architecture

![Architecture Diagram](docs/architecture.png)

## Services

The firmware boots, measures its own code with SHA-256, derives its
identity keys from provisioning seeds, checks itself against the golden
values, and then drops to user mode to serve requests.

Through the mailbox it offers measurement of raw binaries into PCR
registers, a quote that signs the PCR state, sealed storage encrypted
with AES-128 under a key derived from that state, monotonic counters for
anti rollback, ELF validation against a hash whitelist, and supply chain
checks where every component must carry a registered vendor signature.

Access control asks for a password before any service. Three wrong
attempts trigger a lockout. After authenticating, the caller gets a
session token that expires after 20 calls.

All the symmetric cryptography is written from the specifications with no
external dependency: SHA-256 from FIPS 180-4, AES-128 from FIPS 197 and
HMAC-SHA256 from RFC 2104. Ed25519 verification uses TweetNaCl.

One naming note. The firmware calls its report key the Endorsement Key,
following TPM vocabulary, but that key is symmetric and derived on the
device. In the TCG credential profile the same name belongs to an
asymmetric pair, so the match is in the name and not in the mechanism.

## Reproducing the measurements

| Command | What it produces |
|---|---|
| `make test` | the platform test suite with a pass or fail exit code |
| `make secureboot` | builds both boot stages and the signed image |
| `make test-chain` | runs the full chain from the first stage |
| `make test-reject` | checks that a tampered image is refused |
| `make profiles` | prints the nominal profile of every application |
| `make check-profiles` | evaluates the classifier against those profiles |
| `make measure-service` | cost of the attestation service in instructions |
| `make measure-verdict` | cost of computing one verdict |
| `make verify-reports` | verifies the authentication code of every report |
| `make measure-evade` | the window placement trial, both halves |

Saved runs from the campaign are under `docs/tfg/`.

## Project structure

| Path | What it does |
|---|---|
| `src/start.S` | bootstrap: stack, BSS, jump to main |
| `src/main.c` | boot sequence, measurement, secure boot check |
| `src/pmp.c` | configures the 6 PMP regions |
| `src/trap.c` | trap handler with authentication, sessions and services |
| `src/switch.c` | machine mode to user mode transition |
| `src/user.c` | the user mode test suite |
| `src/hpm.c` | programs and reads the event counters |
| `src/attest.c` | the attestation window and the verdict |
| `src/profile.c` | the per application profiles and the band rule |
| `src/attack.c` | the adversarial scenarios used in the evaluation |
| `src/elf64.c` | ELF validation for measured launch |
| `include/image.h` | layout of the signed boot image |
| `src/stage1_main.c` | first stage: verifies the signed image |
| `lib/sha256.c` | SHA-256, FIPS 180-4 |
| `lib/aes128.c` | AES-128, FIPS 197 |
| `lib/hmac.c` | HMAC-SHA256, RFC 2104 |
| `lib/tweetnacl/` | Ed25519, public domain, see THIRD-PARTY.md |
| `src/bench/` | Embench benchmarks, see THIRD-PARTY.md |
| `compare/` | the harness that compares emulator against silicon |
| `qemu-patches/` | the QEMU changes this firmware needs |
| `tools/` | report verification and the management dashboard |

## Memory map

| Address | What | User mode |
|---|---|---|
| 0x02000000 | CLINT | blocked |
| 0x10000000 | UART | read and write |
| 0x10200000 | Secure Storage MMIO | blocked |
| 0x80000000 | crypto core, code, data and stack | blocked |
| 0x80080000 | shared code: UART, SHA-256, HMAC | read and execute |
| 0x80090000 | user mode code and stack | read, write and execute |
| 0x80100000 | secret zone, 4 KB | blocked |
| 0x80300000 | shared mailbox, 4 KB | read and write, no execute |

Slot 0 of the secure storage holds the report key, slot 1 the storage
root key, slots 2 to 4 hold PCR snapshots, slot 5 the monotonic counter,
slot 6 the sealed data and slot 7 the seal policy hash.

## QEMU changes

The firmware needs two things upstream QEMU does not have: a Secure
Storage device at 0x10200000 with 8 slots of 64 bytes, and seven extra
event counters outside the SBI encoding that count loads, stores,
branches, indirect jumps, privilege switches and traps taken.

Both are in `qemu-patches/` as a patch series, which records exactly what
changed. The emulator tree the measurements were taken on is the
`tfg-counters` branch at gitlab.com/secce/qemu-ccore. See
`qemu-patches/README.md` for why the patches are a record and not a build
recipe for today's QEMU.

## Tools

`tools/verify_quote.py` recomputes a report authentication code from the
provisioning seed and compares it against what the device produced. Run
it with `--demo` for a quick check.

`tools/rot_manager.py` parses QEMU output and shows the PCRs, the storage
slots, the counter values and the test results. It can export a JSON
report.

## References

TCG TPM 2.0 Library Specification v185, RISC-V Privileged Specification,
NIST SP 800-108, NIST SP 800-155, NIST SP 800-193, FIPS 180-4, FIPS 197,
RFC 2104 and RFC 8032.

## Author

Sebastian Alba Vives, Computer Engineering, Instituto Tecnologico de
Costa Rica.

Organisational counterpart: Dr.-Ing. Jeferson Gonzalez Gomez, SECCE
Research Group.

## License

GPL-3.0-or-later, see [LICENSE](LICENSE).

The firmware links the Embench benchmarks into the same image. Those
benchmarks are GPL-3.0-or-later, so the binary this repository builds is
a combined work under that licence. `THIRD-PARTY.md` lists every
component that keeps its own terms, including TweetNaCl, which is in the
public domain.
