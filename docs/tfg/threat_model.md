# Threat Model

**Stage 1, item 4** - CE-5600 Final Project - Sebastian Alba Vives
22 August 2026

---

## 1. Purpose

A threat model states three things: what is being protected, against whom,
and what is deliberately left out. What is left out is declared, not hidden.

The model in the project proposal was preliminary. This document refines it
using the literature review and what has already been measured on the
platform.

---

## 2. Assets

Ordered by what is lost if the asset falls.

| # | Asset | Location | Impact if compromised |
|---|---|---|---|
| A1 | EK, the device identity key | Secure Storage, `0x10200000` | The attacker can impersonate the device. All attestation loses its meaning |
| A2 | SRK, the storage key | Secure Storage | The attacker can unseal protected data |
| A3 | PCR values | Protected region, `0x80100000` | The attacker can forge evidence of a clean boot |
| A4 | Anti-rollback counter | Secure Storage | The attacker can install old firmware with known flaws |
| A5 | Stage-1 and its embedded public key | ROM on real hardware, separate image here | The whole chain falls. This is the root |
| A6 | The classifier model | Inside the crypto core (OE3) | The attacker can study it to evade detection |
| A7 | Counter values | CSRs, read only from M-mode | The attacker can forge behavioral evidence |

The first four are already protected by the base platform. The last three
appear with this project.

---

## 3. Adversary model

### In scope

**A1. Modify the firmware while the device is powered off.**
The attacker has access to the storage medium and can rewrite the image.
This is the classic tampered-firmware scenario.

**A2. Modify the reference value together with the firmware.**
This is the one that matters. The current Secure Boot compares against
hashes stored on the same device, so an attacker who changes both passes
verification. **This is the gap OE1 closes.**

**A3. Compromise the U-mode system at runtime.**
Memory corruption, code injection, control-flow hijacking. The system boots
clean and is compromised afterwards. **This is the gap OE3 closes.**

**A4. Read or write crypto core resources from U-mode.**
Already covered by PMP and verified by tests that attempt the access and
receive a processor exception.

**A5. Send arbitrary or malformed commands through the mailbox.**
Unknown command codes, out-of-range sizes, inconsistent fields. Already
covered: an unknown command returns an error and leaves internal state
untouched.

**A6. Evade the classifier by shaping the counter profile.**
The attacker knows the system and tunes the attack so the counts resemble
nominal behavior. Dinakarrao et al. (DAC 2019) show that detectors based on
microarchitectural events are evadable this way. ConFirm (ICCAD 2015)
describes the concrete variant: if the attacker knows where the measurement
points are, they can alter the flow between two of them and compensate
afterwards so the totals match.

**A7. Replay an old attestation report.**
The attacker stores a response from when the system was healthy and replays
it later. Coker et al. call this the freshness principle.

### Out of scope, with justification

**O1. Physical attacks.** Probing, decapping, direct memory readout. Outside
the scope of a work based on emulation.

**O2. Side channels.** Timing, power, cache. The platform does not consider
them and the emulator does not model them faithfully.

**O3. Fault injection.** This one must be declared carefully because it bears
directly on OE1. BADFET (WOOT 2017) and the ESP32-C3 work (WOOT 2024) show
that a correct signature verification can be bypassed by skipping the branch
that consumes its result. **Asymmetric signatures close software substitution,
not fault injection.** Better to state this than to overclaim.

**O4. Compromise of the emulator or the host machine.** If the attacker
controls QEMU, they control everything. This is the boundary of the
experimental environment.

**O5. Compromise of Stage-1 itself.** The model assumes Stage-1 is immutable.
On real hardware this is achieved by placing it in mask ROM, which is what
SMART, LIRA-V and OpenTitan all do. Here it is declared as an assumption
because the emulator does not model real ROM.

**O6. Theft of the private signing key.** It never enters the device. It
lives where the firmware is built.

**O7. Physical memory aliasing against PMP.** Recent work demonstrates a
BadRAM-style attack that bypasses PMP-based isolation through physical
memory aliasing. It requires the ability to manipulate the physical mapping,
so it falls under O1, but it is worth naming because it is PMP-specific and
an informed reader might ask about it.

---

## 4. Attack to mechanism mapping

| Attack | Covering mechanism | Status |
|---|---|---|
| A1, A2 | Two-stage Secure Boot with Ed25519 signature | **OE1**, in progress |
| A3 | Runtime attestation over architectural counters | **OE2 and OE3** |
| A4 | PMP isolation, six regions with no catch-all | Done and verified |
| A5 | Command validation at the mailbox | Done and verified |
| A6 | Randomized measurement points | **OE3**, partial mitigation |
| A7 | External challenge through the mailbox | **OE3** |

---

## 5. Security properties claimed

Being precise about what is claimed, and how strongly, matters here.

**P1. Confidentiality of the keys against U-mode software.**
Strong guarantee: enforced by the processor through PMP, not by a program.
Verified by tests that attempt the access and receive an exception.

**P2. Integrity of the PCRs against U-mode software.**
Strong guarantee, same mechanism.

**P3. Authenticity of the firmware that boots.**
Strong guarantee under assumption O5, that Stage-1 is immutable. Without
that assumption no root of trust is possible, and it is the same assumption
every work in this area makes.

**P4. Freshness of runtime evidence.**
Strong guarantee provided the challenge comes from outside. This is why the
design does not generate its own challenge.

**P5. Detectability of a U-mode compromise.**
**Probabilistic, not absolute.** This must be stated plainly. The classifier
detects deviations from learned behavior, not compromises as such. An attack
that reproduces the nominal profile goes undetected.

Basu et al. (IEEE TIFS 2020) provide the quantitative frame: with four
monitored counters the probability that an attacker matches all of them falls
below e^-40. However, their model assumes the attacker does not know which
counters are being observed. In this work the counter set is public, so that
guarantee is weaker and the difference must be declared.

---

## 6. What the platform already demonstrates

These are measured results, not assumptions.

**Isolation works.** Four of the 35 tests attempt to violate PMP and all four
receive a processor exception: reading the secret region, writing to it,
reading the crypto core code, and reading Secure Storage. A fifth attempt
writes `pmpcfg0` from U-mode and receives an illegal instruction trap.

**The mailbox validates.** An unknown command returns an error without
touching internal state.

**The counters are deterministic.** Ten runs of the same binary: the discrete
event counters are identical, the instruction counters vary below 0.011%, and
that variation is fully explained by the number of decimal digits the
firmware prints. It is not measurement error.

That last result answers Das et al. (IEEE S&P 2019) directly, which is the
strongest critique of using performance counters for security. Their four
problems are non-determinism, overcounting, cross-process contamination and
loss at context switches. The last two do not apply because there is no
scheduler and no context switching. The first two are bounded experimentally.

---

## 7. Open items

- Adversarial evasion (A6) is partially mitigated, not solved. It must be
  reported as a limitation, not as a solved problem.
- The immutable Stage-1 assumption (O5) cannot be demonstrated under
  emulation. It is declared and justified by the practice of the field.
- Fault injection (O3) is out of scope and must be stated when reporting OE1,
  to avoid overclaiming what asymmetric signatures provide.
