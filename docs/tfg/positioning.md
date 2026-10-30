# Positioning Against the State of the Art

**Stage 1, item 2** - CE-5600 Final Project - Sebastian Alba Vives
22 August 2026

---

## 1. Structure

This work sits at the intersection of two research lines that have so far
run separately: roots of trust on RISC-V, and behavior classification using
hardware performance counters. Each line is addressed on its own, followed by
the few works that cross both.

---

## 2. Line A: roots of trust on RISC-V

| Work | Venue | What it does | How it differs |
|---|---|---|---|
| Sanctum | USENIX Sec 2016 | Security monitor at M-mode with minimal hardware extensions | Sets the pattern this work inherits. Requires custom hardware extensions |
| Keystone | EuroSys 2020 | TEE built from PMP and M-mode alone, dynamic enclaves | The mandatory comparison point. Requires an operating system underneath and targets multi-tenant enclaves |
| OpenTitan | Official documentation | Silicon root of trust, ROM to ROM_EXT to BL0 signed chain | The real-world deployment model for OE1. It is a complete closed chip, not reproducible |
| fTPM | USENIX Sec 2016 | Full TPM 2.0 in firmware on TrustZone | Precedent for a firmware TPM. Requires TrustZone and an operating system |
| fTPM on RISC-V | DATE 2021 | Firmware TPM for RISC-V | **A design proposal, not an implementation.** Depends on OP-TEE and a rich operating system. The authors list porting OP-TEE to RISC-V as future work |
| LIRA-V | IEEE SPW 2021 | Remote attestation on constrained RISC-V, ROM and PMP as anchor | The closest match to this scenario. Static challenge-response attestation, not runtime |
| Lightweight secure boot | ISQED 2019 | Signed boot chain on a RISC-V SoC, ECDSA and SHA-3 | **Confirms asymmetric signatures are the right approach.** They solve it with a dedicated hardware block, while this work is pure software at M-mode |

**Where this work sits.** The niche is a bare-metal, open and reproducible
root of trust: no operating system underneath as Keystone requires, and no
closed silicon as OpenTitan is. The DATE 2021 work aims at the same place but
remains a design that depends on OP-TEE. This platform runs with no operating
system and no C standard library.

---

## 3. Line B: performance counters and classification

| Work | Venue | What it does | How it differs |
|---|---|---|---|
| Demme et al. | ISCA 2013 | Founds the field. Counter time series plus classifiers detect malware | x86 and ARM with a full operating system. Supervised. Malware detection, not attestation |
| Tang et al. | RAID 2014 | Unsupervised one-class detection, models only benign behavior | **Closest in method.** Their architectural features map almost one to one onto the ones used here. x86 with an operating system |
| NumChecker | DAC 2013 | Counts events between known checkpoints in privileged flow | Deterministic profile matching, no learning. Linux kernel |
| ConFirm | ICCAD 2015 | Detects firmware modification in embedded systems using counters | **Validates the architectural decision here:** the detector lives inside the bootloader. But it compares against stored signatures, without learning, and it instruments the monitored firmware |
| Zhou et al. | AsiaCCS 2018 | Negative result: on multiprocess Linux, counters do not separate benign from malicious | Their causality argument scales with workload entropy. Fixed deterministic firmware sits at the opposite extreme |
| Das et al. | IEEE S&P 2019 | Systematizes the pitfalls of counters in security | **The mandatory defensive citation.** Two of their four problems do not apply to bare-metal. The other two are bounded experimentally here |
| Basu et al. | IEEE TIFS 2020 | Analytical framework for detection robustness | The counterweight to the two critiques above. Their guarantee assumes the attacker does not know which counters are observed |

**Where this work sits.** This entire line runs on systems with an operating
system, and places the classifier either outside the device or inside the
processor itself, never inside a root of trust.

---

## 4. Works that cross both lines

There are four, and they define the novelty claim.

| Work | Platform | Classifier location | Evidence used |
|---|---|---|---|
| **CHARM** - ACM TECS 2023 | ARM Cortex-M33 | On the verifier | Counters, to make hash-based attestation interruptible |
| **LightFAt** - IEEE HOST 2024 | x86-64 with CentOS | On the verifier | IPC and L1 cache accesses, microarchitectural |
| **LightFAt+** - ACM TCPS 2026 | x86-64 and ARM Cortex-A78 | On the verifier | Same, extended to ARM |
| **HPCCFA** - arXiv 2026, not peer reviewed | RISC-V, Keystone enclave | Generates traces, does not classify | Retired instructions, branches and loads |
| **This work** | **RISC-V bare-metal, M-mode with PMP** | **Inside the root of trust** | **Synthesized architectural events** |

### Detail

**CHARM** is the closest antecedent in objective. It reads counters on the
device and runs machine learning on the verifier. Its goal, however, is to
make hash-based attestation interruptible, not to classify integrity state.
It targets a Cortex-M33, not RISC-V, and is not framed as a root of trust
service.

**LightFAt and LightFAt+** are the most direct published bridge between
counters, machine learning and attestation. The first author is affiliated
with the Costa Rica Institute of Technology and is the organizational
counterpart for this project. They use two features, both microarchitectural,
and the classifier runs on the verifier. The journal version extends the
evaluation to an ARM Cortex-A78, still an application core running an
operating system.

**HPCCFA** is the closest in platform and appeared in March 2026. It uses
performance counters for control-flow attestation **on RISC-V**, which no
prior work had done. Three differences: it runs inside a Keystone enclave,
that is, with a security monitor and an operating system. It generates
control-flow traces rather than classifying with a model, and it is not peer
reviewed. One point in their favor should be acknowledged: they evaluate on
real silicon, while this work evaluates under instrumented emulation.

---

## 5. The three distinguishing axes

After this survey, the novelty rests on three axes, and stating them this
narrowly is deliberate.

**Axis 1 - Platform.** RISC-V bare-metal at M-mode with PMP, with no
operating system or security monitor underneath. CHARM targets Cortex-M,
LightFAt targets x86 and ARM with an operating system, HPCCFA runs inside a
Keystone enclave.

**Axis 2 - Where the decision is made.** The classifier runs **inside the
root of trust**, on the device. The three prior works place it on the
verifier or do not classify at all. This is a stronger claim than CHARM's and
requires justifying the memory and cycle budget.

**Axis 3 - What is observed.** Architectural rather than microarchitectural
events. This is not an aesthetic preference: under functional emulation,
microarchitectural state does not exist in any meaningful sense. The choice
is forced by the platform and must be argued as such.

---

## 6. What cannot be claimed

Stated plainly, because an informed reader will check.

- **Not the first to use counters as attestation evidence.** LightFAt claims
  that explicitly.
- **Not the first to use counters on RISC-V for attestation.** HPCCFA got
  there first, though without peer review.
- **No evaluation on real silicon.** HPCCFA has that. This limitation was
  declared in the project proposal and remains future work.
