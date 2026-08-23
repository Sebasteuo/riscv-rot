# Research Gap: Scope and Justification

**Stage 1, item 3** - CE-5600 Final Project - Sebastian Alba Vives
21 August 2026

---

## 1. What the project proposal claimed

The approved proposal stated that combining a bare-metal root of trust for
RISC-V with runtime attestation backed by machine learning over performance
counters was a largely unexplored line.

After the systematic review, **that claim is too broad and needs narrowing.**
Adjacent work exists, and an informed reader will find it. Stating the gap
precisely is stronger than stating it widely.

---

## 2. What is already occupied

Four published or preprint works sit close enough to matter.

| Work | Venue | What it establishes |
|---|---|---|
| CHARM | ACM TECS 2023 | Performance counters as attestation evidence on a Cortex-M33, with the classifier on the verifier |
| LightFAt | IEEE HOST 2024 | PMU readings plus unsupervised learning for control-flow attestation on x86-64 |
| LightFAt+ | ACM TCPS 2026 | Same approach extended to ARM Cortex-A78 |
| HPCCFA | arXiv 2026, not peer reviewed | Performance counters for control-flow attestation **on RISC-V**, inside a Keystone enclave, evaluated on real silicon |

Two claims are therefore unavailable:

- **Not the first to use performance counters as attestation evidence.**
  LightFAt states this explicitly as its own contribution.
- **Not the first to do so on RISC-V.** HPCCFA got there in March 2026,
  although without peer review.

---

## 3. What remains unoccupied

The gap survives, but along three axes rather than as a general claim.

### Axis 1 - Bare-metal, with no operating system beneath

Every work above assumes a supervisor layer. CHARM targets a Cortex-M with an
RTOS. LightFAt and LightFAt+ run on x86-64 with CentOS and on an ARM
application core. HPCCFA runs inside a Keystone enclave, which requires a
security monitor and a host operating system.

This work runs directly at M-mode with PMP as the only isolation mechanism.

### Axis 2 - The classifier runs inside the root of trust

CHARM, LightFAt and LightFAt+ all place inference on the verifier. HPCCFA
generates control-flow traces rather than classifying at all.

Here the model runs on the device, inside the protected region. This is a
stronger claim than the prior work makes, and it carries a cost that has to
be justified: memory footprint and cycle budget inside a component that must
stay small and auditable.

### Axis 3 - Architectural rather than microarchitectural events

LightFAt uses IPC and L1 cache accesses. HPCCFA uses retired instructions,
branches and loads. This work uses loads, stores, taken branches, indirect
jumps, traps and privilege transitions.

The choice is forced rather than preferred: under functional emulation,
microarchitectural state has no meaningful existence. That constraint is
declared, not presented as a design decision.

---

## 4. Why the bare-metal setting matters beyond novelty

The axes above establish that the work is different. This section argues that
the difference is consequential.

Two frequently cited results argue against counter-based security:

- Zhou et al. (AsiaCCS 2018) report a negative result on multiprocess Linux
  and tie their argument to workload entropy.
- Das et al. (IEEE S&P 2019) systematise four failure modes: non-determinism,
  overcounting, cross-process contamination, and loss at context switches.

**Both are results about systems with an operating system.** Two of the four
failure modes are direct consequences of having a scheduler and multiple
processes, and they do not arise here. The remaining two were bounded
experimentally: over ten runs the discrete event counters showed zero spread
and the instruction counters stayed below 0.011%, with the residual variation
traced to a specific line of firmware rather than to measurement error.

The organisational counterpart, who authored LightFAt, independently
identified data collection under operating system noise as the hardest part
of that work. The setting this project targets removes that noise by
construction.

---

## 5. How the objective is framed

Following consultation with the organisational counterpart, **OE3 is stated
as an effectiveness evaluation rather than as a detector.**

The question is: *do architectural event counters carry enough signal to
discriminate nominal from anomalous behaviour in a bare-metal root of trust?*

This framing matters for two reasons.

**It matches what can be honestly concluded.** A classifier trained on
synthetic scenarios in emulation does not license a claim about detecting
real compromise on real hardware. It does license a claim about whether the
signal is separable.

**A negative result still answers the question.** If the counters turn out
not to discriminate with useful margin, the methodology and the limitation
are the contribution. The project proposal already anticipates this in its
risk table.

---

## 6. The claim, stated precisely

> This work evaluates whether architectural event counters, synthesised in an
> instrumented emulator and read from within a bare-metal RISC-V root of trust,
> provide sufficient signal to discriminate nominal from anomalous execution of
> the monitored system, with classification performed on the device rather than
> on a remote verifier.

Everything in that sentence is defensible. Nothing in it claims priority over
work that got there first.

---

## 7. Limitations carried forward

- **No evaluation on silicon.** HPCCFA has this; this work does not. Declared
  in the project proposal and retained as future work.
- **Detection is probabilistic, not absolute.** The classifier detects
  deviation from learned behaviour. An attack reproducing the nominal profile
  goes undetected.
- **Adversarial evasion is partially mitigated, not solved.** Randomised
  measurement points raise the cost of the compensation attack that ConFirm
  documents, without eliminating it.
