# Architectural Event Counters in qemu-ccore

**OE2 deliverable** - CE-5600 Final Project - Sebastian Alba Vives
22 August 2026

Branch: `tfg-counters` in the qemu-ccore fork.

---

## 1. Starting point

Upstream QEMU defines five performance counter events for RISC-V, and
only two of them actually count:

| Event | ID | Counts? |
|---|---|---|
| `HW_CPU_CYCLES` | `0x01` | Yes, approximated from the host clock |
| `HW_INSTRUCTIONS` | `0x02` | Yes, approximated |
| `CACHE_DTLB_READ_MISS` | `0x10019` | No, declared only |
| `CACHE_DTLB_WRITE_MISS` | `0x1001B` | No, declared only |
| `CACHE_ITLB_PREFETCH_MISS` | `0x10021` | No, declared only |

The three cache events appear in the validation switch in `pmu.c` but
have no increment logic anywhere in the tree. None of the events this
project needs existed.

What upstream does provide, and this work reuses rather than rebuilds:
`riscv_pmu_incr_ctr()` in `pmu.c` already implements privilege-mode
filtering through the `MINH`, `SINH` and `UINH` bits, overflow handling
with the `LCOFI` interrupt, and dynamic event to counter mapping.

---

## 2. New events

Six events in the `0xF0`-`0xF5` range, which falls outside the SBI v0.3
encoding. The privileged specification states that event selectors are
WARL and platform-defined, so defining custom events is spec-compliant
rather than a workaround.

| ID | Name | Counts |
|---|---|---|
| `0xF0` | `LOAD_RETIRED` | Executed load instructions |
| `0xF1` | `STORE_RETIRED` | Executed store instructions |
| `0xF2` | `BRANCH_TAKEN` | Conditional branches actually taken |
| `0xF3` | `JUMP_INDIRECT` | `jalr` instructions: returns and indirect calls |
| `0xF4` | `TRAP_TAKEN` | Exceptions and interrupts taken |
| `0xF5` | `PRIV_SWITCH` | Real privilege mode transitions |

---

## 3. Changes to qemu-ccore

Five files, all on the `tfg-counters` branch.

**`target/riscv/cpu.h`** - six entries added to
`enum riscv_pmu_event_idx`.

**`target/riscv/pmu.c`** - the six new events added to the validation
switch in `riscv_pmu_update_event_map()`. Without this the firmware
cannot bind them to a counter, since the default case returns `-1`.

**`target/riscv/cpu_helper.c`** - two direct instrumentation points,
both in existing C functions. `riscv_cpu_set_mode()`, inside the
conditional that already detects a real mode change, so calls that
leave the privilege level unchanged are not counted. And
`riscv_cpu_do_interrupt()`, after the declaration block, before any
state is modified.

**`target/riscv/helper.h`** and **`target/riscv/op_helper.c`** - a
helper, `helper_ccore_count()`, declared and implemented. It exists
because the remaining four events are produced by translated
instructions, and the translator runs once while the translated code
runs many times. Incrementing directly in the translation function
would count translations, not executions. The helper is called from
generated code, so it runs per execution.

**`target/riscv/insn_trans/trans_rvi.c.inc`** - four instrumentation
points, chosen so a single edit covers a whole instruction family:

| Location | Event | Coverage |
|---|---|---|
| `gen_load` | `LOAD_RETIRED` | `lb`, `lh`, `lw`, `ld` and unsigned variants |
| `gen_store` | `STORE_RETIRED` | `sb`, `sh`, `sw`, `sd` |
| `trans_jalr` | `JUMP_INDIRECT` | All indirect jumps |
| After `gen_set_label(l)` in `gen_branch` | `BRANCH_TAKEN` | Taken conditional branches only |

The branch case deserves a note. A conditional branch instruction always
executes, but the jump is only taken when the comparison holds.
`tcg_gen_brcond_tl` jumps to label `l` when the condition is true, so
the code following the label is the taken path. Placing the helper at
the top of `gen_branch` would have counted every executed conditional
branch instead.

---

## 4. Firmware side

**`include/hpm.h`** defines the event ids, the physical counter indices
and the privilege inhibit bits.

**`src/hpm.c`** maps events to counters 3 through 8, clears them, and
reads them back. Mapping happens immediately before dropping to U-mode
so the counts cover the monitored run rather than the M-mode setup.

**`src/hpm_test.c`** holds the unit tests described below.

---

## 5. Privilege mode filtering

The four instruction counters run with `MINH` set, which stops counting
while the processor is in M-mode.

This is not a refinement, it is what makes the measurement usable:

| Counter | All modes | U-mode only | U-mode share |
|---|---|---|---|
| `LOAD_RETIRED` | 1 132 269 | 120 226 | 10.6% |
| `STORE_RETIRED` | 543 810 | 67 460 | 12.4% |
| `JUMP_INDIRECT` | 54 255 | 8 564 | 15.8% |
| `BRANCH_TAKEN` | 148 166 | 16 555 | 11.2% |

Between 84 and 89 percent of the unfiltered signal is the crypto core
observing itself. Training a classifier on that would mean most of the
input describes the monitoring code rather than the system being
monitored.

`PRIV_SWITCH` and `TRAP_TAKEN` are left unfiltered because those events
occur at the transition itself rather than inside a privilege mode.

This filtering is the bare-metal equivalent of the per-process event
filtering whose absence Das et al. (IEEE S&P 2019) identify as a core
weakness of counter-based security work on commodity systems.


---

## 6. Verification

### Unit tests

Each test runs a workload with a known event count and checks the delta.

| Test | Counted | Expected | Interpretation |
|---|---|---|---|
| `LOAD_RETIRED` | 5005 | >= 1000 | 5 loads per iteration under `-O0` on volatile data |
| `STORE_RETIRED` | 2006 | >= 1000 | 2 stores per iteration |
| `BRANCH_TAKEN` | 1000 | >= 999 | Exact |
| `JUMP_INDIRECT` | 1002 | >= 1000 | 1000 returns plus test entry and exit |

The expected values are lower bounds because the loop, the CSR reads and
the bookkeeping also retire instructions. Demanding exact equality would
make the tests brittle without making them stronger.

### Cross-check

`PRIV_SWITCH` and `TRAP_TAKEN` are validated against each other rather
than by an isolated test. Over a full run `PRIV_SWITCH` is exactly twice
`TRAP_TAKEN`, because every trap produces one transition into M-mode and
one back out. This relation held across every run performed.

### Isolation

Test 36 in the firmware test suite attempts to read `mhpmcounter5` from
U-mode and receives an illegal instruction trap: `mcause` `0x2`, `mtval`
`0xb05027f3`, which is the `csrr` encoding itself. `mcounteren` is
deliberately left unset, so the counters are not delegated to U-mode and
a compromised system cannot read them to learn what profile it would
need to imitate.

### Determinism

`tools/hpm_variance.py` runs the firmware N times from a clean state and
reports the spread of each counter. Over ten runs:

| Counter | Spread | Relative |
|---|---|---|
| `PRIV_SWITCH` | 0 | 0% |
| `TRAP_TAKEN` | 0 | 0% |
| `LOAD_RETIRED` | 66 | 0.006% |
| `STORE_RETIRED` | 54 | 0.010% |
| `JUMP_INDIRECT` | 6 | 0.011% |
| `BRANCH_TAKEN` | 12 | 0.008% |

The spread is not measurement noise. It correlates exactly with the
number of decimal digits printed by `timer_report()`: `uart_put_dec()`
runs one extra division loop per additional digit, costing a fixed 22
loads, 18 stores, 2 indirect jumps and 4 taken branches. Runs that print
the same digit total produce identical counts.

For comparison, Das et al. note that a variation of one to five percent in counter values can degrade the performance of security models, a figure they take from earlier work. These figures sit two orders of magnitude below that range, and the residual variation is
attributable to executed work rather than to counting error.

---

## 7. Known limitations

**Event to counter mapping is one to one.** `riscv_pmu_update_event_map`
returns early if the event id is already present in the lookup table, so
writing the same event to a second `mhpmevent` register is silently
ignored. A filtered and an unfiltered view of the same event cannot
coexist within a single run. The comparison in section 5 was obtained by
running twice with different configurations.

**Cycle and instruction counts are approximated.** The two upstream
events derive from the host clock or from icount rather than being
simulated. The six events added here are incremented per event and do
not share that property.

**Counters are architectural, not microarchitectural.** Cache and TLB
behavior is not modelled with fidelity under functional emulation, so
events of that kind are unavailable by construction. This constrains the
feature set for OE3 and is declared as a limitation rather than
presented as a design preference.

---

## 8. Reproducing

    cd qemu-ccore
    git checkout tfg-counters
    ./configure --target-list=riscv64-softmmu --enable-debug
    make -j$(nproc)

    cd ../riscv-rot
    git checkout tfg
    make
    make run
    python3 tools/hpm_variance.py 10
