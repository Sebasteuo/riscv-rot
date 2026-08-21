#!/usr/bin/env python3
"""
Baseline variance experiment for the architectural event counters.

Runs the firmware N times from a clean state and reports, for each
counter, whether the value is stable across runs.

It also correlates the counts with the total number of decimal digits
printed by timer_report(), which is the only source of variation found:
uart_put_dec() runs one extra division loop per additional digit, and
each digit costs a fixed number of instructions.

Usage:
    python3 tools/hpm_variance.py [runs]
"""

import os
import re
import subprocess
import sys

COUNTERS = [
    "PRIV_SWITCH",
    "TRAP_TAKEN",
    "LOAD_RETIRED",
    "STORE_RETIRED",
    "JUMP_INDIRECT",
    "BRANCH_TAKEN",
]

QEMU = os.path.expanduser("~/qemu-ccore/build/qemu-system-riscv64")
CMD = [
    QEMU, "-machine", "virt", "-cpu", "rv64", "-m", "128M",
    "-nographic", "-bios", "none", "-kernel", "firmware.elf", "-smp", "1",
]
STATE_FILE = "secure_storage.bin"
TIMEOUT_S = 90


def one_run():
    """Run the firmware once from a clean state, return its output."""
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
    try:
        return subprocess.run(
            CMD, capture_output=True, text=True, timeout=TIMEOUT_S
        ).stdout
    except subprocess.TimeoutExpired as exc:
        # The firmware ends in a wfi loop, so a timeout is the normal exit.
        return exc.stdout.decode() if exc.stdout else ""


def parse(output):
    """Extract counter values and the printed digit total from one run."""
    counts = {}
    for name in COUNTERS:
        match = re.search(
            r"\[HPM\]\s+" + name + r"\s*\(ctr\d+\):\s*(\d+)", output
        )
        counts[name] = int(match.group(1)) if match else None

    printed = [int(v) for v in re.findall(r"=\s*(\d+)\s*us", output)]
    digits = sum(len(str(v)) for v in printed)
    return counts, digits, len(printed)


def main():
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 10

    if not os.path.exists("firmware.elf"):
        sys.exit("firmware.elf not found, run make first")

    samples = []
    for i in range(runs):
        counts, digits, printed = parse(one_run())
        samples.append((counts, digits, printed))
        print("run %2d done  (%d digits over %d printed values)"
              % (i + 1, digits, printed))

    print()
    print("%-16s %-12s %-12s %-8s %s"
          % ("COUNTER", "MIN", "MAX", "SPREAD", "RELATIVE"))
    print("-" * 62)

    for name in COUNTERS:
        values = [s[0][name] for s in samples]
        if any(v is None for v in values):
            print("%-16s could not be parsed" % name)
            continue
        lo, hi = min(values), max(values)
        spread = hi - lo
        rel = (spread / hi * 100.0) if hi else 0.0
        print("%-16s %-12d %-12d %-8d %.4f%%" % (name, lo, hi, spread, rel))

    # Cost per printed digit, isolating the only known source of variation.
    print()
    print("Cost per extra printed digit:")
    by_digits = {}
    for counts, digits, _ in samples:
        by_digits.setdefault(digits, counts)

    keys = sorted(by_digits)
    if len(keys) < 2:
        print("  all runs printed the same number of digits, nothing to compare")
        return

    lo_k, hi_k = keys[0], keys[-1]
    span = hi_k - lo_k
    for name in COUNTERS:
        a, b = by_digits[lo_k][name], by_digits[hi_k][name]
        if a is None or b is None:
            continue
        print("  %-16s %+d per digit" % (name, (b - a) // span))


if __name__ == "__main__":
    main()
