#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Collect attestation samples across repeated firmware runs.

Runs the firmware N times from a clean state, parses the [ATT] rows it
prints, and writes every window to a CSV file. Also reports how much
the nominal behaviour varies between runs, which is the baseline any
anomaly has to stand out from.

Each row is one command window: the counter deltas accumulated during
the U-mode execution that led up to that command.

Usage:
    python3 tools/collect_samples.py [runs] [output.csv]
"""

import os
import re
import subprocess
import sys

FEATURES = ["load", "store", "branch", "jump", "trap", "priv"]

QEMU = os.path.expanduser("~/qemu-ccore/build/qemu-system-riscv64")
CMD = [
    QEMU, "-machine", "virt", "-cpu", "rv64", "-m", "128M",
    "-nographic", "-bios", "none", "-kernel", "firmware.elf", "-smp", "1",
]
STATE_FILE = "secure_storage.bin"
TIMEOUT_S = 90

ROW = re.compile(r"^\[ATT\] (\d+(?:,\d+){6})$", re.MULTILINE)


def one_run():
    """Run the firmware once from a clean state and return its output."""
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
    """Extract every sample row as a list of ints."""
    return [[int(v) for v in m.split(",")] for m in ROW.findall(output)]


def summarise(runs):
    """Report how stable the nominal behaviour is across runs."""
    counts = [len(r) for r in runs]
    print()
    print("windows per run: %s" % counts)

    if len(set(counts)) == 1:
        print("  -> every run produced the same number of windows")
    else:
        print("  -> window count varies, so runs are not directly comparable")
        return

    n = counts[0]
    unstable = 0

    print()
    print("%-8s %-10s %-10s %-8s %s"
          % ("WINDOW", "MIN", "MAX", "SPREAD", "FEATURE"))
    print("-" * 56)

    for w in range(n):
        for f in range(1, len(FEATURES) + 1):
            vals = [r[w][f] for r in runs]
            lo, hi = min(vals), max(vals)
            if hi != lo:
                unstable += 1
                if unstable <= 12:
                    print("%-8d %-10d %-10d %-8d %s"
                          % (w, lo, hi, hi - lo, FEATURES[f - 1]))

    total = n * len(FEATURES)
    print()
    print("%d of %d cells vary across runs (%.1f%%)"
          % (unstable, total, unstable / total * 100))
    if unstable > 12:
        print("(only the first 12 shown)")


def main():
    runs_n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    out_path = sys.argv[2] if len(sys.argv) > 2 else "data/nominal.csv"

    if not os.path.exists("firmware.elf"):
        sys.exit("firmware.elf not found, run make first")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    runs = []
    for i in range(runs_n):
        rows = parse(one_run())
        runs.append(rows)
        print("run %2d: %d windows" % (i + 1, len(rows)))

    with open(out_path, "w") as fh:
        fh.write("run,window,cmd,%s\n" % ",".join(FEATURES))
        for i, rows in enumerate(runs):
            for w, row in enumerate(rows):
                fh.write("%d,%d,%s\n"
                         % (i, w, ",".join(str(v) for v in row)))

    total = sum(len(r) for r in runs)
    print()
    print("wrote %d samples to %s" % (total, out_path))

    summarise(runs)


if __name__ == "__main__":
    main()
