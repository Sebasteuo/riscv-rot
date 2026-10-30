#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Fit per-application profiles from measured windows.

Groups the windows of a run by application and derives the profile
each one carries: the mean of every ratio and a tolerance taken from
the observed spread rather than picked by hand.

One-class by construction. Only nominal windows are used to fit; the
adversarial ones are held back and checked afterwards, so detection is
measured against data the model never saw.

Usage:
    python3 tools/fit_profiles.py run.log
"""

import re
import sys

SCALE = 10000

WINDOW = re.compile(r"Window closed: ([\d,]+)")
LABEL = re.compile(r"^\[(?:APP|ATK)\] ([a-z][a-z0-9_-]*)")


def parse(path):
    """Collect (name, kind, counters) for every window in the run."""
    rows = []
    name = None
    section = "nominal"

    for line in open(path, errors="replace"):
        if "=== adversarial" in line:
            section = "adversarial"
        m = LABEL.match(line)
        if m:
            name = m.group(1)
            continue
        m = WINDOW.search(line)
        if m and name:
            v = [int(x) for x in m.group(1).split(",")]
            if len(v) == 6:
                kind = "nominal" if name == "none" else section
                rows.append((name, kind, v))
    return rows


def ratios(v):
    """Counters as parts per SCALE of loads."""
    load = v[0] or 1
    return (v[1] * SCALE // load,
            v[2] * SCALE // load,
            v[3] * SCALE // load)


def fit(samples, min_tol=0.10, headroom=2.0):
    """
    Mean and tolerance for one application.

    The tolerance comes from the observed spread, widened by a headroom
    factor so intensities that were not measured still fit. A minimum
    keeps it from collapsing to zero when every sample landed on the
    same value, which happens often here: the platform is deterministic
    enough that repeated runs are identical.
    """
    out = []
    for i in range(3):
        vals = [s[i] for s in samples]
        mean = sum(vals) // len(vals)
        spread = max(vals) - min(vals)
        rel = (spread * headroom / mean) if mean else 0

        # Cap the band. A tolerance of several hundred percent stops
        # being a tolerance: it accepts anything. Ratios that swing
        # that much across intensities are better handled by the
        # absolute floor in the firmware than by a relative band.
        tol = min(max(rel, min_tol), 0.35)
        out.append((mean, int(tol * SCALE)))
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/fit.log"
    rows = parse(path)
    if not rows:
        sys.exit("no windows parsed")

    apps = {}
    attacks = []
    for name, kind, v in rows:
        if kind == "nominal":
            apps.setdefault(name, []).append(ratios(v))
        else:
            attacks.append((name, ratios(v)))

    print("fitted on %d nominal windows across %d applications"
          % (sum(len(v) for v in apps.values()), len(apps)))
    print("held back %d adversarial windows" % len(attacks))
    print()

    print("%-16s %7s %7s %7s   %s"
          % ("APPLICATION", "store", "branch", "jump", "tolerance"))
    print("-" * 62)

    order = sorted(apps)
    table = {}
    for name in order:
        f = fit(apps[name])
        table[name] = f
        print("%-16s %7d %7d %7d   %d%%, %d%%, %d%%"
              % (name, f[0][0], f[1][0], f[2][0],
                 f[0][1] * 100 // SCALE,
                 f[1][1] * 100 // SCALE,
                 f[2][1] * 100 // SCALE))

    print()
    print("HELD-BACK CHECK")
    print("-" * 62)
    base = table.get("none")
    for name, r in attacks:
        if not base:
            break
        flags = []
        for i, label in enumerate(("store", "branch", "jump")):
            mean, tol = base[i]
            allowed = max(mean * tol // SCALE, 25)
            if abs(r[i] - mean) > allowed:
                flags.append("%s off by %d" % (label, abs(r[i] - mean)))
        print("%-16s %s" % (name, ", ".join(flags) if flags else "NOT DETECTED"))

    print()
    print("C TABLE for src/profile.c")
    print("-" * 62)
    for name in order:
        f = table[name]
        tol = max(t for _, t in f)
        print("    /* %-14s */ { %5d, %5d, %5d, %4d },"
              % (name, f[0][0], f[1][0], f[2][0], tol))


if __name__ == "__main__":
    main()
