#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Leave one intensity out.

Fits the profiles with 2 of the 3 work intensities and judges the third
against them, so every window counted here took no part in its own fit.
The three global values are left as they are, because they were not
fitted from this data either.

Usage:
    python3 tools/holdout_profiles.py data/run.log
"""

import re
import sys

SCALE = 10000
FLOOR = int(sys.argv[2]) if len(sys.argv) > 2 else 25

LABEL = re.compile(r"^\[APP\] ([a-z][a-z0-9_-]*) g(\d+)")
WINDOW = re.compile(r"Window closed: ([\d,]+)")


def parse(path):
    """One window per application and intensity."""
    rows = []
    name = None
    gsf = 0
    for line in open(path, errors="replace"):
        m = LABEL.match(line)
        if m:
            name, gsf = m.group(1), int(m.group(2))
            continue
        m = WINDOW.search(line)
        if m and name:
            v = [int(x) for x in m.group(1).split(",")]
            if len(v) == 6:
                rows.append((name, gsf, v))
            name = None
    return rows


def ratios(v):
    load = v[0] or 1
    return (v[1] * SCALE // load, v[2] * SCALE // load, v[3] * SCALE // load)


def fit(samples, min_tol=0.10, headroom=2.0):
    """The same mean and tolerance the fitting tool produces."""
    out = []
    for i in range(3):
        vals = [s[i] for s in samples]
        mean = sum(vals) // len(vals)
        spread = max(vals) - min(vals)
        rel = (spread * headroom / mean) if mean else 0
        tol = min(max(rel, min_tol), 0.35)
        out.append((mean, int(tol * SCALE)))
    return out


def verdict(profile, r):
    """One tolerance per application, the way the firmware carries it."""
    tol = max(t for _, t in profile)
    for i in range(3):
        mean = profile[i][0]
        allowed = max(mean * tol // SCALE, FLOOR)
        if abs(r[i] - mean) > allowed:
            return i
    return -1


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/run.log"
    by_app = {}
    for name, gsf, v in parse(path):
        by_app.setdefault(name, {})[gsf] = ratios(v)

    apps = sorted(a for a, d in by_app.items() if len(d) == 3)
    names = ("store", "branch", "jump")
    total = 0
    rejected = 0

    print("%d applications measured at 3 intensities" % len(apps))
    print()
    print("%-16s %9s %9s %9s" % ("APPLICATION", "hold g1", "hold g2", "hold g3"))
    print("-" * 48)

    for app in apps:
        d = by_app[app]
        row = []
        for held in (1, 2, 3):
            p = fit([d[g] for g in (1, 2, 3) if g != held])
            w = verdict(p, d[held])
            total += 1
            if w >= 0:
                rejected += 1
            row.append(names[w] if w >= 0 else "ok")
        print("%-16s %9s %9s %9s" % (app, row[0], row[1], row[2]))

    print("-" * 48)
    print("%d of %d held-out nominal windows were rejected" % (rejected, total))
    if total:
        print("out-of-sample false positive rate: %.1f percent"
              % (100.0 * rejected / total))


if __name__ == "__main__":
    main()
