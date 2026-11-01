#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Pin the verdicts and the sealing outcome of a sweep.

The sweep closes 40 windows, 7 in the observed application and 33 in the
reference corpus. A classifier regression leaves every other check green,
so each expected decision is pinned here, with the two unseal outcomes
the verdicts are meant to drive.

Usage:
    python3 tools/check_verdicts.py data/run.log
"""

import re
import sys

NAMES = ["none", "redirect", "small", "long", "reuse", "volume",
         "small-helper"]
OBSERVED = ["nominal", "branch ratio off", "jump ratio off",
            "branch ratio off", "jump ratio off", "store ratio off",
            "jump ratio off"]
SEAL = [("after the nominal windows", "secret released"),
        ("after the adversarial windows", "refused")]


def collect(text):
    """One verdict per window, tagged by the label that preceded it."""
    obs = []
    ref = []
    label = None
    kind = None
    for line in text.split("\n"):
        s = line.strip()
        m = re.match(r"\[ATK\] ([a-z][a-z-]*)$", s)
        if m:
            label, kind = m.group(1), "obs"
        m = re.match(r"\[APP\] ([a-z][a-z0-9_-]*) g\d+", s)
        if m:
            label, kind = m.group(1), "ref"
        m = re.search(r"Verdict: (.+)$", s)
        if m and kind:
            (obs if kind == "obs" else ref).append((label, m.group(1).strip()))
            kind = None
    return obs, ref


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/run.log"
    text = open(path, errors="replace").read()
    obs, ref = collect(text)
    got = [v for _, v in obs]
    bad = []

    for i, name in enumerate(NAMES):
        g = got[i] if i < len(got) else "missing"
        if g != OBSERVED[i]:
            bad.append("%s gave %s, expected %s" % (name, g, OBSERVED[i]))
    if len(ref) != 33:
        bad.append("%d reference windows, expected 33" % len(ref))
    for name, v in ref:
        if v != "nominal":
            bad.append("%s gave %s, expected nominal" % (name, v))
    for stage, want in SEAL:
        m = re.search(r"Unseal " + re.escape(stage) + r" rc = \S+ (.+)", text)
        if not m:
            bad.append("no unseal line for %s" % stage)
        elif want not in m.group(1):
            bad.append("unseal %s gave %s" % (stage, m.group(1).strip()))

    print("%d observed windows, %d reference windows" % (len(obs), len(ref)))
    if bad:
        print("=== RESULT: FAIL ===")
        for b in bad:
            print("  " + b)
        sys.exit(1)
    print("  [OK] 7 observed verdicts, 33 nominal reference verdicts,"
          " both unseal outcomes")
    print("=== RESULT: PASS ===")


if __name__ == "__main__":
    main()
