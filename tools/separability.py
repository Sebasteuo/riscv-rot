#!/usr/bin/env python3
"""
Separability analysis for the attestation windows.

Takes a firmware run, splits the windows into nominal and adversarial,
and reports which ratios between counters separate the two classes.

Ratios matter more than raw counts. A program doing twice the work has
twice every counter, so absolute values carry the size of the workload
as much as its shape. Ratios cancel that out.

Usage:
    python3 tools/separability.py [run.log]
"""

import re
import sys

FEATURES = ["load", "store", "branch", "jump", "trap", "priv"]

WINDOW = re.compile(r"Window closed: ([\d,]+)")
LABEL = re.compile(r"^\[(?:APP|ATK)\] ([a-z][a-z0-9_-]*)\s*$")


def parse(path):
    """Pair each window with the label printed just before it."""
    rows = []
    label = None
    section = "nominal"

    for line in open(path, errors="replace"):
        if "=== adversarial" in line:
            section = "adversarial"
        m = LABEL.match(line.rstrip())
        if m:
            label = m.group(1)
            continue
        m = WINDOW.search(line)
        if m and label:
            vals = [int(v) for v in m.group(1).split(",")]
            if len(vals) == len(FEATURES):
                kind = section
                # the baseline scenario is nominal even inside the
                # adversarial section: same code, input that fits
                if label == "none":
                    kind = "nominal"
                rows.append((label, kind, vals))
    return rows


def ratios(vals):
    """Counter ratios against loads, the busiest counter."""
    load = vals[0] or 1
    return {
        "store/load":  vals[1] / load,
        "branch/load": vals[2] / load,
        "jump/load":   vals[3] / load,
        "jump/branch": vals[3] / (vals[2] or 1),
    }


def report(rows):
    nom = [r for r in rows if r[1] == "nominal"]
    adv = [r for r in rows if r[1] == "adversarial"]

    print("windows: %d nominal, %d adversarial" % (len(nom), len(adv)))
    if not adv:
        print("no adversarial windows found, nothing to compare")
        return

    print()
    print("%-14s %11s %11s %11s %11s"
          % ("WORKLOAD", "store/load", "branch/load", "jump/load",
             "jump/branch"))
    print("-" * 64)

    for label, kind, vals in rows:
        r = ratios(vals)
        mark = "  <- attack" if kind == "adversarial" else ""
        print("%-14s %11.4f %11.4f %11.4f %11.4f%s"
              % (label[:14], r["store/load"], r["branch/load"],
                 r["jump/load"], r["jump/branch"], mark))

    print()
    print("SEPARATION BY RATIO")
    print("-" * 64)

    for name in ("store/load", "branch/load", "jump/load", "jump/branch"):
        n = [ratios(v)[name] for _, k, v in rows if k == "nominal"]
        a = [ratios(v)[name] for _, k, v in rows if k == "adversarial"]

        n_lo, n_hi = min(n), max(n)
        a_lo, a_hi = min(a), max(a)

        # a clean split means the two ranges do not touch
        if a_hi < n_lo:
            verdict = "SEPARABLE, gap %.4f" % (n_lo - a_hi)
        elif a_lo > n_hi:
            verdict = "SEPARABLE, gap %.4f" % (a_lo - n_hi)
        else:
            verdict = "overlaps"

        print("%-12s nominal [%.4f, %.4f]  attack [%.4f, %.4f]"
              % (name, n_lo, n_hi, a_lo, a_hi))
        print("%-12s %s" % ("", verdict))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/data.log"
    rows = parse(path)
    if not rows:
        sys.exit("no windows parsed from %s" % path)
    report(rows)


if __name__ == "__main__":
    main()
