#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Query cost of a verdict oracle against the profile classifier.

When the attestation window closes, the firmware writes the classifier
verdict into the shared region that U mode can read. The code being
watched therefore learns whether it was caught, and can keep adjusting
until it stops being caught.

The report leaks two different things and they matter in different ways.
One is the verdict byte. The other is the six counter deltas, in the
clear, eight bytes each. Neither one alone is worth much. Together they
are, and this script says by how much.

Four cases:

  blind           nothing leaks. The attacker has to land inside all
                  three bands by luck. Reported as the probability per
                  attempt and its reciprocal.
  deltas only     the attacker knows where it landed, but the profile
                  is compiled into src/profile.c and never leaves M
                  mode, so it does not know where it has to land. This
                  is no better than blind.
  verdict only    the attacker knows whether it passed, but not its own
                  coordinates, so it has to guess how far each ratio
                  moved. Costs more than the case below. Not bounded
                  here.
  both            what the firmware leaks today. Binary search in
                  coordinates the attacker can read, so log2 of the
                  range over the band width, summed over the three
                  metrics. This is the "queries" column.

Bands and the absolute floor are the same ones within() uses in
sensitivity.py and profile_check() uses in src/profile.c.

Usage:
    python3 tools/oracle_cost.py
    python3 tools/oracle_cost.py --limit 3
"""

import argparse
import math

SCALE = 10000
FLOOR = 25          # absolute floor, parts per SCALE, matches within()

# Profiles as compiled into src/profile.c
# (name, store/load, branch/load, jump/load, tolerance)
PROFILES = [
    ("vulnerable",   4163, 1743,  249, 1000),
    ("aha-mont64",   4883, 1489,   49, 2857),
    ("crc32",        5006, 1665, 1666, 1000),
    ("depthconv",    3913,  353,  333, 1000),
    ("edn",          2561,  744,    1, 3500),
    ("huffbench",    2983, 1520,    3, 1000),
    ("matmult-int",  1972, 1376,    0, 1000),
    ("md5sum",       3239, 1279,    2, 3500),
    ("nettle-aes",   1617,  228,    3, 3500),
    ("nettle-sha",   2048,  447,   33, 3030),
    ("nsichneu",     2087, 1006,   23, 3500),
    ("picojpeg",     5796, 1106,  587, 1000),
]

METRICS = ("store/load", "branch/load", "jump/load")


def half_width(center, tol):
    """Effective half width of the band, in parts per SCALE.

    Mirrors within(). The band is the larger of the relative tolerance
    and the absolute floor. The floor is what makes the small ratios
    unable to see anything.
    """
    return max(center * tol / SCALE, FLOOR)


def band(center, tol):
    """Accepted interval. A ratio cannot be negative, so the low end
    clamps at zero."""
    h = half_width(center, tol)
    return max(0.0, center - h), center + h


def reachable_ranges():
    """Range each ratio can reach.

    ASSUMPTION, and the document has to state it. The spread of the
    eleven applications stands in for the reachable range. The comment
    in include/profile.h backs this up, it says the eleven Embench
    workloads already span nearly the entire range of every ratio.

    If the measured spread of the 34 nominal windows and the 5
    adversarial scenarios is at hand, replace this and the result gets
    tighter.
    """
    real = [p for p in PROFILES if p[0] != "vulnerable"]
    out = []
    for i in range(3):
        vals = [p[1 + i] for p in real]
        lo, hi = min(vals), max(vals)
        out.append((lo, hi, max(1.0, hi - lo)))
    return out


def cost(center_triple, tol, ranges):
    """Blind probability and query count for one profile.

    The blind probability is the product of the three band widths over
    the three reachable ranges. The query count is the bisection depth
    needed per metric, summed.
    """
    prob = 1.0
    queries = 0.0
    for i, center in enumerate(center_triple):
        lo, hi = band(center, tol)
        # Clip the band to the reachable range. A ratio the attacker
        # cannot produce is not a ratio it can aim at, so counting that
        # part of the band overstates its odds.
        rlo, rhi, width = ranges[i]
        lo, hi = max(lo, rlo), min(hi, rhi)
        frac = min(1.0, max(0.0, hi - lo) / width)
        prob *= frac
        if frac < 1.0:
            queries += math.log2(1.0 / frac)
    attempts = float("inf") if prob == 0.0 else 1.0 / prob
    return prob, attempts, queries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0,
                    help="queries allowed before lockout, 0 for no limit")
    args = ap.parse_args()

    ranges = reachable_ranges()

    print("Reachable range per metric, taken from the spread of the "
          "eleven applications")
    for name, (lo, hi, width) in zip(METRICS, ranges):
        print(f"  {name:13s} {lo:6.0f} to {hi:6.0f}, width {width:6.0f}")
    print()

    print("Accepted bands per metric")
    print("  rule      which one sets the width, the relative tolerance "
          "or the floor")
    print("  zero      the band reaches down to zero, so a window with "
          "none of that")
    print("            event passes this metric")
    print()
    print(f"{'application':14s} {'metric':13s} {'center':>7s} {'band':>18s} "
          f"{'half':>8s} {'rule':>9s} {'zero':>6s}")
    reaches_zero = {m: [] for m in METRICS}
    floor_governs = {m: [] for m in METRICS}
    for name, s, b, j, tol in PROFILES:
        for i, (center, metric) in enumerate(zip((s, b, j), METRICS)):
            h = half_width(center, tol)
            lo, hi = band(center, tol)
            by_floor = center * tol / SCALE < FLOOR
            rule = "floor" if by_floor else "relative"
            if by_floor:
                floor_governs[metric].append(name)
            zero = lo <= 0.0
            if zero:
                reaches_zero[metric].append(name)
            interval = f"[{lo:.0f}, {hi:.0f}]"
            print(f"{name:14s} {metric:13s} {center:7.0f} {interval:>18s} "
                  f"{h:8.1f} {rule:>9s} {'yes' if zero else '':>6s}")
    print()

    for metric in METRICS:
        names = floor_governs[metric]
        if names:
            print(f"Floor sets the width on {metric} in {len(names)} of "
                  f"{len(PROFILES)}: {', '.join(names)}")
    print()
    for metric in METRICS:
        names = reaches_zero[metric]
        if names:
            print(f"Band reaches zero on {metric} in {len(names)} of "
                  f"{len(PROFILES)}: {', '.join(names)}")
    print()
    print("That last one matters for code reuse detection. The signal "
          "measured on")
    print("silicon is the indirect jump count falling from four to three "
          "when the")
    print("return never happens. In the applications whose jump/load band "
          "reaches")
    print("zero, a fall all the way to zero passes just the same, so that "
          "metric")
    print("contributes nothing and the classifier rests on two ratios "
          "instead of")
    print("three.")
    print()

    print("Attack cost per application")
    print("  p(blind)    chance of landing inside all three bands in one "
          "attempt")
    print("  attempts    expected with no leak, or with the deltas but no "
          "verdict")
    print("  queries     with verdict and deltas, which is what leaks today")
    print()
    print(f"{'application':14s} {'p(blind)':>12s} {'attempts':>10s} "
          f"{'queries':>9s}")
    for name, s, b, j, tol in PROFILES:
        prob, attempts, queries = cost((s, b, j), tol, ranges)
        print(f"{name:14s} {prob:12.5f} {attempts:10.1f} {queries:9.1f}")
    print()

    if args.limit > 0:
        print(f"Against a limit of {args.limit} queries")
        print(f"{'application':14s} {'blind':>8s} {'both leaks':>12s}")
        for name, s, b, j, tol in PROFILES:
            _, attempts, queries = cost((s, b, j), tol, ranges)
            print(f"{name:14s} "
                  f"{'through' if attempts <= args.limit else 'no':>8s} "
                  f"{'through' if queries <= args.limit else 'no':>12s}")
        print()

    print("Note for the document. What this computes is a lower bound on "
          "attacker")
    print("effort, or the same thing said backwards, an upper bound on what "
          "the")
    print("defence holds. The attacker cannot move freely through ratio "
          "space,")
    print("because changing a ratio means changing behaviour, and not every "
          "point")
    print("is reachable while the attack still works. The five adversarial")
    print("scenarios measured on silicon are the empirical floor on how far "
          "it can")
    print("move without giving up the attack.")
    print()
    print("And what that means for the fix. Dropping the verdict byte moves "
          "the")
    print("attack from the queries column to the attempts column, from "
          "around ten")
    print("queries to hundreds or thousands of attempts, because the deltas "
          "alone")
    print("do not locate the band. Adding the session token check to "
          "ATTEST_END is")
    print("still worth doing, but as depth, not as the main fix.")


if __name__ == "__main__":
    main()
