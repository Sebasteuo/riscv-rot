#!/usr/bin/env python3
"""
Sensitivity curve for the profile classifier.

The measured attack is detected, but that alone does not say how small
a deviation the classifier can see. It might be catching the overflow
because the classifier is sensitive, or because the overflow is loud.
This tells them apart.

For each application the script perturbs one ratio at a time in
increasing steps and asks where the verdict flips. The answer is a
detection threshold per application and per metric, expressed as the
percentage deviation from nominal at which the classifier reacts.

No attack is needed. The perturbation is synthetic and controlled,
which is the point: it covers deviations no real attack in the corpus
happens to produce.

Usage:
    python3 tools/sensitivity.py
"""

SCALE = 10000
FLOOR = 25          # absolute floor, parts per SCALE, matches within()

# Profiles as compiled into src/profile.c
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


def within(expected, seen, tol):
    """Mirror of within() in src/profile.c, including the floor."""
    diff = abs(seen - expected)
    allowed = (expected * tol) // SCALE
    if allowed < FLOOR:
        allowed = FLOOR
    return diff <= allowed


def threshold(expected, tol):
    """
    Smallest deviation, as a percentage of the expected value, that the
    classifier flags. Returns None when the ratio is too small for a
    percentage to mean anything.
    """
    if expected == 0:
        return None
    for pct in range(1, 501):
        seen = expected + (expected * pct) // 100
        if not within(expected, seen, tol):
            return pct
    return None


def main():
    print("Detection thresholds, as percent deviation from nominal")
    print()
    print("%-14s %12s %12s %12s" % ("APPLICATION", *METRICS))
    print("-" * 54)

    for name, st, br, jp, tol in PROFILES:
        cells = []
        for expected in (st, br, jp):
            t = threshold(expected, tol)
            if t is None:
                cells.append("  n/a")
            else:
                cells.append("%4d%%" % t)
        print("%-14s %12s %12s %12s" % (name, *cells))

    print()
    print("Where n/a appears the expected ratio is zero or so small that")
    print("the absolute floor governs instead of the relative band. Those")
    print("cases are covered by the floor of %d parts per %d." % (FLOOR, SCALE))
    print()

    # the measured attack, for comparison
    print("MEASURED ATTACK, against the vulnerable routine")
    print("-" * 54)
    nominal = (3849, 1549, 234)
    attack = (4457, 2151, 26)
    for i, m in enumerate(METRICS):
        dev = abs(attack[i] - nominal[i]) * 100 // nominal[i]
        t = threshold(nominal[i], 1000)
        mark = "detected" if t and dev >= t else "below threshold"
        print("%-14s nominal %5d  attack %5d  deviation %3d%%  %s"
              % (m, nominal[i], attack[i], dev, mark))


if __name__ == "__main__":
    main()
