#!/usr/bin/env python3
"""
How much of the allowed band each held-out window uses.

Zero rejections only means something if the windows are not sitting far
inside their limits, so this reports the share of the band the worst
held-out window reached.
"""

import sys

from holdout_profiles import FLOOR, SCALE, fit, parse, ratios


def shares(profile, r):
    tol = max(t for _, t in profile)
    out = []
    for i in range(3):
        mean = profile[i][0]
        allowed = max(mean * tol // SCALE, FLOOR)
        out.append(abs(r[i] - mean) / allowed if allowed else 0.0)
    return out


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/run.log"
    by_app = {}
    for name, gsf, v in parse(path):
        by_app.setdefault(name, {})[gsf] = ratios(v)

    apps = sorted(a for a, d in by_app.items() if len(d) == 3)
    every = []

    print("%-16s %8s %8s %8s" % ("APPLICATION", "hold g1", "hold g2", "hold g3"))
    print("-" * 44)
    for app in apps:
        d = by_app[app]
        row = []
        for held in (1, 2, 3):
            p = fit([d[g] for g in (1, 2, 3) if g != held])
            s = max(shares(p, d[held]))
            every.append((s, app, held))
            row.append(s)
        print("%-16s %7.0f%% %7.0f%% %7.0f%%" % (app, row[0] * 100, row[1] * 100, row[2] * 100))
    print("-" * 44)

    every.sort(reverse=True)
    worst = every[0]
    mid = every[len(every) // 2]
    print("worst: %s holding out g%d, at %.0f percent of its band"
          % (worst[1], worst[2], worst[0] * 100))
    print("median: %.0f percent of the band" % (mid[0] * 100))


main()
