#!/usr/bin/env python3
"""
Reproduce the covariance analysis over the measured windows.

Reads the same file fit_profiles.py reads and recomputes everything from
scratch, taking no figure from any earlier analysis:

  1. the pooled within-application covariance, with its correct degrees
     of freedom
  2. its eigenvalues and condition number
  3. the diagonal of the precision matrix, which is the squared distance
     a one unit step along each axis produces
  4. the largest Mahalanobis distance among the nominal windows, which
     is the only empirical threshold the data supports
  5. the distance of every adversarial window against the base profile
  6. the window size at which a single event stops exceeding that
     threshold, which is the resolution limit of the representation
  7. the correlation of the raw counts, to check whether the correlation
     between ratios comes from the denominator they share

No external packages. A 3 by 3 matrix is small enough to invert and
diagonalise by hand, and keeping the tool dependency free means the
result can be reproduced anywhere.

Usage:
    python3 tools/covariance.py run.log
"""

import math
import re
import sys

SCALE = 10000

WINDOW = re.compile(r"Window closed: ([\d,]+)")
LABEL = re.compile(r"^\[(?:APP|ATK)\] ([a-z][a-z0-9_-]*)")

RATIO_NAME = ("store/load", "branch/load", "jump/load")
COUNT_NAME = ("load", "store", "branch", "jump")


def parse(path):
    """Collect (name, kind, counters) for every window, exactly the way
    fit_profiles.py does, so both tools see the same data."""
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
    """Counters as parts per SCALE of loads, with the integer division
    the firmware uses. The quantisation is part of what is being
    measured, so it is kept."""
    load = v[0] or 1
    return [v[1] * SCALE // load,
            v[2] * SCALE // load,
            v[3] * SCALE // load]


def mean(xs):
    return sum(xs) / len(xs)


def inverse3(m):
    """Inverse of a 3 by 3 matrix by cofactors. Returns the inverse and
    the determinant, or None if the matrix cannot be inverted."""
    a, b, c = m[0]
    d, e, f = m[1]
    g, h, i = m[2]

    det = a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)
    if abs(det) < 1e-18:
        return None, det

    inv = [[(e * i - f * h) / det, (c * h - b * i) / det, (b * f - c * e) / det],
           [(f * g - d * i) / det, (a * i - c * g) / det, (c * d - a * f) / det],
           [(d * h - e * g) / det, (b * g - a * h) / det, (a * e - b * d) / det]]
    return inv, det


def eigenvalues_sym3(m):
    """Eigenvalues of a symmetric 3 by 3 matrix, by the closed form
    trigonometric solution of its characteristic cubic."""
    p1 = m[0][1] ** 2 + m[0][2] ** 2 + m[1][2] ** 2
    q = (m[0][0] + m[1][1] + m[2][2]) / 3.0

    if p1 == 0:
        return sorted([m[0][0], m[1][1], m[2][2]], reverse=True)

    p2 = ((m[0][0] - q) ** 2 + (m[1][1] - q) ** 2 + (m[2][2] - q) ** 2
          + 2 * p1)
    p = math.sqrt(p2 / 6.0)

    b = [[(m[i][j] - (q if i == j else 0)) / p for j in range(3)]
         for i in range(3)]
    _, det_b = inverse3(b)
    r = max(-1.0, min(1.0, det_b / 2.0))
    phi = math.acos(r) / 3.0

    e1 = q + 2 * p * math.cos(phi)
    e3 = q + 2 * p * math.cos(phi + 2 * math.pi / 3)
    e2 = 3 * q - e1 - e3
    return sorted([e1, e2, e3], reverse=True)


def quadratic(inv, d):
    """The form d transpose times inv times d, which is the squared
    Mahalanobis distance."""
    total = 0.0
    for i in range(3):
        for j in range(3):
            total += d[i] * inv[i][j] * d[j]
    return total


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "run.log"
    rows = parse(path)

    apps = {}
    adversarial = []
    for name, kind, v in rows:
        if kind == "nominal":
            apps.setdefault(name, []).append(v)
        else:
            adversarial.append((name, v))

    total = sum(len(v) for v in apps.values())

    print("=" * 64)
    print("%d nominal windows across %d applications, %d adversarial"
          % (total, len(apps), len(adversarial)))
    print("=" * 64)

    print()
    print("MEANS AND WINDOW COUNT PER APPLICATION")
    print("-" * 64)

    residuals = []
    means = {}
    for name in sorted(apps):
        rs = [ratios(v) for v in apps[name]]
        mu = [mean([r[i] for r in rs]) for i in range(3)]
        means[name] = mu
        for r in rs:
            residuals.append([r[i] - mu[i] for i in range(3)])
        print("%-15s n=%d  mean = %9.1f %9.1f %9.1f"
              % (name, len(rs), mu[0], mu[1], mu[2]))

    dof = total - len(apps)
    print()
    print("degrees of freedom, %d windows less %d groups = %d"
          % (total, len(apps), dof))

    cov = [[0.0] * 3 for _ in range(3)]
    for d in residuals:
        for i in range(3):
            for j in range(3):
                cov[i][j] += d[i] * d[j]
    for i in range(3):
        for j in range(3):
            cov[i][j] /= dof

    print()
    print("POOLED WITHIN-APPLICATION COVARIANCE")
    print("-" * 64)
    for i in range(3):
        print("   %15.4f %15.4f %15.4f" % tuple(cov[i]))
    print()
    print("standard deviations  %.3f  %.3f  %.3f"
          % tuple(cov[i][i] ** 0.5 for i in range(3)))

    print()
    print("CORRELATION BETWEEN RATIOS")
    print("-" * 64)
    for i in range(3):
        for j in range(i + 1, 3):
            den = (cov[i][i] * cov[j][j]) ** 0.5
            c = cov[i][j] / den if den else float("nan")
            print("  %-22s with %-22s %+.4f"
                  % (RATIO_NAME[i], RATIO_NAME[j], c))

    ev = eigenvalues_sym3(cov)
    print()
    print("EIGENVALUES AND CONDITION")
    print("-" * 64)
    print("  eigenvalues  %.6g  %.6g  %.6g" % tuple(ev))
    if ev[2] > 0:
        print("  condition number  %.1f" % (ev[0] / ev[2]))
    else:
        print("  condition number  infinite, the matrix is singular")

    inv, det = inverse3(cov)
    if inv is None:
        print("  determinant %.3g, the matrix cannot be inverted" % det)
        return
    print("  determinant  %.6g" % det)

    print()
    print("DIAGONAL OF THE PRECISION MATRIX")
    print("-" * 64)
    print("  Each entry is the squared distance a step of 1 part per")
    print("  %d along that axis produces, with the others held fixed."
          % SCALE)
    print()
    for i in range(3):
        print("  precision[%d][%d] = %11.4f   %s"
              % (i, i, inv[i][i], RATIO_NAME[i]))

    print()
    print("DISTANCE OF THE NOMINAL WINDOWS")
    print("-" * 64)
    worst = (0.0, None)
    for name in sorted(apps):
        mu = means[name]
        for v in apps[name]:
            r = ratios(v)
            d2 = quadratic(inv, [r[i] - mu[i] for i in range(3)])
            if d2 > worst[0]:
                worst = (d2, name)
    threshold = worst[0]
    print("  largest nominal distance  %.4f   in %s" % (threshold, worst[1]))
    print()
    print("  This is the only threshold the data supports. A chi squared")
    print("  threshold would assume gaussian noise, and the variation")
    print("  within an application here is driven by the input size.")

    base = means.get("none")
    if base is not None:
        print()
        print("DISTANCE OF THE ADVERSARIAL WINDOWS FROM THE BASE PROFILE")
        print("-" * 64)
        for name, v in adversarial:
            r = ratios(v)
            d2 = quadratic(inv, [r[i] - base[i] for i in range(3)])
            print("  %-14s L=%-9d distance %15.1f   %s"
                  % (name, v[0], d2, "out" if d2 > threshold else "in"))

    print()
    print("RESOLUTION OF THE WINDOW")
    print("-" * 64)
    print("  One event in a window of L loads moves its ratio by")
    print("  %d/L parts per %d, so the distance it produces is" % (SCALE, SCALE))
    print("  precision[i][i] times (%d/L) squared. Solving against the" % SCALE)
    print("  nominal threshold of %.4f gives the smallest window in" % threshold)
    print("  which a single event still passes:")
    print()
    for i in range(3):
        if inv[i][i] <= 0:
            continue
        l_min = SCALE / (threshold / inv[i][i]) ** 0.5
        print("  %-22s L >= %11.0f loads" % (RATIO_NAME[i], l_min))

    if base is not None:
        print()
        print("  What one branch event costs in each measured window:")
        print()
        windows = list(adversarial)
        if "none" in apps:
            windows.append(("none", apps["none"][0]))
        for name, v in sorted(windows, key=lambda t: t[1][0]):
            load = v[0]
            d2_one = inv[1][1] * (float(SCALE) / load) ** 2
            print("    %-14s L=%-9d distance %13.1f   %.0f times the threshold"
                  % (name, load, d2_one,
                     d2_one / threshold if threshold else 0))

    print()
    print("CORRELATION OF THE RAW COUNTS, WITHIN APPLICATION")
    print("-" * 64)
    print("  Two ratios that share a denominator correlate even when")
    print("  their numerators do not, so the raw counts are the control.")
    print("  If every raw pair also correlates, the variation within an")
    print("  application is driven by a common factor and neither figure")
    print("  describes noise.")
    print()

    raw_residuals = []
    for name in sorted(apps):
        vs = apps[name]
        if len(vs) < 2:
            continue
        mu = [mean([v[k] for v in vs]) for k in range(4)]
        for v in vs:
            raw_residuals.append([v[k] - mu[k] for k in range(4)])

    if len(raw_residuals) > 1:
        def correlation(a, b):
            sa = sum(r[a] * r[a] for r in raw_residuals)
            sb = sum(r[b] * r[b] for r in raw_residuals)
            sab = sum(r[a] * r[b] for r in raw_residuals)
            den = (sa * sb) ** 0.5
            return sab / den if den else float("nan")

        for a in range(4):
            for b in range(a + 1, 4):
                print("  %-14s with %-14s %+.4f"
                      % (COUNT_NAME[a], COUNT_NAME[b], correlation(a, b)))
    print()


if __name__ == "__main__":
    main()
