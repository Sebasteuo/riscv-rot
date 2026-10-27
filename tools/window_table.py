#!/usr/bin/env python3
"""
LaTeX rows for the window table of the observed application.

Takes the seven windows of the attestation run, turns them into the three
ratios the classifier uses, and marks the first ratio that falls outside
its band. The profile is row 0 of src/profile.c.

Usage:
    python3 tools/window_table.py data/run.log
"""

import re
import sys

SCALE = 10000
FLOOR = 25
CENTRE = (4163, 1743, 249)
TOL = 1000

NAME = {
    "none": "Línea base",
    "small": "Reducción del trabajo",
    "redirect": "Redirección del flujo",
    "long": "Ejecución prolongada",
    "reuse": "Reutilización de código",
    "volume": "Diagnóstico de volumen",
    "small-helper": "Diagnóstico de saltos",
}
ORDER = ["none", "small", "redirect", "long", "reuse", "volume", "small-helper"]
RATIO = ("escrituras", "saltos cond.", "saltos ind.")

LABEL = re.compile(r"^\[ATK\] ([a-z][a-z0-9-]*)\s*$")
WINDOW = re.compile(r"Window closed: ([\d,]+)")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data/run.log"
    seen = {}
    name = None
    for line in open(path, errors="replace"):
        m = LABEL.match(line.rstrip())
        if m:
            name = m.group(1)
            continue
        m = WINDOW.search(line)
        if m and name and name not in seen:
            v = [int(x) for x in m.group(1).split(",")]
            load = v[0] or 1
            seen[name] = (v[1] * SCALE // load, v[2] * SCALE // load, v[3] * SCALE // load)
            name = None

    band = [max(CENTRE[i] * TOL // SCALE, FLOOR) for i in range(3)]
    print("    Centro del perfil & %d & %d & %d & --- \\\\" % CENTRE)
    print("    Banda aceptada & $\\pm$%d & $\\pm$%d & $\\pm$%d & --- \\\\" % tuple(band))
    print("    \\midrule")
    for key in ORDER:
        if key not in seen:
            print("    %% falta %s" % key)
            continue
        r = seen[key]
        out = "nominal"
        for i in range(3):
            if abs(r[i] - CENTRE[i]) > band[i]:
                out = RATIO[i]
                break
        print("    %s & %d & %d & %d & %s \\\\" % (NAME[key], r[0], r[1], r[2], out))


main()
