#!/usr/bin/env python3
"""
Window report verifier.

The runtime attestation service returns a 96 byte report every time it
closes a measurement window:

  bytes  0 to 15   the nonce the window was opened with
  bytes 16 to 63   six counter deltas, big-endian, 8 bytes each
  bytes 64 to 95   HMAC-SHA256 over bytes 0 to 63, keyed with the
                   Endorsement Key

This script derives the same key from the endorsement seed, recomputes the
code over the first 64 bytes and compares it with the one the device sent.
It reads the reports from a run log, where the client prints each one on a
line that starts with [REP].

The key derivation is imported from verify_quote.py so both tools cannot
drift apart.

Usage:
  python3 verify_report.py /tmp/service.log
  python3 verify_report.py --demo

Exit code is 0 when every report verifies and 1 when any of them fails, so
the script can be used from shell scripts and from the Makefile.
"""

import hashlib
import hmac
import sys

from verify_quote import ENDORSEMENT_SEED, derive_ek

REPORT_SIZE = 96
NONCE_SIZE = 16
FEATURES = 6
SIGNED_SIZE = NONCE_SIZE + FEATURES * 8
PREFIX = "[REP] "

FEATURE_NAMES = ["loads", "stores", "taken branches", "indirect jumps",
                 "traps", "mode changes"]


def report_code(ek, report):
    """The code the device should have produced for this report."""
    return hmac.new(ek, report[:SIGNED_SIZE], hashlib.sha256).digest()


def deltas(report):
    """The six counter deltas the report carries."""
    out = []
    for i in range(FEATURES):
        start = NONCE_SIZE + i * 8
        out.append(int.from_bytes(report[start:start + 8], "big"))
    return out


def read_reports(path):
    """Every [REP] line of a run log, as raw bytes."""
    found = []
    with open(path, "r", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.startswith(PREFIX):
                continue
            text = line[len(PREFIX):].strip()
            if len(text) != REPORT_SIZE * 2:
                print("line %d: expected %d hex characters, got %d"
                      % (number, REPORT_SIZE * 2, len(text)))
                continue
            found.append((number, bytes.fromhex(text)))
    return found


def check(reports, ek):
    """Verify every report. Returns how many failed."""
    bad = 0
    for number, report in reports:
        expected = report_code(ek, report)
        if hmac.compare_digest(expected, report[SIGNED_SIZE:]):
            continue
        bad += 1
        print("line %d: the authentication code does not match" % number)
    return bad


def demo(ek):
    """Check that a genuine report passes and a tampered one is refused."""
    report = bytearray(b"\x00" * REPORT_SIZE)
    for i in range(NONCE_SIZE):
        report[i] = (7 * 31 + i) & 0xFF
    for i, value in enumerate([281, 117, 49, 7, 1, 2]):
        start = NONCE_SIZE + i * 8
        report[start:start + 8] = value.to_bytes(8, "big")
    report[SIGNED_SIZE:] = report_code(ek, bytes(report))

    if not hmac.compare_digest(report_code(ek, bytes(report)),
                               bytes(report[SIGNED_SIZE:])):
        print("the genuine report failed, so the derivation is wrong")
        return 1

    tampered = bytearray(report)
    tampered[NONCE_SIZE] ^= 0x01
    if hmac.compare_digest(report_code(ek, bytes(tampered)),
                           bytes(tampered[SIGNED_SIZE:])):
        print("the tampered report passed, so the check is not working")
        return 1

    print("demo passed, the genuine report verifies and the tampered one "
          "does not")
    return 0


def main():
    ek = derive_ek(ENDORSEMENT_SEED)

    if len(sys.argv) == 2 and sys.argv[1] == "--demo":
        return demo(ek)

    if len(sys.argv) != 2:
        print(__doc__)
        return 1

    reports = read_reports(sys.argv[1])
    if not reports:
        print("no report found in %s" % sys.argv[1])
        return 1

    bad = check(reports, ek)
    print("%d reports read, %d verified, %d failed"
          % (len(reports), len(reports) - bad, bad))

    first = reports[0][1]
    print("first report, nonce %s" % first[:NONCE_SIZE].hex())
    for name, value in zip(FEATURE_NAMES, deltas(first)):
        print("  %-16s %d" % (name, value))

    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
