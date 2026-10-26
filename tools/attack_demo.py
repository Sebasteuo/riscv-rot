#!/usr/bin/env python3
"""
Demonstrate that the two-stage secure boot rejects a tampered image.

Runs three scenarios against the same Stage-1 binary:

  1. Intact image, expected to boot
  2. One payload byte flipped, expected to be rejected
  3. Both the payload and the stored reference modified, which is the
     attack that defeats the golden hash scheme this replaces

The third case is the point of the whole objective: with golden hashes
an attacker who can rewrite the firmware can usually rewrite the
reference value too, and the comparison then succeeds. With a
signature there is nothing on the device to rewrite that would help,
because producing a valid signature requires the private key.

Usage:
    python3 tools/attack_demo.py
"""

import os
import shutil
import subprocess
import sys

QEMU = os.path.expanduser("~/qemu-ccore/build/qemu-system-riscv64")
IMAGE = "stage2.img"
WORK = "/tmp/attack_demo.img"
TIMEOUT_S = 25

HEADER_SIZE = 80


def boot(image_path):
    """Boot Stage-1 with the given image, return its output."""
    cmd = [
        QEMU, "-machine", "virt", "-cpu", "rv64", "-m", "128M",
        "-nographic", "-bios", "stage1.elf",
        "-device", "loader,file=%s,addr=0x84000000" % image_path,
        "-smp", "1",
    ]
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=TIMEOUT_S).stdout
    except subprocess.TimeoutExpired as exc:
        # The firmware ends in a wfi loop, so a timeout means it booted
        return exc.stdout.decode() if exc.stdout else ""


def verdict(output):
    if "HALT" in output:
        reason = ""
        for line in output.splitlines():
            if "HALT" in line:
                reason = line.split("HALT:")[-1].strip()
        return False, reason
    if "Transferring control" in output:
        return True, "booted"
    return False, "no output"


def scenario(name, prepare, should_boot):
    shutil.copy(IMAGE, WORK)
    detail = prepare(WORK)

    booted, reason = verdict(boot(WORK))
    ok = (booted == should_boot)

    print("%-42s %-22s %s" % (
        name,
        "booted" if booted else "rejected: " + reason,
        "PASS" if ok else "FAIL"))
    if detail:
        print("%-42s %s" % ("", detail))
    return ok


def untouched(path):
    return "image as produced by the build"


def flip_payload_byte(path):
    with open(path, "r+b") as fh:
        fh.seek(HEADER_SIZE + 4096)
        b = fh.read(1)
        fh.seek(HEADER_SIZE + 4096)
        fh.write(bytes([b[0] ^ 0x01]))
    return "one bit flipped at payload offset 4096"


def rewrite_payload_and_reference(path):
    """
    The golden hash attack, translated to this format.

    An attacker who can modify the firmware can also modify anything
    stored alongside it, so here both the payload and the signature
    field are rewritten. Under a golden hash scheme the equivalent
    edit makes the comparison succeed.
    """
    with open(path, "r+b") as fh:
        fh.seek(HEADER_SIZE + 4096)
        b = fh.read(1)
        fh.seek(HEADER_SIZE + 4096)
        fh.write(bytes([b[0] ^ 0xFF]))
        # overwrite the signature with an attacker-chosen value
        fh.seek(16)
        fh.write(bytes(64))
    return "payload modified and signature field overwritten"


def main():
    if not os.path.exists(IMAGE) or not os.path.exists("stage1.elf"):
        sys.exit("run 'make secureboot' first")

    print()
    print("%-42s %-22s %s" % ("SCENARIO", "RESULT", "EXPECTED?"))
    print("-" * 78)

    results = [
        scenario("1. Intact image", untouched, True),
        scenario("2. One payload byte flipped",
                 flip_payload_byte, False),
        scenario("3. Payload and reference both rewritten",
                 rewrite_payload_and_reference, False),
    ]

    print("-" * 78)
    print("%d of %d scenarios behaved as expected" %
          (sum(results), len(results)))

    if os.path.exists(WORK):
        os.remove(WORK)

    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
