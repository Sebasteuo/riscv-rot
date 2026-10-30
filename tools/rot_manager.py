#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Root of Trust Manager - Remote Management Interface

A simplified TPM Software Stack (TSS) for our RISC-V Root of Trust.
This tool runs the firmware in QEMU, captures the output, and
presents it in a clean, interactive format.

It can:
  - Show the boot sequence and Secure Boot result
  - Display all PCR values
  - Display Secure Storage contents
  - Verify Quote signatures (remote attestation)
  - Show Dictionary Attack lockout status
  - Show session and NV counter state
  - Export a full attestation report as JSON

Think of this as the "control panel" for our Root of Trust.
In a real deployment, this would run on a management server
and communicate with the device over a secure channel.

Usage:
  python3 rot_manager.py                  # interactive mode
  python3 rot_manager.py --run            # run QEMU and parse output
  python3 rot_manager.py --parse FILE     # parse saved QEMU output
  python3 rot_manager.py --report FILE    # generate JSON report

By default --run uses the QEMU binary at ~/qemu-ccore/build/. To test
against a different build, set the QEMU environment variable:

  QEMU=/path/to/qemu-system-riscv64 python3 rot_manager.py --run

Based on:
  - TCG TSS 2.0 (TPM Software Stack)
  - TCG TAP (TPM Attestation Protocol)

Author: Sebastian Alba
Project: Root of Trust Firmware for RISC-V with PMP isolation
"""

import re
import sys
import json
import hmac
import hashlib
import struct
import subprocess
import os
from datetime import datetime


# =========================================================================
# Endorsement seed (same as firmware, see keygen.c)
# In production this would be the public part of an asymmetric key.
# =========================================================================
ENDORSEMENT_SEED = bytes([
    0x7A, 0x1B, 0x3C, 0x4D, 0x5E, 0x6F, 0x80, 0x91,
    0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19,
    0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x90, 0xA1,
    0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29
])


def kdf_derive(seed, label):
    """Replicate firmware KDF (NIST SP 800-108 Counter Mode)."""
    buf = struct.pack('>I', 1) + label.encode() + b'\x00'
    buf += b'RoT-RISCV' + struct.pack('>I', 256)
    return hmac.new(seed, buf, hashlib.sha256).digest()


def derive_ek():
    """Derive Endorsement Key from seed."""
    return kdf_derive(ENDORSEMENT_SEED, "ENDORSEMENT")


def verify_quote(ek, pcr0, pcr1, pcr2, signature):
    """Verify a Quote signature. Returns True if authentic."""
    expected = hmac.new(ek, pcr0 + pcr1 + pcr2, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def parse_hex_values(line):
    """
    Extract hex bytes from a firmware dump line.

    The firmware prints each byte with a 0x prefix and WITHOUT zero
    padding (0x6 instead of 0x06). The storage dump separates bytes
    with spaces ('0xff 0xd4 0x58 ...') but the PCR dump concatenates
    them ('0xbd0xe80x8f0x39...'). A plain regex scan breaks on the
    concatenated form: for '0x80x9e' it grabs '80' (stealing the '0'
    that belongs to the next prefix) and corrupts everything after.

    Splitting on the '0x' prefix instead makes the format uniquely
    decodable: each chunk between prefixes starts with the 1 or 2 hex
    digits of exactly one byte.
    """
    out = []
    for chunk in line.split('0x')[1:]:
        m = re.match(r'[0-9a-fA-F]{1,2}', chunk)
        if m:
            out.append(int(m.group(0), 16))
    return bytes(out)


def parse_pcr_line(line):
    """Parse a PCR dump line and return the index and partial hash."""
    match = re.search(r'PCR0x(\d+):\s+(.*)', line)
    if match:
        idx = int(match.group(1))
        hex_vals = parse_hex_values(match.group(2))
        return idx, hex_vals
    return None, None


class RoTManager:
    """
    Parses QEMU output and provides a structured view of the
    Root of Trust state. This is our simplified TSS.
    """

    def __init__(self):
        self.boot_passed = False
        self.pcrs = {0: None, 1: None, 2: None}
        self.storage_slots = {}
        self.ek = None
        self.srk = None
        self.quote_signature = None
        self.nv_counter = None
        self.tests_passed = 0
        self.tests_total = 0
        self.all_passed = False
        self.seal_encrypted = False
        self.firmware_size = {'text': 0, 'rodata': 0}
        self.raw_output = ""

    def parse_output(self, output):
        """Parse complete QEMU output and extract all state."""
        self.raw_output = output
        lines = output.split('\n')

        # The firmware announces the section name and the measured size
        # on two separate lines:
        #   [MAIN] Measuring .text section (code)...
        #   [PCR] Measured 0xa3a4 bytes, hash = 0x2e0x91...
        # so we remember which section was announced last and assign the
        # next 'Measured N bytes' line to it. Later MEASURE service calls
        # also print 'Measured' lines, but with no pending section they
        # are ignored.
        pending_section = None

        for line in lines:
            # Secure Boot
            if 'Secure Boot PASSED' in line:
                self.boot_passed = True

            # Firmware sizes (two-line format, see comment above)
            m = re.search(r'Measuring \.(\w+) section', line)
            if m:
                pending_section = m.group(1)
            m = re.search(r'Measured (0x[0-9a-fA-F]+) bytes', line)
            if m and pending_section:
                if pending_section in self.firmware_size:
                    self.firmware_size[pending_section] = int(m.group(1), 16)
                pending_section = None

            # PCR values (from final dump)
            idx, vals = parse_pcr_line(line)
            if idx is not None:
                self.pcrs[idx] = vals

            # EK: 'derived' on first boot, 'loaded' when restored from
            # the persistent Secure Storage on later boots
            if 'EK derived:' in line or 'EK loaded:' in line:
                self.ek = parse_hex_values(line)

            # SRK: same two variants as the EK
            if 'SRK derived:' in line or 'SRK loaded:' in line:
                self.srk = parse_hex_values(line)

            # Quote signature (from QUOTE output)
            if '[QUOTE] Signature:' in line:
                self.quote_signature = parse_hex_values(line)

            # NV counter
            if '[NVC] Current counter value:' in line:
                m = re.search(r'0x([0-9a-fA-F]+)', line.split(':')[-1])
                if m:
                    self.nv_counter = int(m.group(1), 16)

            # Counter increment
            if 'Counter incremented:' in line:
                m = re.search(r'-> (0x[0-9a-fA-F]+)', line)
                if m:
                    self.nv_counter = int(m.group(1), 16)

            # Sealed storage with AES
            if 'AES-128 encryption' in line:
                self.seal_encrypted = True

            # Storage slots (from final dump)
            m = re.search(r'Slot (0x[0-9a-f]+): (0x[0-9a-f]+) bytes = (.*)', line)
            if m:
                slot = int(m.group(1), 16)
                size = int(m.group(2), 16)
                data = parse_hex_values(m.group(3))
                self.storage_slots[slot] = {'size': size, 'data': data}

            m = re.search(r'Slot (0x[0-9a-f]+): empty', line)
            if m:
                slot = int(m.group(1), 16)
                self.storage_slots[slot] = {'size': 0, 'data': b''}

            # Test results
            if 'ALL TESTS PASSED' in line:
                self.all_passed = True

            m = re.search(r'All (\d+) tests complete', line)
            if m:
                self.tests_total = int(m.group(1))
                self.tests_passed = self.tests_total

        # The storage dump always shows the key prefixes (slot 0 = EK,
        # slot 1 = SRK), so fall back to those if the derivation lines
        # were not present in this capture.
        if self.ek is None and self.storage_slots.get(0, {}).get('data'):
            self.ek = self.storage_slots[0]['data']
        if self.srk is None and self.storage_slots.get(1, {}).get('data'):
            self.srk = self.storage_slots[1]['data']

    def print_dashboard(self):
        """Print a clean dashboard of the RoT state."""
        print()
        print("=" * 64)
        print("  RISC-V Root of Trust - Management Dashboard")
        print("  Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("=" * 64)

        # Secure Boot
        print()
        print("  SECURE BOOT")
        if self.boot_passed:
            print("    Status:  PASSED (firmware is authentic)")
        else:
            print("    Status:  UNKNOWN")
        print(f"    Code size:   {self.firmware_size['text']:,} bytes")
        print(f"    Data size:   {self.firmware_size['rodata']:,} bytes")

        # Keys
        print()
        print("  IDENTITY KEYS")
        if self.ek:
            print(f"    EK:  {self.ek[:8].hex()} ...")
        if self.srk:
            print(f"    SRK: {self.srk[:8].hex()} ...")

        # PCRs
        print()
        print("  PLATFORM CONFIGURATION REGISTERS")
        for idx in sorted(self.pcrs.keys()):
            val = self.pcrs[idx]
            if val:
                label = {0: 'code (.text)', 1: 'data (.rodata)', 2: 'host measurements'}
                print(f"    PCR{idx} [{label.get(idx, '')}]:")
                print(f"      {val[:8].hex()} ...")
            else:
                print(f"    PCR{idx}: empty")

        # NV Counter
        print()
        print("  MONOTONIC COUNTER")
        if self.nv_counter is not None:
            print(f"    Value: {self.nv_counter}")
        else:
            print("    Value: not initialized")

        # Sealed Storage
        print()
        print("  SEALED STORAGE")
        print(f"    Encryption: {'AES-128' if self.seal_encrypted else 'none'}")

        # Storage Slots
        print()
        print("  SECURE STORAGE SLOTS")
        slot_labels = {0: 'EK', 1: 'SRK', 2: 'PCR0', 3: 'PCR1',
                       4: 'PCR2', 5: 'NV Counter', 6: 'Sealed Data', 7: 'Seal Policy'}
        for slot in sorted(self.storage_slots.keys()):
            info = self.storage_slots[slot]
            label = slot_labels.get(slot, '?')
            if info['size'] > 0:
                print(f"    Slot {slot} ({label}): {info['size']} bytes"
                      f" = {info['data'][:6].hex()} ...")
            else:
                print(f"    Slot {slot} ({label}): empty")

        # Quote verification
        print()
        print("  REMOTE ATTESTATION")
        if self.quote_signature and self.pcrs[0] and self.pcrs[1] and self.pcrs[2]:
            ek = derive_ek()
            # Note: we only have partial PCR values from the output
            print(f"    Quote signature: {self.quote_signature[:8].hex()} ...")
            print(f"    EK fingerprint:  {ek[:8].hex()} ...")
            print("    (Full verification requires complete 32-byte PCR values)")
        else:
            print("    No quote data available")

        # Tests
        print()
        print("  TEST RESULTS")
        if self.all_passed:
            print(f"    {self.tests_passed}/{self.tests_total} PASSED")
        else:
            print("    Tests not completed")

        print()
        print("=" * 64)

    def export_report(self):
        """Export state as JSON for external tools."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "platform": "RISC-V RV64 (QEMU virt)",
            "secure_boot": self.boot_passed,
            "firmware": {
                "text_size": self.firmware_size['text'],
                "rodata_size": self.firmware_size['rodata']
            },
            "keys": {
                "ek_prefix": self.ek[:8].hex() if self.ek else None,
                "srk_prefix": self.srk[:8].hex() if self.srk else None
            },
            "pcrs": {},
            "nv_counter": self.nv_counter,
            "sealed_storage": {
                "encryption": "AES-128" if self.seal_encrypted else "none"
            },
            "storage_slots": {},
            "tests": {
                "passed": self.tests_passed,
                "total": self.tests_total,
                "all_passed": self.all_passed
            }
        }
        for idx, val in self.pcrs.items():
            report["pcrs"][f"PCR{idx}"] = val.hex() if val else "empty"
        for slot, info in self.storage_slots.items():
            report["storage_slots"][f"slot_{slot}"] = {
                "size": info['size'],
                "prefix": info['data'][:8].hex() if info['data'] else ""
            }
        return report


def run_qemu():
    """Run QEMU and capture the firmware output."""
    qemu_path = os.environ.get("QEMU") or \
        os.path.expanduser("~/qemu-ccore/build/qemu-system-riscv64")
    firmware_path = "firmware.elf"

    if not os.path.exists(firmware_path):
        print("[ERROR] firmware.elf not found. Run 'make' first.")
        return None

    if not os.path.exists(qemu_path):
        print(f"[ERROR] QEMU not found at {qemu_path}")
        print("[ERROR] Set the QEMU environment variable to use another build.")
        return None

    print("[MANAGER] Starting QEMU (capturing for up to 15 seconds)...")
    try:
        result = subprocess.run(
            [qemu_path, "-machine", "virt", "-cpu", "rv64", "-m", "128M",
             "-nographic", "-bios", "none", "-kernel", firmware_path, "-smp", "1"],
            capture_output=True, text=True, timeout=15,
            stdin=subprocess.DEVNULL
        )
        return result.stdout
    except subprocess.TimeoutExpired as e:
        # The firmware never exits on its own (it parks in wfi after the
        # test suite), so hitting the timeout is the NORMAL way a run
        # ends. The output captured so far is the complete run.
        output = e.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        if output.strip():
            print("[MANAGER] QEMU stopped (normal: the firmware never exits)")
            return output
        print("[MANAGER] QEMU produced no output before the timeout")
        return None
    except Exception as e:
        print(f"[MANAGER] Error running QEMU: {e}")
        return None


def main():
    manager = RoTManager()

    if len(sys.argv) > 1:
        if sys.argv[1] == '--run':
            output = run_qemu()
            if output:
                manager.parse_output(output)
                manager.print_dashboard()
            else:
                sys.exit(1)

        elif sys.argv[1] == '--parse' and len(sys.argv) > 2:
            with open(sys.argv[2], 'r') as f:
                output = f.read()
            manager.parse_output(output)
            manager.print_dashboard()

        elif sys.argv[1] == '--report' and len(sys.argv) > 2:
            with open(sys.argv[2], 'r') as f:
                output = f.read()
            manager.parse_output(output)
            report = manager.export_report()
            print(json.dumps(report, indent=2))

        elif sys.argv[1] == '--help':
            print(__doc__)
        else:
            print("Usage:")
            print("  python3 rot_manager.py --run              Run QEMU and show dashboard")
            print("  python3 rot_manager.py --parse FILE       Parse saved output")
            print("  python3 rot_manager.py --report FILE      Export JSON report")
            print("  python3 rot_manager.py --help             Show full help")
            print()
            print("  Set QEMU=/path/to/qemu-system-riscv64 to use another build.")
    else:
        print("Root of Trust Manager - Interactive Mode")
        print()
        print("Paste QEMU output below (end with Ctrl+D or an empty line):")
        print()
        lines = []
        try:
            while True:
                line = input()
                if line == '':
                    break
                lines.append(line)
        except EOFError:
            pass

        if lines:
            manager.parse_output('\n'.join(lines))
            manager.print_dashboard()
        else:
            print("No input received. Use --help for usage.")


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        # The consumer of our output closed early (e.g. piping to head).
        # That is not an error for a CLI tool, so exit quietly.
        os._exit(0)
