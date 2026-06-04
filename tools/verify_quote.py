#!/usr/bin/env python3
"""
Remote Attestation Verifier

This script acts as a remote verifier for our Root of Trust firmware.
It replicates the exact same cryptographic operations that the firmware
does internally, and checks if a Quote signature is authentic.

How it works:
  1. We know the endorsement seed (in a real system, the device
     manufacturer would share the EK public key with us)
  2. We derive the EK from the seed using the same KDF as the firmware
  3. We take the PCR values reported by the device
  4. We compute HMAC-SHA256(EK, PCR0 || PCR1 || PCR2)
  5. We compare our computed signature with the one the device sent
  6. If they match, the device is authentic and its firmware is intact

Usage:
  python3 verify_quote.py            interactive: paste PCR values and
                                     the signature from the QEMU output
  python3 verify_quote.py --demo     self-test with example values, no
                                     QEMU needed (checks that a genuine
                                     quote passes and a tampered one is
                                     rejected)

Exit code is 0 when the verification (or the demo) passes, 1 when it
fails, so the script can be used from shell scripts and CI.

Based on:
  - TPM 2.0 spec section 6.12 (TPM2_Quote)
  - NIST SP 800-108 (KDF in Counter Mode)

Author: Sebastian Alba
Project: Root of Trust Firmware for RISC-V with PMP isolation
"""

import hmac
import hashlib
import struct
import sys

# =========================================================================
# The endorsement seed. In a real system this would be provisioned
# during manufacturing and the verifier would only know the public
# part of the EK. For our symmetric-key demo, the verifier knows
# the seed so it can derive the same EK as the firmware.
# =========================================================================
ENDORSEMENT_SEED = bytes([
    0x7A, 0x1B, 0x3C, 0x4D, 0x5E, 0x6F, 0x80, 0x91,
    0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19,
    0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x90, 0xA1,
    0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29
])


def kdf_derive(seed: bytes, label: str) -> bytes:
    """
    Replicate the firmware's KDF (NIST SP 800-108 Counter Mode).

    The input to HMAC is:
      counter (4 bytes, big-endian, always 1)
      + label string
      + 0x00 separator
      + "RoT-RISCV" context
      + 0x00000100 output length in bits (256)

    The key for HMAC is the seed.
    """
    buf = b''
    buf += struct.pack('>I', 1)           # counter = 1
    buf += label.encode('ascii')          # label
    buf += b'\x00'                        # separator
    buf += b'RoT-RISCV'                   # context
    buf += struct.pack('>I', 256)         # output bits = 256

    return hmac.new(seed, buf, hashlib.sha256).digest()


def derive_ek(seed: bytes) -> bytes:
    """Derive the Endorsement Key from the seed, same as the firmware."""
    return kdf_derive(seed, "ENDORSEMENT")


def compute_quote_signature(ek: bytes, pcr0: bytes, pcr1: bytes, pcr2: bytes) -> bytes:
    """
    Compute the expected Quote signature.
    This is HMAC-SHA256(EK, PCR0 || PCR1 || PCR2).
    """
    pcr_concat = pcr0 + pcr1 + pcr2
    return hmac.new(ek, pcr_concat, hashlib.sha256).digest()


def parse_hex_string(s: str) -> bytes:
    """
    Parse a hex string like '0xc1 0x2c 0x2d 0x69 ...' into bytes.
    Also handles formats like 'c1 2c 2d 69' or 'c12c2d69'.
    """
    s = s.strip()
    # Remove "..." at the end if present
    s = s.replace('...', '').strip()
    if '0x' in s:
        # Format: 0xc1 0x2c 0x2d ...
        parts = s.split()
        return bytes([int(p, 16) for p in parts if p.startswith('0x')])
    elif ' ' in s:
        # Format: c1 2c 2d ...
        parts = s.split()
        return bytes([int(p, 16) for p in parts])
    else:
        # Format: c12c2d69...
        return bytes.fromhex(s)


def run_demo(ek: bytes) -> int:
    """
    Self-test mode. Simulates a complete attestation exchange with
    example PCR values, then checks the two properties a verifier
    must have:

      Check 1: a quote signed with the real EK must PASS
      Check 2: a tampered quote must be REJECTED

    Returns the exit code (0 = demo passed, 1 = verifier is broken).
    """
    print("[VERIFY] Running in demo mode (self-test, no QEMU output needed)")
    print()

    # Simulated device state: example PCR values, and the signature
    # that a genuine device holding this EK would produce for them.
    pcr0 = hashlib.sha256(b'demo .text measurement').digest()
    pcr1 = hashlib.sha256(b'demo .rodata measurement').digest()
    pcr2 = hashlib.sha256(b'demo host measurement').digest()
    genuine_sig = compute_quote_signature(ek, pcr0, pcr1, pcr2)

    # Check 1: the genuine quote must verify
    print("[VERIFY] Check 1: genuine quote (signature made with the real EK)")
    expected = compute_quote_signature(ek, pcr0, pcr1, pcr2)
    ok_genuine = hmac.compare_digest(expected, genuine_sig)
    print(f"[VERIFY]   Computed: {expected[:8].hex()} ...")
    print(f"[VERIFY]   Received: {genuine_sig[:8].hex()} ...")
    print(f"[VERIFY]   Result:   {'ACCEPTED' if ok_genuine else 'REJECTED'}"
          f"  (expected: ACCEPTED)")
    print()

    # Check 2: a tampered quote must be rejected. We flip one byte of
    # the signature, as if an attacker had forged or altered it.
    print("[VERIFY] Check 2: tampered quote (one byte of the signature flipped)")
    tampered_sig = bytes([genuine_sig[0] ^ 0xFF]) + genuine_sig[1:]
    ok_tampered = hmac.compare_digest(expected, tampered_sig)
    print(f"[VERIFY]   Computed: {expected[:8].hex()} ...")
    print(f"[VERIFY]   Received: {tampered_sig[:8].hex()} ...")
    print(f"[VERIFY]   Result:   {'ACCEPTED' if ok_tampered else 'REJECTED'}"
          f"  (expected: REJECTED)")
    print()

    if ok_genuine and not ok_tampered:
        print("  *** DEMO OK ***")
        print("  The verifier accepts genuine quotes and rejects tampered ones.")
        print("  For a real verification, run without --demo and paste the")
        print("  PCR values and Quote signature from the QEMU output.")
        print()
        return 0

    print("  *** DEMO FAILED ***")
    print("  The verifier did not behave as expected. Check this script.")
    print()
    return 1


def main():
    print("=" * 60)
    print("  Remote Attestation Verifier")
    print("  Root of Trust Firmware for RISC-V")
    print("=" * 60)
    print()

    # Step 1: Derive the EK from the known seed
    print("[VERIFY] Step 1: Deriving EK from endorsement seed...")
    ek = derive_ek(ENDORSEMENT_SEED)
    print(f"[VERIFY]   EK = {ek[:8].hex()} ...")
    print(f"[VERIFY]   (should match: ff d4 58 71 81 58 7c 57)")
    print()

    # Demo mode: self-contained test, no QEMU output needed
    if len(sys.argv) > 1 and sys.argv[1] == '--demo':
        sys.exit(run_demo(ek))

    # Step 2: Get PCR values and the signature from the user
    print("[VERIFY] Step 2: Enter PCR values from QEMU output")
    print("[VERIFY] (paste the hex bytes, e.g. '0xc1 0x2c 0x2d ...')")
    print("[VERIFY] You need all 32 bytes for each PCR.")
    print()

    try:
        print("PCR0 (32 bytes hex): ", end='')
        pcr0 = parse_hex_string(input())
        print("PCR1 (32 bytes hex): ", end='')
        pcr1 = parse_hex_string(input())
        print("PCR2 (32 bytes hex): ", end='')
        pcr2 = parse_hex_string(input())
        print("Quote signature (32 bytes hex): ", end='')
        sig = parse_hex_string(input())
    except (ValueError, EOFError) as e:
        print(f"\n[VERIFY] Error parsing input: {e}")
        print("[VERIFY] Try running with --demo for a quick test")
        sys.exit(2)

    print()

    # Step 3: Compute expected signature
    print("[VERIFY] Step 3: Computing expected Quote signature...")
    expected_sig = compute_quote_signature(ek, pcr0, pcr1, pcr2)
    print(f"[VERIFY]   Computed: {expected_sig[:8].hex()} ...")
    print(f"[VERIFY]   Received: {sig[:8].hex()} ...")
    print()

    # Step 4: Compare
    print("[VERIFY] Step 4: Comparing signatures...")
    if hmac.compare_digest(expected_sig, sig):
        print()
        print("  *** ATTESTATION PASSED ***")
        print("  The device is authentic.")
        print("  The firmware has NOT been tampered with.")
        print("  The PCR values are genuine.")
        print()
        sys.exit(0)
    else:
        print()
        print("  *** ATTESTATION FAILED ***")
        print("  WARNING: The signature does not match!")
        print("  The device may have been compromised,")
        print("  or the PCR values may have been forged.")
        print()
        sys.exit(1)


if __name__ == '__main__':
    main()
