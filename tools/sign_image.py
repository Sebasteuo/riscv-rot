#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sebastian Alba Vives
"""
Sign a Stage-2 payload for the two-stage secure boot.

Produces an image with an 80-byte header followed by the payload:

    magic (4) | version (4) | payload_size (4) | reserved (4)
    signature (64) | payload

The signature is Ed25519 over the SHA-256 digest of the payload, not
over the payload itself, which keeps the signed message at a fixed
32 bytes regardless of image size.

Usage:
    python3 tools/sign_image.py keygen  <key_prefix>
    python3 tools/sign_image.py sign    <key_prefix> <payload> <output> [version]
    python3 tools/sign_image.py inspect <image>
"""

import hashlib
import os
import struct
import sys

MAGIC = 0x43524F54          # "CROT"
HEADER_FMT = "<IIII64s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

try:
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    sys.exit("PyNaCl is required: pip3 install pynacl")


def keygen(prefix):
    """Generate a signing keypair. The private half never leaves here."""
    key = SigningKey.generate()
    with open(prefix + ".priv", "wb") as fh:
        fh.write(bytes(key))
    with open(prefix + ".pub", "wb") as fh:
        fh.write(bytes(key.verify_key))

    print("private key -> %s.priv  (keep this off the device)" % prefix)
    print("public  key -> %s.pub" % prefix)
    print()
    print("Public key as a C array for Stage-1:")
    pub = bytes(key.verify_key)
    for i in range(0, 32, 8):
        row = ", ".join("0x%02X" % b for b in pub[i:i + 8])
        print("    " + row + ",")


def sign(prefix, payload_path, out_path, version):
    with open(prefix + ".priv", "rb") as fh:
        key = SigningKey(fh.read())
    with open(payload_path, "rb") as fh:
        payload = fh.read()

    digest = hashlib.sha256(payload).digest()
    signature = key.sign(digest).signature

    header = struct.pack(HEADER_FMT, MAGIC, version, len(payload), 0, signature)
    with open(out_path, "wb") as fh:
        fh.write(header + payload)

    print("payload    %s (%d bytes)" % (payload_path, len(payload)))
    print("sha256     %s" % digest.hex())
    print("version    %d" % version)
    print("image      %s (%d bytes)" % (out_path, HEADER_SIZE + len(payload)))


def inspect(image_path):
    with open(image_path, "rb") as fh:
        blob = fh.read()

    if len(blob) < HEADER_SIZE:
        sys.exit("file is smaller than one header")

    magic, version, size, _, signature = struct.unpack(
        HEADER_FMT, blob[:HEADER_SIZE])

    print("magic          0x%08X %s"
          % (magic, "(ok)" if magic == MAGIC else "(WRONG)"))
    print("version        %d" % version)
    print("payload_size   %d" % size)
    print("actual size    %d" % (len(blob) - HEADER_SIZE))
    print("signature      %s..." % signature[:8].hex())

    payload = blob[HEADER_SIZE:HEADER_SIZE + size]
    print("sha256         %s" % hashlib.sha256(payload).hexdigest())


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)

    action = sys.argv[1]

    if action == "keygen" and len(sys.argv) == 3:
        keygen(sys.argv[2])
    elif action == "sign" and len(sys.argv) in (5, 6):
        version = int(sys.argv[5]) if len(sys.argv) == 6 else 1
        sign(sys.argv[2], sys.argv[3], sys.argv[4], version)
    elif action == "inspect" and len(sys.argv) == 3:
        inspect(sys.argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
