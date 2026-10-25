#!/usr/bin/env python3
"""
Check that the loader refuses malformed images.

Stage-1 validates every field it uses before it writes anything, and
those rejection paths had no tests. A signature makes an image
authentic, not well formed, so an authenticated image can still name a
destination outside the window, a size that does not add up, or an
entry point outside everything that was loaded.

Each case changes one field of a good image, signs it with the project
key, boots Stage-1 against it, and requires the error that field feeds.
A good image runs first as the control, so a pass here cannot come from
the chain being broken for some other reason.

The expected codes are read out of include/elf64.h rather than written
here, so reordering the enumeration cannot make this test quietly wrong.

Usage:
    python3 tools/test_reject.py [key-prefix]
"""

import os
import re
import struct
import subprocess
import sys

PT_LOAD = 1
E_ENTRY, E_PHOFF, E_PHENTSIZE, E_PHNUM = 24, 32, 54, 56
P_TYPE, P_PADDR, P_FILESZ, P_MEMSZ = 0, 24, 32, 40

# From include/elf64.h and scripts/stage1.ld. If those move, so do these.
LOAD_MAX = 0x80300000
IMAGE_ADDR = 0x84000000
STAGE1_STACK = 0x80500000

QEMU = os.path.expanduser("~/qemu-ccore/build/qemu-system-riscv64")
WORK = "build/reject"
TIMEOUT = 40

# label, mutation, the error the loader has to report
CASES = (
    ("ok", None, None),
    ("over-top", "over-top", "ELF_ERR_SEGMENT_RANGE"),
    ("on-image", "on-image", "ELF_ERR_SEGMENT_RANGE"),
    ("on-stack", "on-stack", "ELF_ERR_SEGMENT_RANGE"),
    ("short-memsz", "short-memsz", "ELF_ERR_SEGMENT_SIZE"),
    ("bad-entry", "bad-entry", "ELF_ERR_ENTRY"),
)


def u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def u64(b, off):
    return struct.unpack_from("<Q", b, off)[0]


def put64(b, off, v):
    struct.pack_into("<Q", b, off, v)


def mutate(mutation, src, dst):
    """Change one field of a good image and write the result."""
    b = bytearray(open(src, "rb").read())

    phoff, phentsize, phnum = u64(b, E_PHOFF), u16(b, E_PHENTSIZE), u16(b, E_PHNUM)
    segments = [phoff + i * phentsize for i in range(phnum)
                if struct.unpack_from("<I", b, phoff + i * phentsize + P_TYPE)[0]
                == PT_LOAD]
    if not segments:
        raise SystemExit("no loadable segments in %s" % src)
    first = segments[0]

    if mutation == "over-top":
        put64(b, first + P_PADDR, LOAD_MAX + 0x1000)
    elif mutation == "on-image":
        put64(b, first + P_PADDR, IMAGE_ADDR)
    elif mutation == "on-stack":
        put64(b, first + P_PADDR, STAGE1_STACK)
    elif mutation == "short-memsz":
        filesz = u64(b, first + P_FILESZ)
        put64(b, first + P_MEMSZ, filesz - 1 if filesz else 0)
    elif mutation == "bad-entry":
        # Inside the window the loader accepts, so the segment checks
        # pass, but past everything that gets loaded.
        top = max(u64(b, s + P_PADDR) + u64(b, s + P_FILESZ) for s in segments)
        put64(b, E_ENTRY, top + 0x1000)
    else:
        raise SystemExit("unknown mutation %s" % mutation)

    open(dst, "wb").write(bytes(b))


def error_codes(header="include/elf64.h"):
    """Read elf_result_t and return a name to value mapping."""
    m = re.search(r"typedef enum \{(.*?)\} elf_result_t;",
                  open(header).read(), re.S)
    if not m:
        raise SystemExit("could not find elf_result_t in %s" % header)

    codes, value = {}, 0
    for line in m.group(1).split("\n"):
        line = re.sub(r"/\*.*?\*/", "", line).strip().rstrip(",").strip()
        if not line or line[0] in "*/":
            continue
        if "=" in line:
            name, rhs = [p.strip() for p in line.split("=", 1)]
            value = int(rhs, 0)
        else:
            name = line
        codes[name] = value
        value += 1
    return codes


def boot(image):
    """Boot Stage-1 against one image and return what it printed."""
    cmd = ("%s -machine virt -cpu rv64 -m 128M -nographic -bios stage1.elf"
           " -device loader,file=%s,addr=0x%X -smp 1 < /dev/null"
           % (QEMU, image, IMAGE_ADDR))
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=TIMEOUT)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
        err = e.stderr or b""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return out + err


def main():
    keys = sys.argv[1] if len(sys.argv) > 1 else "keys/stage2"
    for f in ("stage1.elf", "firmware.elf", keys + ".pub"):
        if not os.path.exists(f):
            raise SystemExit("%s is missing, run make secureboot first" % f)

    codes = error_codes()
    os.makedirs(WORK, exist_ok=True)

    print("=== Checking that the loader refuses malformed images ===")
    print()

    passed = failed = 0

    for label, mutation, want in CASES:
        image = "%s/stage2_%s.img" % (WORK, label)

        if mutation is None:
            elf = "firmware.elf"
        else:
            elf = "%s/firmware_%s.elf" % (WORK, label)
            mutate(mutation, "firmware.elf", elf)

        r = subprocess.run("python3 tools/sign_image.py sign %s %s %s 1"
                           % (keys, elf, image), shell=True,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("  [FAIL] %-13s could not be signed" % label)
            print("         %s" % (r.stdout + r.stderr).strip())
            failed += 1
            continue

        out = boot(image)

        if want is None:
            if "Transferring control" in out and "loader error" not in out:
                print("  [OK]   %-13s the good image still boots" % label)
                passed += 1
            else:
                print("  [FAIL] %-13s the good image did not boot" % label)
                failed += 1
            continue

        expect = codes.get(want)
        got = re.search(r"loader error code (\d+)", out)

        if expect is None:
            print("  [FAIL] %-13s %s is not in the enumeration" % (label, want))
            failed += 1
        elif got is None:
            print("  [FAIL] %-13s expected %s (%d), nothing was reported"
                  % (label, want, expect))
            failed += 1
        elif int(got.group(1)) != expect:
            print("  [FAIL] %-13s expected %s (%d), got %s"
                  % (label, want, expect, got.group(1)))
            failed += 1
        else:
            print("  [OK]   %-13s refused with %s (%d)" % (label, want, expect))
            passed += 1

    print()
    print("=== RESULT: %s, %d of %d ==="
          % ("PASS" if failed == 0 else "FAIL", passed, passed + failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
