# Board side of the comparison harness

These are the programs that run on the HiFive Unmatched, built as FIT
images and loaded by U-Boot. The files one directory up, with a `q`
prefix, are the matching programs for the emulator, so each pair runs
the same work on both sides.

| board | emulator | what it measures |
|---|---|---|
| bench11.c | q11.c | the 11 reference programs at 3 intensities |
| atk.c | qatk.c | the adversarial scenarios |
| bench.c | qbench.c | a single program, used while bringing the board up |
| tr.c | qtr.c | the trap event, with 1000 ecalls |
| st.c | qst.c | the one store offset |
| clf.c | none | the cost of the classifier routine |

`clf.c` feeds two windows taken from the emulator run into
`profile_check`, so both environments judge the same input and what the
board measures is the cost of the routine, not the counts.

`mk.sh` builds every image. The measurement logs are one directory up.

## Building and running one of these on the board

`mk.sh` only patches the adversarial image. The rest are built by hand, and
the board procedure was undocumented until now. Using `sig.c` as the example:

```
riscv64-unknown-elf-gcc -march=rv64gc -mabi=lp64d -mcmodel=medany \
  -nostdlib -nostartfiles -ffreestanding -O2 -Ilib/tweetnacl -Icompare/unmatched \
  -T compare/unmatched/fw.ld compare/unmatched/start.S compare/unmatched/sig.c \
  build/stage1/tweetnacl.o -o compare/unmatched/sig.elf
riscv64-unknown-elf-objcopy -O binary compare/unmatched/sig.elf compare/unmatched/sig.bin
```

Then copy fw.its to sig.its, change fw.bin to sig.bin inside it, and run
mkimage -f sig.its sig.itb from compare/unmatched.

The board boots the FIT straight from the SD card, with no U-Boot prompt in
between. The SiFive FSBL lives in the partition whose type GUID is
`5B193300-FC78-40CD-8002-E86C45580B47` and reads the FIT from the one typed
`2E54B353-1271-4842-806F-E436D6AF6985`, so the image goes there. On macOS,
with the card as /dev/disk4 and that partition as s14:

```
diskutil unmountDisk /dev/disk4
sudo dd if=sig.itb of=/dev/rdisk4s14 bs=512 conv=sync
sudo dd if=/dev/rdisk4s14 bs=512 count=1 | xxd | head -1
diskutil eject /dev/disk4
```

That last read must start with d00d feed, the FIT magic. And bs=512
conv=sync matters: a raw device rejects a write that is not a multiple of
the sector size, and these images are not.

The console is the second channel of the board FTDI part, /dev/ttyUSB1
rather than ttyUSB0, at 115200 8N1. Open it before powering the board, with
screen -L -Logfile run.log /dev/ttyUSB1 115200, so nothing is lost if the
first lines arrive before the terminal settles.
