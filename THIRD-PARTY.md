# Third-party components

This repository is licensed under GPL-3.0-or-later, see LICENSE.
The firmware links the Embench benchmarks into the same image, so the
resulting binary is a combined work and carries that license.

The components below keep their own terms.

## Apache-2.0

Depthwise convolution benchmark. Copyright 2024 The TensorFlow Authors.

1 files:

- `src/bench/depthconv__depthconv.c`

## GPL-3.0-or-later

Embench-IoT benchmarks and support code. Copyright (C) 2013-2019 Embecosm Limited and the University of Bristol.

30 files:

- `lib/embench/beebsc.c`
- `lib/embench/beebsc.h`
- `lib/embench/support.h`
- `src/bench/aha_mont64__mont64.c`
- `src/bench/crc32__crc_32.c`
- `src/bench/ecctable.h`
- `src/bench/edn__libedn.c`
- `src/bench/huffbench__libhuffbench.c`
- `src/bench/matmult_int__matmult-int.c`
- `src/bench/nettle_aes__nettle-aes.c`
- `src/bench/nettle_sha256__nettle-sha256.c`
- `src/bench/nsichneu__libnsichneu.c`
- `src/bench/picojpeg.h`
- `src/bench/picojpeg__libpicojpeg.c`
- `src/bench/picojpeg__picojpeg_test.c`
- `src/bench/qrbits.h`
- `src/bench/qrduino__qrencode.c`
- `src/bench/qrduino__qrframe.c`
- `src/bench/qrduino__qrtest.c`
- `src/bench/qrencode.h`
- `src/bench/sglib.h`
- `src/bench/sglib_combined__combined.c`
- `src/bench/slre.h`
- `src/bench/slre__libslre.c`
- `src/bench/statemate__libstatemate.c`
- `src/bench/ud__libud.c`
- `src/bench/wikisort__libwikisort.c`
- `src/bench/xgboost.h`
- `src/bench/xgboost__testbench.c`
- `src/bench/xgboost__xgboost.c`

## MIT

Two Embench benchmarks. `md5sum__md5.c` is by Creationix, modified by Julian Kunkel for Embench-iot. `tarfind__tarfind.c` is by Julian Kunkel for Embench-iot.

2 files:

- `src/bench/md5sum__md5.c`
- `src/bench/tarfind__tarfind.c`

## Public domain

`lib/tweetnacl/` holds TweetNaCl, which its authors placed in the
public domain. See https://tweetnacl.cr.yp.to for the upstream terms.
The files carry no header, so they are listed here instead.

## Third-party files with no header

- `lib/embench/bench_config.h`
- `lib/embench/board.c`
- `lib/tweetnacl/tweetnacl.c`
- `lib/tweetnacl/tweetnacl.h`
