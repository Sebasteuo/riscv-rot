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
