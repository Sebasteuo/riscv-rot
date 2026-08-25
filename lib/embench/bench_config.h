#ifndef BENCH_CONFIG_H
#define BENCH_CONFIG_H

/*
 * Embench build configuration (OE3).
 *
 * Embench normally sets this from its own Python build system, which
 * scales each benchmark to run for roughly four seconds of CPU time on
 * the target. That is not what is wanted here: the goal is a bounded
 * amount of work per attestation window, not a fixed wall-clock
 * duration, and functional emulation has no meaningful notion of
 * elapsed CPU time anyway.
 *
 * The factor is therefore set explicitly and kept small, so a window
 * covers a workload comparable to the hand-written ones rather than
 * running for seconds under emulation.
 */
#ifndef GLOBAL_SCALE_FACTOR
#define GLOBAL_SCALE_FACTOR 1
#endif

#endif /* BENCH_CONFIG_H */
