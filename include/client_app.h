/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
#ifndef CLIENT_APP_H
#define CLIENT_APP_H

#include <stdint.h>

/*
 * Client application (OE3).
 *
 * This is the workload the root of trust attests. It is deliberately
 * separate from the firmware itself. The firmware has a small, fully
 * mapped control-flow graph and is better covered by hashing, whereas a
 * client application is arbitrarily complex and is what an attacker
 * would actually compromise.
 *
 * Four workloads, chosen because they are the primitive shapes any
 * program is built from, and because a compromise perturbs at least one
 * of them in a way the counters can see:
 *
 *   WALK      sequential data traversal   -> loads dominate
 *   SEARCH    table lookup with early out -> conditional branches vary
 *   NESTED    chained function calls      -> indirect jumps dominate
 *   TRANSFORM write results to a buffer   -> stores dominate
 *
 * Each workload takes an intensity parameter, so the same shape yields
 * different windows depending on how much work it does. Without that
 * the profile would be constant and the measurement trivially
 * deterministic.
 */

typedef enum {
    CLIENT_WALK = 0,
    CLIENT_SEARCH,
    CLIENT_NESTED,
    CLIENT_TRANSFORM,
    CLIENT_WORKLOAD_COUNT,
} client_workload_t;

/*
 * Run one workload at the given intensity. The attestation window is
 * opened before and closed after by the caller, so this function does
 * nothing but the work itself.
 */
uint64_t client_run(client_workload_t which, uint32_t intensity);

/*
 * Run a sequence of workloads, each inside its own attestation window.
 * This is the nominal behaviour the classifier is trained on.
 */
void client_nominal_session(void);

/*
 * Run the Embench workloads, each inside its own attestation window.
 * Unlike the hand-written workloads above, these come from a standard
 * benchmark suite for deeply embedded systems and were not chosen or
 * shaped by this project.
 */
void client_bench_session(void);

/* Same workloads at several intensities, so each profile
 * describes a range rather than a single point. */
void client_bench_varied(void);

#endif /* CLIENT_APP_H */
