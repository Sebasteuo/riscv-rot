#include "client_app.h"
#include <stddef.h>
#include "uart.h"
#include "pmp.h"

/*
 * Working set. Sized so a full traversal is measurable but the whole
 * thing still fits comfortably in the U-mode region.
 */
#define BUF_WORDS 256

static volatile uint64_t buf[BUF_WORDS];
static volatile uint64_t sink;

static volatile uint32_t *shared =
    (volatile uint32_t *)SHARED_BASE;
static volatile uint8_t *shared_data =
    (volatile uint8_t *)(SHARED_BASE + SHARED_OFF_DATA);

/*
 * Open a measurement window. The nonce would come from the external
 * verifier in a real deployment; here it is derived from the window
 * index so runs stay reproducible while each window still carries a
 * distinct value.
 */
static void window_open_app(uint32_t seq, uint32_t app_id)
{
    uint32_t i;

    for (i = 0; i < ATTEST_NONCE_SIZE; i++) {
        shared_data[i] = (uint8_t)(seq * 31 + i);
    }

    shared[SHARED_OFF_CMD / 4] = SHARED_CMD_ATTEST_BEGIN;
    shared[SHARED_OFF_SIZE / 4] = ATTEST_NONCE_SIZE;
    shared[SHARED_OFF_PCR_IDX / 4] = app_id;
    asm volatile("ecall");
}

static void window_open(uint32_t seq)
{
    window_open_app(seq, 0);
}

static void window_close(void)
{
    shared[SHARED_OFF_CMD / 4] = SHARED_CMD_ATTEST_END;
    shared[SHARED_OFF_SIZE / 4] = 0;
    asm volatile("ecall");
}

/* ---- WALK: sequential traversal, loads dominate ---- */
static uint64_t walk(uint32_t intensity)
{
    uint64_t acc = 0;
    uint32_t i, pass;

    for (pass = 0; pass < intensity; pass++) {
        for (i = 0; i < BUF_WORDS; i++) {
            acc += buf[i];
        }
    }
    return acc;
}

/* ---- SEARCH: lookup with early exit, branch behaviour varies ---- */
static uint64_t search(uint32_t intensity)
{
    uint64_t hits = 0;
    uint32_t i, k;

    /*
     * The target changes each pass, so the loop exits at a different
     * point every time. That is what makes the branch counts vary
     * rather than staying fixed.
     */
    for (k = 0; k < intensity; k++) {
        uint64_t target = (uint64_t)((k * 37) % BUF_WORDS);
        for (i = 0; i < BUF_WORDS; i++) {
            if (buf[i] == target) {
                hits++;
                break;
            }
        }
    }
    return hits;
}

/* ---- NESTED: chained calls, indirect jumps dominate ---- */
/* noinline so each call and return is a real jump, not folded away */
static uint64_t __attribute__((noinline)) level_c(uint64_t x)
{
    return x + buf[x % BUF_WORDS];
}

static uint64_t __attribute__((noinline)) level_b(uint64_t x)
{
    return level_c(x) + 1;
}

static uint64_t __attribute__((noinline)) level_a(uint64_t x)
{
    return level_b(x) + 1;
}

static uint64_t nested(uint32_t intensity)
{
    uint64_t acc = 0;
    uint32_t i;

    for (i = 0; i < intensity; i++) {
        acc = level_a(acc);
    }
    return acc;
}

/* ---- TRANSFORM: write results back, stores dominate ---- */
static uint64_t transform(uint32_t intensity)
{
    uint32_t i, pass;

    for (pass = 0; pass < intensity; pass++) {
        for (i = 0; i < BUF_WORDS; i++) {
            buf[i] = (buf[i] * 3) + 1;
        }
    }
    return buf[0];
}

/*
 * Window hooks for Embench.
 *
 * The suite calls start_trigger() and stop_trigger() around the region
 * it wants measured. Those land here, so an attestation window covers
 * exactly the benchmark body: no setup, no verification, no printing.
 */
static uint32_t bench_seq;

static uint32_t bench_app_id;

void bench_set_app(uint32_t id)
{
    bench_app_id = id;
}

void bench_window_open(void)
{
    window_open_app(bench_seq, bench_app_id);
}

void bench_window_close(void)
{
    window_close();
    bench_seq++;
}

uint64_t client_run(client_workload_t which, uint32_t intensity)
{
    uint64_t r = 0;

    switch (which) {
    case CLIENT_WALK:      r = walk(intensity);      break;
    case CLIENT_SEARCH:    r = search(intensity);    break;
    case CLIENT_NESTED:    r = nested(intensity);    break;
    case CLIENT_TRANSFORM: r = transform(intensity); break;
    default: break;
    }

    sink = r;
    return r;
}

static const char *workload_name[CLIENT_WORKLOAD_COUNT] = {
    "walk", "search", "nested", "transform",
};

/* Provided by the Embench board support */
extern void initialise_board(void);
extern void start_trigger(void);
extern void stop_trigger(void);
extern void init_heap_beebs(void *heap, size_t heap_size);

/*
 * Heap for the benchmarks that allocate. BEEBS brings its own
 * allocator but expects the platform to hand it a block: without this
 * call malloc_beebs returns NULL and the benchmarks dereference it.
 *
 * Sized to fit the largest allocation in the suite while staying
 * inside the U-mode region.
 */
#define BENCH_HEAP_SIZE (64 * 1024)
static uint8_t bench_heap[BENCH_HEAP_SIZE];

/*
 * Each benchmark is compiled with its entry points renamed, so all
 * nineteen can live in one binary and run one after another. The
 * renaming happens on the compiler command line; the sources are
 * unmodified.
 */
extern void init_aha_mont64(void);
extern void warm_aha_mont64(int);
extern int  bench_aha_mont64(void);
extern int  verify_aha_mont64(int);
extern void init_crc32(void);
extern void warm_crc32(int);
extern int  bench_crc32(void);
extern int  verify_crc32(int);
extern void init_depthconv(void);
extern void warm_depthconv(int);
extern int  bench_depthconv(void);
extern int  verify_depthconv(int);
extern void init_edn(void);
extern void warm_edn(int);
extern int  bench_edn(void);
extern int  verify_edn(int);
extern void init_huffbench(void);
extern void warm_huffbench(int);
extern int  bench_huffbench(void);
extern int  verify_huffbench(int);
extern void init_matmult_int(void);
extern void warm_matmult_int(int);
extern int  bench_matmult_int(void);
extern int  verify_matmult_int(int);
extern void init_md5sum(void);
extern void warm_md5sum(int);
extern int  bench_md5sum(void);
extern int  verify_md5sum(int);
extern void init_nettle_aes(void);
extern void warm_nettle_aes(int);
extern int  bench_nettle_aes(void);
extern int  verify_nettle_aes(int);
extern void init_nettle_sha256(void);
extern void warm_nettle_sha256(int);
extern int  bench_nettle_sha256(void);
extern int  verify_nettle_sha256(int);
extern void init_nsichneu(void);
extern void warm_nsichneu(int);
extern int  bench_nsichneu(void);
extern int  verify_nsichneu(int);
extern void init_picojpeg(void);
extern void warm_picojpeg(int);
extern int  bench_picojpeg(void);
extern int  verify_picojpeg(int);
extern void init_qrduino(void);
extern void warm_qrduino(int);
extern int  bench_qrduino(void);
extern int  verify_qrduino(int);
extern void init_sglib_combined(void);
extern void warm_sglib_combined(int);
extern int  bench_sglib_combined(void);
extern int  verify_sglib_combined(int);
extern void init_slre(void);
extern void warm_slre(int);
extern int  bench_slre(void);
extern int  verify_slre(int);
extern void init_statemate(void);
extern void warm_statemate(int);
extern int  bench_statemate(void);
extern int  verify_statemate(int);
extern void init_tarfind(void);
extern void warm_tarfind(int);
extern int  bench_tarfind(void);
extern int  verify_tarfind(int);
extern void init_ud(void);
extern void warm_ud(int);
extern int  bench_ud(void);
extern int  verify_ud(int);
extern void init_wikisort(void);
extern void warm_wikisort(int);
extern int  bench_wikisort(void);
extern int  verify_wikisort(int);
extern void init_xgboost(void);
extern void warm_xgboost(int);
extern int  bench_xgboost(void);
extern int  verify_xgboost(int);

typedef struct {
    const char *name;
    void (*init)(void);
    void (*warm)(int);
    int  (*run)(void);
    int  (*verify)(int);
} bench_entry_t;

/*
 * Eleven of the nineteen Embench workloads run to completion here. The
 * rest reach for platform facilities this build does not provide, and
 * fail on a bad pointer rather than a missing symbol, so they are left
 * out rather than patched: modifying a benchmark would defeat the
 * point of using a standard suite.
 */
static const bench_entry_t bench_table[] = {
    { "aha-mont64", init_aha_mont64, warm_aha_mont64, bench_aha_mont64, verify_aha_mont64 },
    { "crc32", init_crc32, warm_crc32, bench_crc32, verify_crc32 },
    { "depthconv", init_depthconv, warm_depthconv, bench_depthconv, verify_depthconv },
    { "edn", init_edn, warm_edn, bench_edn, verify_edn },
    { "huffbench", init_huffbench, warm_huffbench, bench_huffbench, verify_huffbench },
    { "matmult-int", init_matmult_int, warm_matmult_int, bench_matmult_int, verify_matmult_int },
    { "md5sum", init_md5sum, warm_md5sum, bench_md5sum, verify_md5sum },
    { "nettle-aes", init_nettle_aes, warm_nettle_aes, bench_nettle_aes, verify_nettle_aes },
    { "nettle-sha256", init_nettle_sha256, warm_nettle_sha256, bench_nettle_sha256, verify_nettle_sha256 },
    { "nsichneu", init_nsichneu, warm_nsichneu, bench_nsichneu, verify_nsichneu },
    { "picojpeg", init_picojpeg, warm_picojpeg, bench_picojpeg, verify_picojpeg },
};

#define BENCH_COUNT (sizeof(bench_table) / sizeof(bench_table[0]))

void client_bench_session(void)
{
    uint32_t i;

    uart_puts("\n[APP] === Embench workloads ===\n");

    initialise_board();
    init_heap_beebs(bench_heap, BENCH_HEAP_SIZE);

    for (i = 0; i < BENCH_COUNT; i++) {
        int result, ok;

        uart_puts("[APP] ");
        uart_puts(bench_table[i].name);
        uart_puts("\n");

        bench_table[i].init();

        /*
         * No cache warming: the emulator models no cache, so it would
         * add work without changing what the counters observe.
         */
        bench_table[i].warm(0);

        /*
         * Embench leaves the triggers to the harness, so the window is
         * opened here. It covers the benchmark body alone: not the
         * setup, not the verification, not the printing.
         */
        bench_set_app(i + 1);
        start_trigger();
        result = bench_table[i].run();
        stop_trigger();

        ok = bench_table[i].verify(result);
        uart_puts("[APP]   verify: ");
        uart_puts(ok ? "OK" : "FAILED");
        uart_puts("\n");
    }

    uart_puts("[APP] === Embench done ===\n");
}

void client_nominal_session(void)
{
    /*
     * Intensities are varied on purpose. A constant intensity would
     * produce identical windows every time, which is exactly the
     * degenerate case the measurement has to avoid.
     */
    static const uint32_t plan[][2] = {
        { CLIENT_WALK,       2 },
        { CLIENT_SEARCH,     8 },
        { CLIENT_NESTED,    40 },
        { CLIENT_TRANSFORM,  1 },
        { CLIENT_WALK,       5 },
        { CLIENT_SEARCH,    20 },
        { CLIENT_NESTED,   120 },
        { CLIENT_TRANSFORM,  3 },
        { CLIENT_WALK,       1 },
        { CLIENT_SEARCH,     4 },
        { CLIENT_NESTED,    15 },
        { CLIENT_TRANSFORM,  6 },
    };
    uint32_t n = sizeof(plan) / sizeof(plan[0]);
    uint32_t i;

    /* Known starting state so runs are comparable */
    for (i = 0; i < BUF_WORDS; i++) {
        buf[i] = (uint64_t)(i * 7 + 3);
    }

    uart_puts("\n[APP] === client application, nominal session ===\n");

    for (i = 0; i < n; i++) {
        uart_puts("[APP] ");
        uart_puts(workload_name[plan[i][0]]);
        uart_puts(" x");
        uart_put_dec((uint64_t)plan[i][1]);
        uart_puts("\n");

        window_open(i);
        client_run((client_workload_t)plan[i][0], plan[i][1]);
        window_close();
    }

    uart_puts("[APP] === session done ===\n");
}
