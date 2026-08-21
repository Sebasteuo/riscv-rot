#include "hpm.h"
#include "uart.h"

/*
 * Unit tests for the architectural event counters.
 *
 * Each test runs a workload with a known number of events, reads the
 * counter before and after, and checks the delta.
 *
 * The expected values are lower bounds rather than exact figures: the
 * loop itself, the CSR reads and the bookkeeping also retire loads,
 * stores and branches. Demanding an exact match would make the tests
 * brittle without making them stronger.
 *
 * PRIV_SWITCH and TRAP_TAKEN are not covered here. They are validated
 * by the full run instead, where PRIV_SWITCH is exactly twice
 * TRAP_TAKEN because every trap produces one transition into M-mode
 * and one back out. That cross-check is stronger evidence than an
 * isolated test would be.
 */

#define TEST_ITERATIONS 1000

/* volatile so the compiler cannot optimise the accesses away */
static volatile uint64_t scratch[16];

static int tests_run;
static int tests_passed;

static void report(const char *name, uint64_t delta, uint64_t expected)
{
    tests_run++;

    uart_puts("[HPMTEST] ");
    uart_puts(name);
    uart_puts(": counted ");
    uart_put_dec(delta);
    uart_puts(", expected at least ");
    uart_put_dec(expected);

    if (delta >= expected) {
        tests_passed++;
        uart_puts("  -> PASS\n");
    } else {
        uart_puts("  -> FAIL\n");
    }
}

static void test_loads(void)
{
    uint64_t before, after;
    volatile uint64_t sink = 0;
    int i;

    before = hpm_read(HPM_CTR_LOAD);
    for (i = 0; i < TEST_ITERATIONS; i++) {
        sink += scratch[i & 15];
    }
    after = hpm_read(HPM_CTR_LOAD);

    (void)sink;
    report("LOAD_RETIRED ", after - before, TEST_ITERATIONS);
}

static void test_stores(void)
{
    uint64_t before, after;
    int i;

    before = hpm_read(HPM_CTR_STORE);
    for (i = 0; i < TEST_ITERATIONS; i++) {
        scratch[i & 15] = (uint64_t)i;
    }
    after = hpm_read(HPM_CTR_STORE);

    report("STORE_RETIRED", after - before, TEST_ITERATIONS);
}

static void test_branches(void)
{
    uint64_t before, after;
    volatile int i;

    /*
     * A loop of N iterations takes the backward branch N times, once
     * per iteration except the last.
     */
    before = hpm_read(HPM_CTR_BRANCH);
    for (i = 0; i < TEST_ITERATIONS; i++) {
        /* empty on purpose, the branch itself is what is measured */
    }
    after = hpm_read(HPM_CTR_BRANCH);

    report("BRANCH_TAKEN ", after - before, TEST_ITERATIONS - 1);
}

/* Kept out of line so the call and return are real jalr instructions */
static uint64_t __attribute__((noinline)) leaf(uint64_t x)
{
    return x + 1;
}

static void test_indirect_jumps(void)
{
    uint64_t before, after;
    volatile uint64_t acc = 0;
    int i;

    /*
     * Every return from leaf() is a jalr. The call itself may be a
     * direct jal, so the lower bound is one per iteration.
     */
    before = hpm_read(HPM_CTR_JUMP);
    for (i = 0; i < TEST_ITERATIONS; i++) {
        acc = leaf(acc);
    }
    after = hpm_read(HPM_CTR_JUMP);

    (void)acc;
    report("JUMP_INDIRECT", after - before, TEST_ITERATIONS);
}

void hpm_selftest(void)
{
    uart_puts("\n[HPMTEST] === architectural counter unit tests ===\n");

    tests_run = 0;
    tests_passed = 0;

    test_loads();
    test_stores();
    test_branches();
    test_indirect_jumps();

    uart_puts("[HPMTEST] ");
    uart_put_dec((uint64_t)tests_passed);
    uart_puts(" of ");
    uart_put_dec((uint64_t)tests_run);
    uart_puts(" passed\n");
}
