#include "client_app.h"
#include "uart.h"

/*
 * Working set. Sized so a full traversal is measurable but the whole
 * thing still fits comfortably in the U-mode region.
 */
#define BUF_WORDS 256

static volatile uint64_t buf[BUF_WORDS];
static volatile uint64_t sink;

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

        client_run((client_workload_t)plan[i][0], plan[i][1]);
    }

    uart_puts("[APP] === session done ===\n");
}
