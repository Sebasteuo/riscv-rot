#include "attest.h"
#include "timer.h"
#include "uart.h"
#include "pmp.h"

/*
 * Counter indices in the order they appear in a sample. Kept as a table
 * so the feature order is defined in one place: the firmware, the
 * exported dataset and the trained model must all agree on it.
 */
static const int feature_ctr[ATTEST_FEATURES] = {
    HPM_CTR_LOAD,
    HPM_CTR_STORE,
    HPM_CTR_BRANCH,
    HPM_CTR_JUMP,
    HPM_CTR_TRAP,
    HPM_CTR_PRIV,
};

static const char *feature_name[ATTEST_FEATURES] = {
    "load", "store", "branch", "jump", "trap", "priv",
};

static attest_sample_t samples[ATTEST_MAX_SAMPLES];
static uint64_t baseline[ATTEST_FEATURES];
static uint32_t sample_count;
static uint32_t dropped;

/* Measurement window state */
static uint64_t window_base[ATTEST_FEATURES];
static uint8_t  window_nonce[ATTEST_NONCE_SIZE];
static int      window_open;
static uint32_t window_app;
static uint32_t point_mask;

/*
 * Overhead accounting.
 *
 * cost_us accumulates the time spent inside the attestation path: the
 * counter reads on open, and the reads plus classification on close.
 * work_us accumulates the time between the two, which is the workload
 * being observed.
 *
 * The split is what makes the relative figure possible. Neither number
 * means much alone under emulation; their ratio does.
 */
static uint64_t cost_us;
static uint64_t work_us;
static uint64_t work_t0;
static uint32_t window_n;
static uint64_t class_us;

/*
 * The classification is timed separately from the counter reads.
 *
 * The two answer different questions. The read cost is what any
 * attestation scheme pays to collect evidence; the classification cost
 * is what this design pays for deciding inside the device rather than
 * shipping the metrics out. Only the second is particular to the
 * approach, so lumping them together would hide the figure that
 * matters.
 */
void attest_add_class_us(uint64_t us) { class_us += us; }
uint64_t attest_class_us(void)        { return class_us; }

uint64_t attest_cost_us(void)      { return cost_us; }
uint64_t attest_work_us(void)      { return work_us; }
uint32_t attest_window_count(void) { return window_n; }

void attest_cost_reset(void)
{
    cost_us = 0;
    work_us = 0;
    window_n = 0;
    class_us = 0;
}
static uint32_t dropped;

static void read_all(uint64_t out[ATTEST_FEATURES])
{
    int i;

    for (i = 0; i < ATTEST_FEATURES; i++) {
        out[i] = hpm_read(feature_ctr[i]);
    }
}

void attest_init(void)
{
    sample_count = 0;
    dropped = 0;
    read_all(baseline);

    uart_puts("[ATT] Sampling armed at command boundaries\n");
}

void attest_sample(uint32_t cmd)
{
    uint64_t now[ATTEST_FEATURES];
    attest_sample_t *s;
    int i;

    read_all(now);

    /*
     * Drop the sample rather than overwrite when the buffer is full.
     * Overwriting would silently change what a later export contains,
     * which is worse than losing the tail of a long run.
     */
    if (sample_count < ATTEST_MAX_SAMPLES) {
        s = &samples[sample_count];
        s->cmd = cmd;
        for (i = 0; i < ATTEST_FEATURES; i++) {
            s->delta[i] = now[i] - baseline[i];
        }
        sample_count++;
    } else {
        dropped++;
    }

    /* The baseline moves regardless, so windows stay contiguous */
    for (i = 0; i < ATTEST_FEATURES; i++) {
        baseline[i] = now[i];
    }
}

void attest_window_open(const uint8_t *nonce, uint32_t nonce_len)
{
    uint32_t i;
    uint64_t t0 = timer_now();

    read_all(window_base);

    for (i = 0; i < ATTEST_NONCE_SIZE; i++) {
        window_nonce[i] = (i < nonce_len) ? nonce[i] : 0;
    }

    window_open = 1;

    /*
     * The clock is read last so the cost figure covers everything the
     * open path does, and work_t0 starts the moment control goes back
     * to the observed workload.
     */
    work_t0 = timer_now();
    cost_us += work_t0 - t0;
}

int attest_window_close(uint64_t out[ATTEST_FEATURES])
{
    uint64_t now[ATTEST_FEATURES];
    uint64_t t0;
    int i;

    if (!window_open) {
        return 0;
    }

    t0 = timer_now();
    work_us += t0 - work_t0;

    read_all(now);
    for (i = 0; i < ATTEST_FEATURES; i++) {
        out[i] = now[i] - window_base[i];
    }

    window_open = 0;
    window_n++;

    cost_us += timer_now() - t0;
    return 1;
}

void attest_set_selection(const uint8_t *nonce, uint32_t nonce_len)
{
    uint32_t i;
    uint32_t m = 0;

    /*
     * Fold the nonce into a bitmask, one bit per measurement point.
     * Nothing cryptographic is needed here: the point is that the
     * selection is unpredictable to the client, and the nonce already
     * comes from the verifier.
     */
    for (i = 0; i < nonce_len; i++) {
        m = (m << 3) ^ (m >> 29) ^ (uint32_t)nonce[i];
    }

    /* Never select none: an attestation that measures nothing is
       worse than useless, it looks like a pass. */
    point_mask = m ? m : 1u;
}

int attest_point_selected(uint32_t point)
{
    return (point_mask >> (point & 31)) & 1u;
}

void attest_set_app(uint32_t app_id)
{
    window_app = app_id;
}

uint32_t attest_get_app(void)
{
    return window_app;
}

int attest_window_active(void)
{
    return window_open;
}

const uint8_t *attest_window_nonce(void)
{
    return window_nonce;
}

uint32_t attest_dropped(void)
{
    return dropped;
}


uint32_t attest_count(void)
{
    return sample_count;
}

const attest_sample_t *attest_get(uint32_t index)
{
    if (index >= sample_count) {
        return 0;
    }
    return &samples[index];
}

void attest_dump(void)
{
    uint32_t i;
    int f;

    uart_puts("\n[ATT] === samples (");
    uart_put_dec((uint64_t)sample_count);
    uart_puts(" windows");
    if (dropped) {
        uart_puts(", ");
        uart_put_dec((uint64_t)dropped);
        uart_puts(" dropped");
    }
    uart_puts(") ===\n");

    /* Header row, so the output can be parsed without guessing columns */
    uart_puts("[ATT] cmd");
    for (f = 0; f < ATTEST_FEATURES; f++) {
        uart_puts(",");
        uart_puts(feature_name[f]);
    }
    uart_puts("\n");

    for (i = 0; i < sample_count; i++) {
        uart_puts("[ATT] ");
        uart_put_dec((uint64_t)samples[i].cmd);
        for (f = 0; f < ATTEST_FEATURES; f++) {
            uart_puts(",");
            uart_put_dec(samples[i].delta[f]);
        }
        uart_puts("\n");
    }

    uart_puts("[ATT] === end ===\n");
}
