#include "attest.h"
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

    read_all(window_base);

    for (i = 0; i < ATTEST_NONCE_SIZE; i++) {
        window_nonce[i] = (i < nonce_len) ? nonce[i] : 0;
    }

    window_open = 1;
}

int attest_window_close(uint64_t out[ATTEST_FEATURES])
{
    uint64_t now[ATTEST_FEATURES];
    int i;

    if (!window_open) {
        return 0;
    }

    read_all(now);
    for (i = 0; i < ATTEST_FEATURES; i++) {
        out[i] = now[i] - window_base[i];
    }

    window_open = 0;
    return 1;
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
