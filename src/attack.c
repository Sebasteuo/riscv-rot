#include "attack.h"
#include "uart.h"
#include "client_app.h"

/*
 * Adversarial workloads. See attack.h for why this file exists.
 *
 * Compiled with -fno-stack-protector so the overflow is not caught
 * before it can divert control. The rest of the firmware is built the
 * same way, so this is not a special case: it reflects how the
 * platform is actually built.
 */

extern void bench_window_open(void);
extern void bench_set_app(uint32_t id);
extern void bench_window_close(void);

/* Marks whether the diverted path was reached */
static volatile uint32_t diverted;
static volatile uint64_t work_sink;

/*
 * The function the redirect jumps to. It is never called from anywhere
 * in normal operation: reaching it means control flow was diverted.
 */
/*
 * Where a diverted call lands.
 *
 * The overflow destroys the frame, so the diverted function cannot
 * return normally: it would pop a return address that no longer means
 * anything. A real exploit either repairs the stack or never returns.
 *
 * Here it never returns. The function does its work and then jumps
 * back to a recorded recovery point, which keeps the system alive so
 * the attestation window can be closed and the measurement collected.
 * Without that the run dies mid-window and there is nothing to read.
 */
static uint64_t recover_sp;
static uint64_t recover_ra;

static void __attribute__((noinline)) unreachable_path(void)
{
    volatile uint64_t acc = 0;
    int i;

    diverted = 1;

    /* Enough work that the diversion is visible in the counters */
    for (i = 0; i < 200; i++) {
        acc += (uint64_t)i * 3;
    }
    work_sink = acc;

    /*
     * Close the window here. Control flow past this point cannot be
     * relied on: the frame that called into this function no longer
     * exists. Closing first means the measurement survives even if the
     * recovery does not.
     */
    bench_window_close();

    /*
     * Jump back to the recovery point rather than returning. The
     * overflow destroyed the frame, so a normal return would pop an
     * address that no longer means anything.
     */
    asm volatile(
        "ld sp, %0\n"
        "ld ra, %1\n"
        "jr ra\n"
        :: "m"(recover_sp), "m"(recover_ra) : "memory"
    );
}

/*
 * The vulnerable function.
 *
 * copy_input() writes as many bytes as it is given, with no bound
 * check against the destination size. That is the bug, and it is the
 * same shape as the classic strcpy-into-a-fixed-buffer defect.
 */
static void __attribute__((noinline))
copy_input(uint8_t *dst, const uint8_t *src, uint32_t n)
{
    uint32_t i;

    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

static void __attribute__((noinline))
vulnerable(const uint8_t *input, uint32_t len)
{
    uint8_t buffer[32];

    copy_input(buffer, input, len);

    /* Keep the buffer live so the compiler cannot elide it */
    work_sink += buffer[0];
}

/* ---------------------------------------------------------------- */

static void run_none(void)
{
    /* An input that fits. Same code path, no overflow. */
    uint8_t input[16];
    int i;

    for (i = 0; i < 16; i++) {
        input[i] = (uint8_t)(i + 1);
    }
    vulnerable(input, sizeof(input));
}

static void run_redirect(void)
{
    /*
     * The recovery point is captured here with a label, so the
     * diverted path resumes after the vulnerable call rather than
     * inside a frame that no longer exists.
     */
    /*
     * Overwrite the saved return address with the address of
     * unreachable_path(). The offset to the saved ra depends on the
     * frame gcc emits for vulnerable(); it is checked against the
     * disassembly rather than guessed.
     */
    uint8_t input[64];
    uint64_t target = (uint64_t)(void *)unreachable_path;
    int i;

    for (i = 0; i < 64; i++) {
        input[i] = 0x41;
    }

    /* Saved ra sits at the top of the frame */
    for (i = 0; i < 8; i++) {
        input[40 + i] = (uint8_t)((target >> (i * 8)) & 0xFF);
    }

    vulnerable(input, sizeof(input));
}

static void run_inject(void)
{
    /*
     * Same overflow, but the return address points back into the
     * buffer, which holds RISC-V instructions. The payload sets
     * diverted and returns.
     *
     *   li   t0, 1
     *   la   t1, diverted     (built from the address at run time)
     *   sw   t0, 0(t1)
     *   ret
     */
    uint8_t input[64];
    uint64_t flag = (uint64_t)(void *)&diverted;
    uint32_t insn[6];
    int i;

    /* addi t0, zero, 1 */
    insn[0] = 0x00100293;
    /* lui t1, hi(flag) ; addi t1, t1, lo(flag) */
    insn[1] = 0x00000337 | (uint32_t)((flag + 0x800) & 0xFFFFF000);
    insn[2] = 0x00030313 | (uint32_t)((flag & 0xFFF) << 20);
    /* sw t0, 0(t1) */
    insn[3] = 0x00532023;
    /* ret */
    insn[4] = 0x00008067;
    insn[5] = 0x00000013;

    for (i = 0; i < 64; i++) {
        input[i] = 0x41;
    }
    for (i = 0; i < 6; i++) {
        input[i * 4 + 0] = (uint8_t)(insn[i] & 0xFF);
        input[i * 4 + 1] = (uint8_t)((insn[i] >> 8) & 0xFF);
        input[i * 4 + 2] = (uint8_t)((insn[i] >> 16) & 0xFF);
        input[i * 4 + 3] = (uint8_t)((insn[i] >> 24) & 0xFF);
    }

    vulnerable(input, sizeof(input));
}

/* ---------------------------------------------------------------- */

static const char *kind_name[ATTACK_COUNT] = {
    "none", "redirect", "inject",
};

void attack_run(attack_kind_t kind)
{
    diverted = 0;

    /*
     * Snapshot the context before the overflow, so the diverted path
     * has something valid to return to.
     */
    asm volatile("mv %0, sp" : "=r"(recover_sp));
    asm volatile("mv %0, ra" : "=r"(recover_ra));

    /* All three scenarios exercise the same routine, profile 0 */
    bench_set_app(0);
    bench_window_open();

    switch (kind) {
    case ATTACK_NONE:     run_none();     break;
    case ATTACK_REDIRECT: run_redirect(); break;
    case ATTACK_INJECT:   run_inject();   break;
    default: break;
    }

    /* The diverted paths close their own window before recovering */
    if (!diverted) {
        bench_window_close();
    }
}

void attack_session(void)
{
    int k;

    uart_puts("\n[ATK] === adversarial workloads ===\n");

    for (k = 0; k < ATTACK_COUNT; k++) {
        uart_puts("[ATK] ");
        uart_puts(kind_name[k]);
        uart_puts("\n");

        attack_run((attack_kind_t)k);

        uart_puts("[ATK]   diverted: ");
        uart_puts(diverted ? "YES" : "no");
        uart_puts("\n");
    }

    uart_puts("[ATK] === done ===\n");
}
