#ifndef ATTACK_H
#define ATTACK_H

#include <stdint.h>

/*
 * Adversarial workloads (OE3).
 *
 * These are real attacks, executed rather than simulated. The control
 * flow is genuinely diverted: a stack buffer overflow overwrites the
 * saved return address, so the function returns somewhere it was never
 * supposed to.
 *
 * The vulnerable function below is deliberately vulnerable. It exists
 * to be exploited and is never reached by normal operation. It is kept
 * in its own file so the distinction is unambiguous.
 *
 * This corresponds to attack A3 in the threat model: runtime
 * compromise of the U-mode system. The model assumes the attacker is
 * already inside, so what is reproduced here is what they do next, not
 * how they got in.
 */

typedef enum {
    /* Baseline: the same function with an input that fits */
    ATTACK_NONE = 0,

    /*
     * Code reuse. The return address is overwritten with the address
     * of another function already present in the binary, so execution
     * continues along a path the program never intended. This is the
     * primitive that return-oriented programming builds on.
     */
    ATTACK_REDIRECT,

    /*
     * Code injection. The input carries RISC-V instructions and the
     * return address points back into the buffer, so the processor
     * executes data as code. Possible here because the U-mode region
     * is mapped executable; a non-executable stack would block this
     * one while leaving ATTACK_REDIRECT untouched.
     */
    ATTACK_INJECT,

    ATTACK_COUNT,
} attack_kind_t;

/* Run one scenario inside its own attestation window */
void attack_run(attack_kind_t kind);

/* Run all of them in sequence */
void attack_session(void);

#endif /* ATTACK_H */
