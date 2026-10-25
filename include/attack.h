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
 * This corresponds to attack A3 in the threat model, the runtime
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
     * is mapped executable. A non-executable stack would block this
     * one while leaving ATTACK_REDIRECT untouched.
     */
    /*
     * Implemented and the diversion does occur, but the run does not
     * survive it long enough to close the window, so no measurement
     * comes back. The injected payload would have to restore enough
     * context to return, which a real exploit does and this one does
     * not.
     *
     * Left in rather than removed, because the case it represents is
     * worth stating: injection needs an executable stack, which this
     * platform's PMP configuration grants. A system mapping U-mode
     * data as non-executable would block ATTACK_INJECT outright while
     * leaving ATTACK_REDIRECT untouched, since code reuse never
     * executes data.
     */
    ATTACK_INJECT,

    /*
     * Variants of the same defect, kept apart because they produce
     * different signatures.
     *
     * One attack says the classifier caught that attack. Several say
     * something about the shape of what it catches, which is what an
     * evaluation needs.
     */

    /* Minimal overflow: writes just past the buffer without diverting
     * control. Tests whether the classifier reacts to the copy itself
     * or only to the diversion. */
    ATTACK_SMALL,

    /* Long overflow: a much larger input, so the copy loop dominates.
     * Should be the loudest of the three on store and branch. */
    ATTACK_LONG,

    /* Code reuse: diverts into the middle of an existing function
     * rather than to a function nothing calls. Closer to what a real
     * return-oriented attack does, and the hardest of the three to
     * separate from nominal behaviour. */
    ATTACK_REUSE,

    /*
     * Diagnostics added after the analysis of the scenarios above.
     * Neither one is an attack.
     *
     * ATTACK_VOLUME copies the same number of bytes as ATTACK_LONG
     * into a buffer that holds them, so there is no overflow and no
     * diversion. It isolates the copy volume on its own.
     *
     * ATTACK_SMALL_HELPER repeats ATTACK_SMALL with the one auxiliary
     * call that the baseline makes and the attack scenarios do not. It
     * holds the indirect jump count equal to the baseline, so what is
     * left to read is the volume.
     */
    ATTACK_VOLUME,
    ATTACK_SMALL_HELPER,

    ATTACK_COUNT,
} attack_kind_t;

/* Run one scenario inside its own attestation window */
void attack_run(attack_kind_t kind);

/* Run all of them in sequence */
void attack_session(void);

#endif /* ATTACK_H */
