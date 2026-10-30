/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sebastian Alba Vives */
#ifndef SECRET_H
#define SECRET_H

/*
 * __secret places a variable in the .secret section, which the linker
 * maps to 0x80200000 (the PMP-protected secret zone). Variables marked
 * this way live in RAM that U-mode cannot read or write, because PMP
 * region 0 blocks that address range. The section is zeroed at boot by
 * start.S, so all __secret variables start at zero.
 *
 * Used for crypto core state that must stay out of U-mode reach: the
 * PCR bank, the authentication and session state, the ELF whitelist
 * and the supply chain vendor table.
 */
#define __secret __attribute__((section(".secret")))

/*
 * __secret_const places initialized read-only data (the hardcoded seeds
 * and the auth password) in the .secret_data section, which the linker
 * also maps inside the PMP-protected zone at 0x80100000. Unlike __secret,
 * this section keeps its initial values (it is loaded, not zeroed), so it
 * is meant for constants that must stay secret from U-mode.
 */
#define __secret_const __attribute__((section(".secret_data")))

#endif /* SECRET_H */
