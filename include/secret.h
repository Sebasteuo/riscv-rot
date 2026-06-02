#ifndef SECRET_H
#define SECRET_H

/*
 * __secret places a variable in the .secret section, which the linker
 * maps to 0x80100000 (the PMP-protected secret zone). Variables marked
 * this way live in RAM that U-mode cannot read or write, because PMP
 * region 0 blocks that address range. The section is zeroed at boot by
 * start.S, so all __secret variables start at zero.
 *
 * Used for crypto core state that must stay out of U-mode reach: the
 * PCR bank, the authentication and session state, the ELF whitelist
 * and the supply chain vendor table.
 */
#define __secret __attribute__((section(".secret")))

#endif /* SECRET_H */
