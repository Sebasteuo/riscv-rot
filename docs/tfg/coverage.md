# Coverage against the threat model

**Stage OE4** · CE-5600 Final Project · Sebastian Alba Vives
17 September 2026

---

## What this document answers

The threat model names seven attacks inside scope. This says, for each
one, whether the work covers it, how the coverage was established, and
where it stops.

Three of the seven were already covered by the platform inherited from
CE-1114 and are restated here for completeness. The other four are what
this project addresses.

A distinction worth keeping in view: covered means demonstrated on this
platform under emulation, not proven in general. Where the argument
rests on something not measured, the entry says so.

---

## A1 · Modify the firmware while the device is powered off

**Covered.**

The image carries an Ed25519 signature over the SHA-256 digest of its
payload. Stage-1 verifies that signature before parsing any field of the
image, so a modified image is rejected regardless of what its header
claims.

Established by `tools/attack_demo.py`, scenario two: a single byte
flipped anywhere in the payload changes the digest, the signature no
longer verifies, and the boot halts.

**Where it stops.** The verification proves the image was signed by the
holder of the private key. It says nothing about whether that key holder
intended this particular version, which is what the anti-rollback
counter addresses separately.

---

## A2 · Modify the reference value together with the firmware

**Covered. This is the gap OE1 was written to close.**

The previous scheme compared measurements against golden hashes stored
on the same device, so an attacker able to rewrite both passed. The new
scheme has no stored reference to rewrite: verification depends on a
public key, and forging a signature requires the private key, which
never enters the device.

Established by `tools/attack_demo.py`, scenario three: firmware and
reference value are modified together and the boot still halts. That
scenario is the one that defeated the previous design.

**Where it stops.** An attacker who replaces the embedded public key
does not gain anything, since they still cannot sign. But an attacker
who obtains the private key defeats the scheme entirely. Key custody is
outside this work.

---

## A3 · Compromise the U-mode system at runtime

**Covered for the scenarios measured. This is the gap OE3 addresses.**

Four adversarial scenarios were implemented and measured against the
same vulnerable routine:

| Scenario | Diverts control | Verdict |
|---|---|---|
| Normal input | no | nominal |
| Overflow without reaching the return address | no | detected |
| Overflow redirecting to unreachable code | yes | detected |
| Long overflow redirecting | yes | detected |
| Overflow redirecting into reachable code | yes | detected |

The last one is the demanding case. It diverts into a function the
program already calls on its own, so the destination is legitimate code
and nothing about where execution landed is anomalous. It is still
caught, and by a signal that holds regardless of the target: indirect
jumps drop from seven to five because two returns never happen.

The second is the other informative case. Control flow is never
diverted, yet the extra copying shifts the ratios enough to be caught.
The classifier is therefore reacting to two distinct things rather than
to diversion alone.

**Where it stops.** Detection is bounded by the sensitivity measured in
`tools/sensitivity.py`: the vulnerable routine reacts at 11 percent
deviation, and the measured attacks deviate by 15 to 88 percent. A
compromise that stays inside that band is not detected. This is the
substance of A6 below.

---

## A4 · Read or write crypto core resources from U-mode

**Covered. Inherited from CE-1114 and re-verified after the memory map
changed.**

Six PMP regions with no catch-all entry, so anything not explicitly
granted is denied to U-mode. Tests 1, 2, 32, 33 and 34 attempt the
access and receive a processor exception.

The memory map moved during this project: the Embench port grew the
U-mode region from 64 KB to 512 KB, which required relocating the secret
zone. The same five tests were re-run after the change and still receive
the exception, so the relocation did not weaken the isolation.

Test 36 was added for this project: it attempts to read the counters
from U-mode and receives an illegal instruction.

**Where it stops.** The regions are not locked. PMP provides a lock bit
that makes an entry immutable until reset, and this platform does not
use it, so M-mode can reconfigure PMP at any time. That is consistent
with the threat model, which treats M-mode as trusted, but it means the
isolation protects against U-mode rather than against arbitrary code at
any privilege.

---

## A5 · Send arbitrary or malformed commands through the mailbox

**Covered. Inherited from CE-1114.**

The dispatcher validates the command code and the declared size before
acting. Test 35 sends an unknown command and receives an error with
internal state untouched.

The two commands added by this project follow the same discipline. The
attestation report command returns a fixed-size response and the window
commands validate that a window is open before closing it.

**Where it stops.** The validation is per command. A sequence of
individually valid commands that produces an unintended state was not
systematically explored.

---

## A6 · Evade the classifier by shaping the counter profile

**Partially mitigated. Reported as partial.**

Two mechanisms bear on this.

The measurement points are derived from the verifier's nonce, so which
of them fire changes with every challenge. This is the mitigation
ConFirm describes for the compensation attack: an adversary who knows
where the points sit can alter the flow between two of them and make it
up afterwards. Points that move remove the fixed target that attack
needs.

The classifier carries three ratios rather than one. The sensitivity
analysis shows why that matters: `md5sum` and `nsichneu` are effectively
blind on indirect jumps, where their nominal ratio of 23 parts per ten
thousand falls under the absolute floor, but neither is blind on the
other two. No application in the corpus is blind on all three.

**Where it stops.** Neither mechanism makes evasion impossible. An
adversary who compromises every path still passes, and an attack shaped
to stay within the detection band of all three ratios is not caught.
Dinakarrao and coauthors demonstrate that detectors built on hardware
events are evadable by an adversary who models them, and nothing here
contradicts that. What the work establishes is the size of the band an
attacker must stay inside, which is a quantity rather than an assurance.

---

## A7 · Replay an old attestation report

**Covered.**

Each attestation is opened by a challenge carrying a 16-byte nonce
supplied by the external verifier, and the nonce travels back in the
report. A stored response from an earlier session carries the wrong
nonce and is rejected by the verifier.

The nonce is supplied by the verifier rather than generated on the
device, which is what makes the freshness guarantee meaningful: a
compromised device cannot choose the value it will be challenged with.

**Where it stops.** Freshness depends on the verifier never repeating a
nonce. That is a property of the verifier, which is outside this work.

---

## Summary

| Attack | Status | Established by |
|---|---|---|
| A1 · Firmware modified at rest | Covered | Attack demonstration, scenario 2 |
| A2 · Firmware and reference modified | Covered | Attack demonstration, scenario 3 |
| A3 · Runtime compromise | Covered for the scenarios measured | Four adversarial scenarios |
| A4 · U-mode reaches protected resources | Covered | Tests 1, 2, 32, 33, 34, 36 |
| A5 · Malformed mailbox commands | Covered | Test 35 |
| A6 · Classifier evasion | **Partially mitigated** | Nonce-derived points, three ratios |
| A7 · Report replay | Covered | Nonce in challenge and report |

Six covered, one partial. The partial one is the honest outcome: a
behavioral detector cannot claim immunity to an adversary who models it,
and claiming otherwise would be the kind of assurance this work is meant
to measure rather than assert.
