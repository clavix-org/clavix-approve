# clavix-approve

Approve every SSH signature on your phone.

A key-less SSH agent runs on the machine that needs access (a server, a
remote shell, an unattended tool). The private key lives on the phone.
Each signature request shows up as a notification; the phone displays
the destination, asks for a biometric check and signs.

**Status: prototype, nothing usable yet.** This repository currently
holds the design and two feasibility experiments.

- [`DESIGN.md`](DESIGN.md) — problem, architecture, threat-model
  changes, phasing, open questions.
- [`experiments/`](experiments/) — the throwaway code behind the two
  experiments recorded in the design.

Companion to [Clavix](https://github.com/clavix-org/clavix). Licensed
under GPL-3.0, like Clavix.
