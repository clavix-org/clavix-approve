# Phone-approved SSH signing — Design

This document describes a planned "approve every SSH signature on your
phone" feature: a key-less agent on a remote machine, and a phone that
holds the private key and signs after a biometric check. It is a design
sketch: phase 0 of "Phasing" is implemented in this repository (see
`README.md`, `PROTOCOL.md`), the rest is not. Statements marked **to
verify** have not been tested yet.

The threat model of the implementation is `THREAT_MODEL.md`; if the
desktop client ever integrates it, Clavix's own `THREAT_MODEL.md` needs
the matching addition.

## Decisions so far

- **Separate repository.** The prototype lives here, not in the Clavix
  desktop client: different deliverables, no impact on its releases or
  audit scope. The agent protocol core is copied from Clavix
  (`src-tauri/src/ssh_agent.rs`, same licence) and extracted into a
  shared crate only if the project is confirmed.
- **One approval per signature.** No batching in the first versions.
- **Web prototype first, native app later.** See "Phasing"; both
  feasibility experiments are recorded below and in `experiments/`.
- **Domain.** A passkey is bound to its relying-party domain, so the
  choice is nearly permanent. The relying-party ID is a dedicated host,
  never the bare `clavix.org`, so that no other page of the domain can
  ask the passkey for anything; nothing else is served on that host.
  `approve.clavix.org` is reserved for a possible public service; the
  prototype uses `approve-dev.clavix.org`.

## Problem

The Clavix SSH agent assumes a person sitting at the machine that runs
it. Three situations break that assumption:

1. **Prompt nobody sees.** The vault is unlocked, the policy asks for a
   confirmation, and the user is away. The request times out and the
   client reports `agent refused operation`.
2. **Vault auto-locked.** The idle or screen-lock watchdog dropped the
   session. The agent has no keys left; nothing can be approved.
3. **No agent at all.** Work happens on a headless server (a remote
   shell, a long-running job, an AI coding agent). The desktop that
   holds the vault may be off. Agent forwarding (`ssh -A`) needs a live
   interactive connection from that desktop.

Case 3 is growing: unattended tools now routinely need SSH to deploy,
and the only ways to give them a key today are a private key on disk or
a forwarded agent. Both remove the human from the loop.

## Scope

What this feature is:

- A **headless agent** (`clavix-agent`) that speaks the standard SSH
  agent protocol on a Unix socket and holds **no private key**.
- A **phone signer** that holds the key in hardware, shows each request
  and signs it after a biometric check.
- A **relay** that carries opaque, end-to-end encrypted messages
  between the two and wakes the phone with a push notification.

What it is **not**:

- Not remote unlock of the vault. The master password and the vault
  contents never reach the headless machine or the phone signer.
- Not a replacement for the desktop agent or its local confirmation
  dialog. Vault-stored keys keep working as today.
- Not command-level authorization. The user approves a *connection to a
  host*, not what is then typed into it (see "Residual risk").
- Not an SSH certificate authority. No server-side trust change beyond
  one more line in `authorized_keys`.

## What others do

- **1Password, Bitwarden Desktop, Secretive** approve signatures with a
  local prompt or biometric on the machine that runs the agent. None
  approves from another device.
- **Krypton** (krypt.co) did exactly this — key on the phone, `kr`
  agent on the computer, push approval per signature. It was acquired
  by Akamai in 2019 and later discontinued. The model is proven; the
  slot is empty.
- **HashiCorp Vault SSH CA, Teleport, step-ca** issue short-lived
  certificates after a login. They solve key distribution, need every
  server to trust a CA, and gate on a login session rather than on each
  signature.
- **Duo / verified push** is the UX reference: one notification, one
  screen that says what is being approved, approve or deny.

## Architecture

```
 headless machine                relay                    phone
┌──────────────────┐      ┌────────────────┐      ┌──────────────────┐
│ ssh / git / tool │      │ stores opaque  │      │ Clavix Approver  │
│        │ agent   │      │ blobs, sends   │ push │  - private key   │
│        ▼ socket  │ HTTPS│ a content-free │─────▶│    (hardware)    │
│  clavix-agent    │◀────▶│ wake-up        │◀────▶│  - verifies host │
│  (no key)        │      │                │ HTTPS│  - Face ID, sign │
└──────────────────┘      └────────────────┘      └──────────────────┘
```

The headless machine and the phone only make outbound HTTPS calls; no
inbound port is opened on either. The relay is untrusted for
confidentiality and integrity (it can only delay or drop).

### Key custody

The private key is generated on the phone and never leaves it.

- **Native app:** ECDSA P-256 in the Secure Enclave, access-controlled
  by biometry. The public key is a plain `ecdsa-sha2-nistp256` key,
  accepted by every OpenSSH version in use.
- **Passkey as the SSH key — tested, rejected as the agent path.** A
  WebAuthn credential can be an `sk-ecdsa-sha2-nistp256@openssh.com`
  key signing with `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`. See
  "Passkey experiment" below: sshd accepts it, but the stock `ssh`
  client refuses such a signature from an agent, which defeats the
  purpose of an agent.

Consequence: these keys are **not vault items**. They cannot be synced
or exported, by design. The vault may store the *public* key and the
pairing record so the desktop UI can list and revoke signers.

### Pairing

One-time, in person, by QR code:

1. `clavix-agent pair` generates the agent's static identity key pair
   and prints a QR code: relay URL, agent public key, one-time pairing
   secret.
2. The phone scans it, generates its own identity key pair and the SSH
   signing key, and posts both public keys to the agent through the
   relay, authenticated by the pairing secret.
3. Both sides display a short fingerprint of the two identity keys for
   the user to compare. The agent prints the SSH public key to install
   in `authorized_keys`.

Phase 0 replaces the QR code by a short code typed or pasted into the
approval page: the central use case drives the remote machine from the
very phone that would have to scan it, and the phone's camera app would
open the browser rather than the installed web app. The exchange is the
same; see `PROTOCOL.md`. A QR code of the same code is printed too,
for when the terminal is on another screen: it leads to the page in the
browser, from which the code is copied into the installed app.

After pairing, every message is encrypted to the peer's static key and
signed by the sender's (HPKE, RFC 9180, plus Ed25519 — no bespoke
primitive). The relay learns timing and sizes, nothing else.

### Signing flow

1. An SSH client sends `SSH_AGENTC_SIGN_REQUEST` to `clavix-agent`.
2. The agent packages the request: data to sign, the connection's
   verified `session-bind@openssh.com` bindings, the caller's process
   name, a request id and an expiry (default 90 s, under sshd's
   120 s `LoginGraceTime`).
3. The agent posts the sealed request to the relay; the relay sends a
   content-free push.
4. The phone fetches and decrypts the request, **re-verifies it
   itself** (next section), and shows the approval screen.
5. On approve, after biometry, the phone signs and returns the
   signature. On deny or expiry the agent answers `SSH_AGENT_FAILURE`.

The agent reuses the existing protocol core (`ssh_agent.rs`, `proto`
module): `SignRequest`, `HostHop`, `CallerInfo` and the confirmation
timeout already exist. The new part is a `ConfirmFn`-like backend that
returns a signature instead of a boolean.

### What the phone verifies and shows

The headless machine may be compromised, so the phone trusts nothing it
says about the destination. From the request alone it checks that:

- the data to sign is an SSH `publickey` user-auth request;
- the session identifier inside it matches a `session-bind` whose
  signature verifies under the claimed host key (the same check
  `session_bind()` performs today);
- that host key is in the phone's **own pinned host list** (imported at
  pairing, extended by explicit trust-on-first-use on the phone).

The screen then shows: destination host name (or "unknown host" with
the fingerprint, in a distinct warning style), remote user, forwarding
chain if any, and — labelled as *unverified* — the requesting process
name. Requests without a verifiable binding (old clients, `git` commit
signing) are refused by default; a per-key setting may allow them with
an explicit "destination unknown" warning.

### Policy and approval fatigue

- No "approve everything" switch, on either side.
- The agent rate-limits requests and queues at most a few; the phone
  shows a counter when requests arrive faster than a human could have
  caused them.
- A denied request triggers a short back-off on the agent.
- Fleet operations (one playbook, twenty hosts) mean twenty approvals.
  **This is accepted for the first versions**: one approval per
  signature, no batching. The recommended client setup is connection
  multiplexing (`ControlMaster`/`ControlPersist`), so one approval
  covers one host for the whole run. A **bounded grant** ("these N
  named hosts, for 15 minutes") is deferred; see "Open questions".

## Failure modes

| Situation | Behaviour |
|---|---|
| Phone offline or push not delivered | request expires, client sees `agent refused operation`; agent logs "no answer from signer" |
| Relay down | same; agent reports the relay error distinctly |
| Phone lost or replaced | revoke the pairing (`clavix-agent unpair`) and the public key on servers; re-pair. Access falls back to the user's other keys — the feature must never be the only way in |
| Headless machine compromised | attacker can send requests and read approved sessions (see below); cannot sign without the phone, cannot forge the destination shown |
| Relay compromised | can drop or delay; cannot read, forge or replay (request ids, expiry, and the SSH session id is unique per connection) |

## Threat-model changes

New assets: the agent identity key (on the headless machine's disk),
the phone identity key, the pairing record, the pinned host list.

New trust boundary: headless agent ↔ relay ↔ phone, over the network.
Today no network message can cause a signature; after this feature one
can, **with the user's biometric approval on the phone**. That sentence
belongs in `THREAT_MODEL.md` verbatim.

### Residual risk

Approving a connection hands a live session to whoever controls the
requesting machine at that moment. A compromised headless machine can
wait for a legitimate request, or issue its own and hope for a
reflexive approval, and then run anything in the approved session
(including through a multiplexed control socket). This is inherent to
any SSH agent. The feature narrows it to "one approved destination at a
time, each one seen by the user" — it does not remove it. Mitigations
outside our scope: forced commands or restricted accounts on the
servers, short `ControlPersist`.

## Phasing

0. **Web prototype, no native app.** A small web page installed on the
   home screen holds a plain P-256 signing key and produces ordinary
   `ecdsa-sha2-nistp256` signatures; Web Push or any existing
   notification channel carries the wake-up. The key is stored wrapped
   under a secret derived from a passkey (WebAuthn PRF extension), so
   Face ID is cryptographically required for each use. Weaker than the
   Secure Enclave (the key exists in page memory while signing) but
   works with stock clients and default servers. Goal: validate daily
   use before investing in an app. Feasibility checked on an iPhone,
   see "Web prototype experiment".
1. **`clavix-agent`** as a standalone headless binary built from the
   shared protocol core, with pairing, relay client and logging.
2. **Reference relay**, self-hostable, single small service.
3. **iOS app** with Secure Enclave key, notification extension and the
   approval screen. Android follows the same protocol.
4. **Desktop integration:** the Clavix desktop agent can delegate a
   prompt to the phone when the screen is locked, and lists/revokes
   paired signers. Proposal: [`DESKTOP_APPROVAL.md`](DESKTOP_APPROVAL.md).

Each phase is usable on its own; 0 may conclude that 3 is not worth
building.

## Passkey experiment

Question: can a passkey *be* the SSH key, so that no signing key other
than the WebAuthn credential exists? Tested with a software
authenticator that builds assertions as a browser does
(`authenticatorData` + `clientDataJSON`), against OpenSSH 9.6
(Ubuntu 24.04) and OpenSSH 10.0 (Debian 13). A real phone passkey was
not used; the wire format is what was under test.

Findings:

- **sshd verifies it.** A key whose application string is a plain web
  RP ID (`approve.example.com`, no `ssh:` prefix) is accepted. The
  challenge must be the base64url encoding of the **raw data to sign**
  (not its hash), and `clientDataJSON` must start with
  `{"type":"webauthn.get","challenge":"…","origin":"…"`. Flags `0x1D`
  (UP, UV, backup-eligible, backed-up — a synced passkey) pass.
- **Not enabled by default on the server.** Neither version lists
  `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` in its default
  `PubkeyAcceptedAlgorithms`; every server needs
  `PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.
- **The client must name the WebAuthn algorithm in the auth request.**
  Stock `ssh` always names `sk-ecdsa-sha2-nistp256@openssh.com` for
  such a key.
- **Stock `ssh` rejects the signature when it comes from an agent**
  (`agent key … returned incorrect signature type`), on 9.6 and 10.0.
  Only a custom SSH client can use this path.

Conclusion: the WebAuthn signature path cannot serve `ssh`, `git` or
Ansible through an agent. The phone must produce ordinary
`ecdsa-sha2-nistp256` signatures; a passkey can gate the key (PRF) but
cannot be the key.

## Web prototype experiment

Question: can a home-screen web app on iOS do the phone's job without a
native app? Tested once on an iPhone running iOS 18.7, with a throwaway
page served over HTTPS.

- **PRF works with a synced passkey.** The browser advertises the
  extension, the credential reports `prf.enabled` at creation, and an
  assertion returns a stable secret.
- **A PRF-wrapped P-256 key signs correctly.** The key was generated
  with WebCrypto, encrypted under a key derived from the PRF secret,
  then decrypted after Face ID and used to produce a signature that
  verifies. About 3 s end to end, Face ID included.
- **Web Push reaches a locked phone.** The subscription endpoint is
  `web.push.apple.com`; a VAPID-signed, `aes128gcm`-encrypted push was
  accepted (HTTP 201) and displayed on the lock screen. Tapping it
  reopened the web app.

Not covered by this single run: delivery latency and reliability over
days, behaviour in Low Power or Focus modes, and whether the page
state survives long idle periods. Phase 0 exists to answer those.

## Alternatives considered

- **"Away mode"** (suspend auto-lock and prompts for a bounded time):
  cheap, no network path, covers cases 1 and 2 only, and must be
  remembered before leaving. Worth doing independently.
- **Push with acknowledgement only** (no phone-held key): the key stays
  on the headless machine or in an unlocked vault there; a compromise
  of that machine yields the key. Rejected as the main design.
- **Headless vault unlocked via "login with device":** puts the whole
  unlocked vault in a server's memory. Rejected for the same reason.
- **Keeping keys in the agent across vault lock:** contradicts the
  auto-lock guarantee in `THREAT_MODEL.md`.
- **SSH CA with short-lived certificates:** sound, but a different
  product; requires changing trust on every server.

## Open questions

- **Bounded grants (deferred, not blocking).** Can the phone sign
  several requests without one biometric prompt each, while the app is
  in the background? Secure Enclave access control and background
  execution limits may make this impossible. Only worth investigating
  if per-signature approval proves too heavy in daily use.
- **Product boundary.** Phone-held keys are not vault items. Is this a
  Clavix feature or a companion product sharing the protocol core?
- **Hosted relay.** Do we run a public relay, or ship self-hosting
  only? A public one is a service to operate and a metadata sink.
- **Enrolment secret per agent (deferred).** Every agent of a relay
  creates its channels with the same secret. Whoever holds it can fill
  the relay with channels (1000 at most) and so block new pairings; it
  cannot read, sign or touch an existing pairing. Taking that right from
  one machine means changing the secret for all. Low stakes for one
  person's relay; needed before a relay serves several people (hosted
  relay, team offer), where enrolment tokens would be issued, listed and
  withdrawn one by one, and logged.
- **Audit scope.** Pairing, the sealed channel and the phone-side
  verification are new security-critical code; `AUDIT_SCOPE.md` needs
  an entry before phase 1 ships.
- **Security key as the lock (web prototype).** The SSH key is wrapped
  under "any passkey that yields a PRF secret", not under Face ID: the
  page must assume neither a synced passkey nor a platform
  authenticator. A YubiKey 5 provides the secret (`hmac-secret`).
  **To verify** on the iPhone: does Safari on iOS pass the PRF
  extension to an external security key (NFC or USB-C)? Only a synced
  passkey was tested. Expected differences: tap plus PIN instead of
  Face ID, slower; the lock is not synced, so a compromised cloud
  account does not expose it. Unchanged: the SSH key is still briefly
  decrypted in page memory.
- **Security key as the SSH key (native app phase, untested).** OpenSSH
  natively accepts FIDO keys (`sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`) with their ordinary signature:
  no server setting, no refusal by the stock client — unlike the
  `webauthn-sk-…` variant rejected in "Passkey experiment". A web page
  cannot produce that signature (the browser imposes the WebAuthn
  wrapping), but a native app could speak CTAP2 to the key over NFC:
  the phone would only display and relay, the private key would never
  leave the security key, and losing the phone would lose nothing.
  **To verify** then: that the agent can hand the stock `ssh` client an
  ordinary sk signature produced remotely (flags and counter included),
  and that an iOS app gets raw CTAP2 access with an `ssh:` application.
  Kept open by the protocol: the signer's answer carries a complete SSH
  signature blob, which names its own algorithm.
- **RSA-only servers and existing keys.** Hardware-held keys are P-256
  only; existing vault keys cannot be migrated. Is a software-held,
  biometry-gated key on the phone an acceptable second tier?
