# Approving desktop signatures on the phone — Design proposal

Status: **proposal, nothing implemented.** This expands step 4 of
"Phasing" in [`DESIGN.md`](DESIGN.md). It assumes phase 0 has proved
itself (push delivery and page storage over weeks) and changes nothing
before that.

## Goal

The Clavix desktop agent asks for a confirmation before signing (policy
`Always` or `PerSession`). The dialog is missed in two situations:

- **nobody is at the screen** (`DESIGN.md`, "Problem", case 1);
- **the user is there but does not see it**: the window comes up behind
  others, and the 30 s timeout runs out.

The proposal: let the desktop put the same question to a paired phone,
which answers after a passkey user verification. The second situation
also has a desktop-only part (making sure the dialog really comes to the
front), handled in Clavix independently of this proposal.

## The choice: the phone approves, the desktop signs

Two ways to involve the phone were considered.

- **Approve only (proposed).** The key stays in the Clavix vault. The
  phone returns a signed "yes", which the desktop verifies before signing
  with the vault key as it does today.
- **Forward to the phone's key.** The desktop relays the request to the
  phone's SSH key, as `clavix-agent` does. Rejected for this step: it
  requires the phone's key in every `authorized_keys`, duplicates
  `clavix-agent`, and the vault keys would be unused exactly when the user
  is away.

Approve-only means:

- no change on any server; every vault key keeps working;
- a stronger confirmation than the local dialog: a process that can
  inject input into the desktop session (X11, accessibility APIs) can
  click a button, not produce a passkey verification on another device;
- **no help when the vault is locked** (case 2). If auto-lock has
  dropped the keys, there is nothing to approve. See "Open questions".

## When the phone is asked

One desktop setting, next to the confirmation policy: **off** (default,
today's behaviour) or **on, with a delay of N seconds** (default 10).
When on:

| Situation | Who is asked |
|---|---|
| Session unlocked | the local dialog first; the phone as well if nobody answered after N seconds |
| Screen locked | the phone only, at once |
| Screen unlocked while a request waits | the dialog comes back, next to the phone |

The delay keeps the phone quiet for the confirmations answered at the
desk (every `git push`), and reaches it when the dialog was missed,
whether the user stepped away or the window is buried.

Phone only while locked: behind the lock screen the dialog is useless to
the user, who must unlock before clicking, but a process able to inject
input (X11) may still reach it. Bringing the dialog back on unlock is
the fallback when the phone is lost or the relay is down: unlock and
answer locally, as today. Where the platform cannot tell whether the
screen is locked (`screen_lock::probe()` returns `None`), the session is
treated as unlocked, and the setting says so, like the screen-lock
auto-lock trigger does.

When both are asked, the **first answer wins**: the other prompt is
withdrawn (dialog closed; on the phone, the desktop withdraws the
request on the relay). A deny from either side denies. The desktop's confirmation
timeout is 30 s today (`commands/ssh.rs`), shorter than the 16 to 29 s
measured from `ssh` to approval on the phone in phase 0; once the phone
is asked it becomes 90 s, as in `clavix-agent`, to stay under sshd's
`LoginGraceTime`.

The locked-screen case only exists between the screen lock and the vault lock: with
the screen-lock auto-lock trigger at its shortest, the vault (and its
keys) is gone before anyone could approve. The UI must make that
visible rather than let a user believe the phone covers a locked vault.

## What the phone shows and checks

The request carries the same material as a phase 0 sign request, plus
which vault key would sign. The phone repeats the checks of
`PROTOCOL.md`, "Sign request", with two changes:

- the user-auth request must name the key in the request (not the phone's
  own key), and may use any algorithm the desktop holds: `ssh-ed25519`,
  `ecdsa-sha2-nistp256/384/521`, `rsa-sha2-256/512`;
- the destination is still shown under the name **the phone** pinned for
  the host key; the desktop's `known_hosts` name is a hint, as now.

The screen reads: user name, destination, the key's comment and
fingerprint (from the request, labelled as reported by the desktop), and
"from Clavix desktop « label »", where the label is the one recorded at
pairing.

**Requests that are not SSH logins** (git commit signing through
`SSHSIG`, arbitrary data, clients without `session-bind`) carry nothing
the phone can verify. First version: the desktop does not send them; they
get the local dialog only. Showing an `SSHSIG` namespace and message hash
is a possible later addition, with an explicit "not verified" screen.

## Protocol changes

Relay: **none.** The desktop is one more agent on its own channel; the
relay keeps seeing opaque messages and a constant push.

The wire format is fixed in `PROTOCOL.md`, "Approve mode"; this section
gives the reasons.

### Keys

One new key on the phone, the **approval key**: Ed25519 on the page,
wrapped under the passkey's PRF secret like the SSH key; P-256 in the
Secure Enclave for a native iPhone app, which offers no Ed25519. It
travels as an SSH public key blob and signs SSH signature blobs, so both
types fit one format and both ends reuse their SSH code.

Why a separate key: the phone's Ed25519 identity key signs every sealed
message but is usable without user verification (the page needs it to
read requests). An approval signed with it would prove the page ran, not
that the user verified. Reusing the SSH key would make one key sign two
kinds of statement; a key per purpose keeps them apart.

### Pairing

Same exchange as `PROTOCOL.md`, "Pairing", with the hello marked
`mode: "approve"` and the approval key in place of the SSH key. Each
change also changes a MAC or fingerprint label, so the relay cannot pair
a device in the wrong mode. The desktop shows "approval only, nothing to
install on servers".

A phone can be paired with a desktop and with `clavix-agent`s; each
pairing is its own channel.

### Approval request and response

The request is a sign request with `t: "approve"` and the vault key in
`key`; the response is `approved` with a `proof`, an SSH signature by the
approval key over the channel, signer id, request id and the SHA-256 of
the request message as received. The proof thus names the exact data,
key and bindings that were shown. The desktop checks the sealed envelope
as today, then the proof under the approval key recorded at pairing, and
only then signs.

### Withdrawing a request

When the local dialog answers first, the desktop withdraws the request on
the relay (`POST …/requests/{id}/cancel`, added for several devices): the
phone's page drops it at its next poll. No cancel message is needed; a
late `approved` is ignored since the request is no longer pending.

## Clavix desktop changes

- `ssh_agent`: `SignRequest` gains the bytes to sign, and `HostHop` the
  raw `session-bind` signature, so the phone can re-verify. Both pass
  through the agent already (the signature is verified, then dropped);
  neither reaches the `ConfirmFn` today.
- A second `ConfirmFn` backend that races the dialog and the phone, as
  described under "When the phone is asked".
- The channel, pairing and relay client come from a crate shared with
  `clavix-agent`, extracted from `agent/src/{channel,pairing,relay}.rs`
  (the extraction `DESIGN.md` defers until the project is confirmed).
  Clavix already depends on `reqwest` with rustls.
- Pairing state (identity keys, bearer token, peer keys, label) stored in
  the vault, so it is only usable while the vault is unlocked — which is
  the only time there is anything to approve. Whether it must be kept out
  of vault sync is to verify against Clavix's sync design; it is
  per-device.
- UI: pair a phone (code shown, six digits compared), list and revoke
  paired phones, the "Ask the phone" setting.
- Clavix's `THREAT_MODEL.md` and `AUDIT_SCOPE.md` gain the network client
  and the parsing of relay responses.

## Threat model changes

| Attacker | Effect |
|---|---|
| The relay or the network | Can delay or drop requests: the local dialog still works, so the worst case is today's behaviour. Cannot forge an approval (needs the PRF-wrapped approval key) or replay one (bound to channel, request id and request hash). |
| A malicious page served by the relay | As in phase 0: it could show a different destination to obtain a passkey verification. Same residual risk, same mitigation (the page's integrity is the relay's). |
| A compromised desktop | No change: it holds the keys and can sign without asking anyone. The phone is a check on what goes through the agent, not on the machine. |
| A process in the desktop session | Cannot approve by faking input while the screen is locked, when the phone is the only prompt. While the session is unlocked the dialog is shown, and it still can, as today. |
| A thief with the unlocked phone | Needs the passkey's user verification for each approval. |

New risk accepted: a signature can now happen while the user is away,
which the timeout used to prevent. That is the point of the feature, and
each one still needs a verification on the phone.

## Steps

1. **In this repository (done):** the approve mode in the page and in
   `tools/fake-phone.mjs`, and a test requester that plays the desktop:
   `tools/fake-desktop.mjs`, in Node on the page's modules
   (`web/lib/requester.js`) rather than in Rust, until the shared crate of
   step 2 exists. End to end with Ed25519 and RSA requester keys:
   `tools/approve-e2e.mjs`, and the real page in `tools/page-e2e.mjs`.
2. **Shared crate (done):** `core/` (`clavix-approve-core`) holds the
   channel, pairing in both modes and the relay client, which
   `clavix-agent` now uses, and the requester (`requester` module):
   pair devices in approve mode, ask every device at once (first answer
   wins, a refusal is final, the others are withdrawn), verify the proof,
   withdraw by the caller's own request id. Its rustdoc maps it onto
   Clavix's `PhoneApprover`. End to end against the fake phone:
   `core/tests/e2e_approve.rs`.
3. **Clavix PR:** the backend, the settings and pairing UI, the threat
   model additions, behind a setting that defaults to off.

## Open questions

- **Locked vault while away** (case 2). An "away mode" could keep the
  keys in memory after the screen locks, on condition that every
  signature then goes to the phone. Not proposed: "a locked session holds
  no keys" is a core promise of Clavix's auto-lock and of its audit
  argument, and case 2 is better served by `clavix-agent` with the
  phone's key, or by a longer vault-lock delay. If ever built: explicit
  opt-in, phone required for every signature, keys kept for a bounded
  time (an hour, say) after the screen locks.
- **Git signing:** whether an unverifiable `SSHSIG` request is worth
  showing on the phone at all.
- **Several phones:** the format allows several signers per channel;
  first answer wins, a single deny denies.
