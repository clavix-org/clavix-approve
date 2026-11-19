# Threat model (phase 0, web prototype)

Scope: the key-less agent, the relay and the approval page as implemented
in this repository. The design it comes from is in
[`DESIGN.md`](DESIGN.md), the messages in [`PROTOCOL.md`](PROTOCOL.md).
This is a prototype for a daily-use trial by its author; it has not been
audited.

**Today no network message can cause a signature; after this feature one
can, with the user's biometric approval on the phone.** (With a security
key as the passkey, read "user verification" for "biometric".)

## What is protected

| Asset | Where | Compromise means |
|---|---|---|
| SSH private key | approval page storage, encrypted under a passkey PRF secret | logins as the user on every server that trusts it |
| Passkey | the user's authenticator (platform or security key) | with the stored ciphertext: the SSH key |
| Signer channel keys | page storage, non-extractable | reading requests, forging responses that carry no valid SSH signature |
| Agent channel keys, agent token | agent state file, mode 0600 | sending requests that look like this agent's |
| Pinned host list | page storage | a destination shown under a wrong name |
| Pairing code | on screen for a few minutes | pairing another device in the user's place |
| Relay enrolment secret (closed enrolment only) | relay and agent environments | creating channels on the relay, within the per-address limits |
| APNs auth key (`.p8`) | relay environment | sending notifications to the app on any device that registered it (spam, false alerts; no request content, no signature) |

## Who is trusted for what

- **The phone and its browser** are trusted completely.
- **The origin that serves the page** is trusted completely, because it
  delivers the code that handles the key. In this prototype that origin
  is the relay's host by default; a public relay runs with
  `RELAY_SERVE_WEB=off` so that the page lives on another origin. See
  "Known weaknesses".
- **The relay as a message carrier** is not trusted: it sees sizes,
  timing, channel and request ids, expiry times and the push
  subscription. It cannot read, forge, alter or redirect a message.
- **The machine that runs the agent** is not trusted for what it says
  about a request. It is trusted not to be the attacker only in the sense
  of the residual risk below.
- **SSH servers** are identified by their host key and nothing else.

## Attackers

### The relay, or anyone on the network path

Can drop or delay messages, and replay old ones. Cannot learn a
destination or a key (HPKE). Cannot inject a request or a response
(Ed25519 signatures under keys exchanged at pairing). Cannot change a
request's id or expiry, or pass a response off as answering another
request (both are bound into the sealed message; the response names the
hash of the request). A replayed request is one the user already saw; its
signature is useless outside the SSH session it names, which is unique to
one connection.

At pairing it cannot substitute its own keys: both directions carry a MAC
keyed from the pairing secret, of which the relay only sees an unrelated
derivation. The six verification digits are a second, human check.

It can withhold service, and it can send notifications at will (they
carry no content and lead to an empty list).

### A compromised machine running the agent

Can ask for signatures, at any time, and gets a live session for each one
the user approves — see "Residual risk". Cannot sign without the phone.
Cannot make the phone display another destination than the real one: the
phone checks the server's own signature over the session being
authenticated, and that the bytes to sign are a login for that session.
Names come from the phone's pinned list, never from the request; what the
machine supplies (process name, its own label, a suggested host name) is
displayed as unverified and stripped of control characters.

It can present a server the phone has never seen. The phone then shows
"unknown host" with the fingerprint, in a distinct style, and requires the
user to name the host before approving. **A user who approves unknown
hosts without checking the fingerprint defeats this protection.**

It can bury the user under requests. Mitigations: at most 4 waiting, a
5-second silence after each denial, no "approve all" (all three in the
agent, which this attacker controls), and on the relay, which it does
not: at most 8 live and 32 stored requests per channel (cancelled and
answered ones count, so a cancel loop does not get around it), 60
requests per channel per minute, and at most one push per 10 seconds and
100 a day, per channel and per device. A flood can still keep the user's
request list busy within those bounds; it cannot make the phone buzz
more than that.

### Anyone on the internet (public relay, open enrolment)

Can create channels, pair its own devices and post requests to them: it
needs no secret. It cannot touch a channel it does not hold a token of.
What bounds it: channels per client address per hour and per day, a
global safety cap, idle channels deleted after 90 days, devices and
requests per channel, a size cap on every message, a global byte budget
for pending data, push rate limits per channel and per device token,
concurrent long-polls per token and per address, a connection cap and
socket timeouts. A device token registered on a second channel leaves the
first (the latest registration wins), so one token cannot be woken from
many channels at once. What remains: someone controlling many addresses
can fill the global cap until idle expiry catches up, and can register a
victim's APNs token on its own channel (no proof of possession yet) to
send it at most the push budget of notifications per day. Per-account
quotas and App Attest are the next steps.

### Another user of the machine running the agent

The socket and the state file are only accessible to their owner. Root on
that machine is the previous case.

### A thief with the unlocked phone

Needs the passkey's user verification for each signature. The channel
keys alone let them read incoming requests, nothing more.

### A hostile SSH server

Receives one signature bound to its own session and host key. With a
forwarded agent (`ssh -A`) it can ask for more; each one shows the
forwarding chain and needs its own approval.

## Residual risk

Approving a connection hands a live session to whoever controls the
requesting machine at that moment. A compromised machine can wait for a
legitimate request, or issue its own and hope for a reflexive approval,
and then run anything in the approved session (including through a
multiplexed control socket). This is inherent to any SSH agent. The
feature narrows it to "one approved destination at a time, each one seen
by the user"; it does not remove it. Forced commands, restricted accounts
and a short `ControlPersist` on the server side are outside this project.

## Known weaknesses of the prototype

- **The page is code served on demand.** Whoever controls the origin (or
  its TLS termination) can serve a page that exfiltrates the SSH key at
  the next approval. A native app with a hardware-held key removes this;
  it is the main reason phase 0 is a trial and not a product.
- **The SSH key exists in page memory** for the duration of a signature,
  as an extractable PKCS#8 buffer that is zeroed afterwards on a
  best-effort basis.
- **A synced passkey** extends trust to the account that syncs it. A
  security key as the passkey avoids that; untested on iOS (see
  DESIGN.md, open questions).
- **Host pinning is trust on first use**, decided by a human reading a
  fingerprint on a phone.
- **Storage may be evicted** by the browser, and is erased when the web
  app is removed from the home screen (observed). The key is then lost,
  not leaked; servers must always have another way in.
- **The pairing code travels in a URL fragment** when the QR code is
  used. It is not sent to the server and is removed from the address, but
  it passes through the phone's camera and browser. It works once, for 15
  minutes, and the verification digits still have to match.
- **Metadata**: the relay and the push service (Apple's for the app)
  learn when the user authenticates, and how often.
- **Revocation cuts the channel, not the key.** Either end can delete
  the pairing on the relay (`clavix-agent unpair`, "Oublier cette
  machine"): a lost phone then receives nothing, a decommissioned machine
  can send nothing. The phone's SSH key stays valid on every server that
  lists it until it is removed from `authorized_keys`, and a phone lost
  while the relay is unreachable keeps its pairing until the agent end
  revokes it. With a stolen phone, the passkey's user verification still
  stands between the thief and any signature.
- **Enrolment is open, or one secret is shared** by every agent allowed on
  a relay. Abuse is bounded by per-address and per-channel limits, not by
  identity: there are no accounts to cut off one by one yet.
- Not yet verified on a real device: everything listed under "Needs the
  iPhone" in the README.
