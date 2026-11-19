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
| Relay enrolment secret | relay and agent environments | creating channels on the relay (spam, storage) |
| APNs auth key (`.p8`) | relay environment | sending notifications to the app on any device that registered it (spam, false alerts; no request content, no signature) |

## Who is trusted for what

- **The phone and its browser** are trusted completely.
- **The origin that serves the page** is trusted completely, because it
  delivers the code that handles the key. In this prototype that origin
  is the relay's host. See "Known weaknesses".
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
derivation. The secret never travels in a link to a page of the relay:
the QR code is a `clavix-approve://` link that opens the app.

Should the relay learn the secret all the same (a code pasted into the
page it serves, a code shown to the wrong person), the six verification
digits are a real short authentication string (pairing version 2): the
agent commits to a random nonce in its hello and reveals it only after
the device's keys and nonce have reached it, and the digits hash both
key sets, both nonces and the mode. A relay in the middle can no longer
search for keys that give matching digits: it has one chance in a
million per code, and each failed try is a pairing the user refuses. The
digits protect only if the user compares them, at both ends: the agent
saves nothing until the user confirms, and the iPhone app holds a new
pairing unconfirmed — no request read, no push token sent — until the
user confirms there too. Refusing on either end revokes what the relay
holds.

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
5-second silence after each denial, at most 8 queued at the relay, no
"approve all".

### Someone who hands the user a pairing code (phishing)

A QR code or link from an attacker ("re-pair your device") would pair
the phone with the attacker's machine, which could then send genuine
requests under a familiar label. The iPhone app answers nothing before
showing the relay's host, the machine's name (labelled as the machine's
own word) and the mode, and asking the user to accept; any relay other
than the official `approve.clavix.org` takes a second, explicit step
under a warning. The phone sends its public key, and registers its push
token, only after that. An attacker running its machine on the official
relay is not caught by the relay check: the user's judgement of "is this
the machine in front of me" is the last line.

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
- **A code pasted into the page goes to code the relay serves.** The QR
  link opens the native app, never the page, and the page ignores any
  code in its address; but the page itself still runs whatever the relay
  serves, so a hostile relay can read a code typed there. The commitment
  in the digits keeps that from winning the pairing unnoticed; the page
  has no relay check of its own (it is the relay's origin), and holds a
  new pairing aside, unused, until its digits are confirmed.
- **Relay addresses**: the agent, Clavix desktop and the iPhone app accept
  only https, or http to a loopback address, since bearer tokens travel
  in a header.
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
- **The enrolment secret is shared** by every agent allowed on a relay.
- Not yet verified on a real device: everything listed under "Needs the
  iPhone" in the README.
