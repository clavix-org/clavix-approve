# Protocol (version 1, prototype)

How the three parts talk: the **agent** (key-less, on the machine that
needs SSH), the **signer** (the approval page; holds the SSH key) and the
**relay** (carries opaque messages, sends the wake-up push, serves the
page). Design rationale is in [`DESIGN.md`](DESIGN.md); what each part can
and cannot do to the others is in [`THREAT_MODEL.md`](THREAT_MODEL.md).

Implementations: `agent/src/{channel,pairing,relay}.rs` and
`web/lib/{channel,pairing,protocol,signer}.js`. They are kept in step by
shared vectors in `testdata/` and by end-to-end tests that run both.

Notation: `b64u` is base64url without padding; `string(x)` is the SSH
encoding (4-byte big-endian length, then the bytes); `||` concatenates.

## Keys

| Key | Held by | Use |
|---|---|---|
| SSH key, ECDSA P-256 | signer, wrapped under a passkey's PRF secret | signs the SSH login |
| HPKE key, P-256 | each side, one each | messages are encrypted to it |
| Ed25519 key | each side, one each | signs the messages it sends |
| Bearer tokens | agent, signer | authenticate to the relay, which stores their SHA-256 |

The agent's keys sit in its state file (mode 0600). The signer's HPKE and
Ed25519 keys are non-extractable `CryptoKey` objects in IndexedDB: the
page can use them before any user verification (it must decrypt a request
to display it) but cannot read them. Only the SSH key needs the passkey.

The SSH key is stored as `AES-256-GCM(key = HKDF-SHA256(PRF secret, salt =
32 zero bytes, info = "clavix-approve/v1/key-wrap"), aad = SSH public key
blob, plaintext = PKCS#8)`. The PRF input is
`"clavix-approve/v1/ssh-key"`. Any passkey with PRF support and user
verification works; nothing assumes a platform authenticator.

## The sealed channel

Every message between agent and signer, after pairing:

```
msg       = b64u( signature(64) || enc(65) || ciphertext )
enc, ciphertext = HPKE-Seal(recipient HPKE key, info, aad = header, JSON)
info      = "clavix-approve/v1 hpke" || sender Ed25519 key(32) || recipient HPKE key(65)
signature = Ed25519( "clavix-approve/v1 sig" || string(header) || string(enc) || string(ciphertext) )
```

HPKE is RFC 9180, base mode, single-shot, suite DHKEM(P-256, HKDF-SHA256)
/ HKDF-SHA256 / AES-128-GCM. The receiver verifies the signature under
the peer key recorded at pairing, then opens.

The header binds what the relay sees and could alter:

```
header = string("clavix-approve/v1") || string(kind) || string(field)…

request   kind "request",  fields: channel, signer id, request id, expiry (decimal seconds)
response  kind "response", fields: channel, signer id, request id
pairing   kind "pair",     fields: channel, signer id
```

## Pairing

In person, once. The agent shows a **pairing code**:

```
"cva1-" || b64u( channel id(16) || pairing secret(16) )
```

The agent also prints it as a QR code of `<relay URL>/#<code>`. The page
takes a code found in its address fragment, removes it from the address,
and fills the pairing field — or, when opened where no key exists (the
browser rather than the installed app), only offers to copy it.

Two values are derived from the secret with HKDF-SHA256 (no salt):
`info = "clavix-approve/v1/relay-pair"` gives the token the relay sees;
`info = "clavix-approve/v1/pair-mac"` gives a MAC key the relay never
sees.

1. Agent → relay, `POST /api/channels` (relay enrolment secret): channel
   id, SHA-256 of its own token and of the pairing token, and a `hello`:
   `b64u(JSON { label, kem, sig, mac })` with
   `mac = HMAC-SHA256(mac key, string("hello") || string(channel) || string(kem) || string(sig) || string(label))`.
2. Signer, given the code: fetches the hello with the pairing token and
   checks its MAC — the relay cannot substitute its own keys.
3. Signer → relay, `POST …/pair`: a signer id, the SHA-256 of its new
   token, and `b64u( signer Ed25519 key(32) || sealed message )` with
   header kind `pair` and content
   `{ t: "pair", key, comment, kem, mac }`,
   `mac = HMAC-SHA256(mac key, string("answer") || string(channel) || string(signer id) || string(signer kem) || string(signer sig) || string(SSH key blob) || string(agent kem) || string(agent sig))`.
   The pairing token works once.
4. Agent: opens it with the key in front, checks the MAC, accepts only an
   `ecdsa-sha2-nistp256` key.
5. Both display **six digits**: the first four bytes of
   `SHA-256(string("clavix-approve/v1/fingerprint") || string(agent kem) || string(agent sig) || string(signer kem) || string(signer sig) || string(SSH key blob))`
   as a big-endian integer modulo 10⁶. The agent saves the pairing only
   after the user confirms they match.

## Sign request (agent → signer)

Relay envelope: `{ id, to, exp, msg }` — `id` 32 hex digits, `to` the
signer id, `exp` an integer Unix time. `msg` is sealed and contains:

```
{ t: "sign", id, iat, exp,
  key:   b64u(SSH public key blob that must sign),
  data:  b64u(bytes to sign),
  flags: agent sign-request flags,
  binds: [ { hostkey, sid, sig, fwd } … ],   outermost first, raw session-bind material
  caller: { pid, name } | null,               unverified
  agent:  label of the machine,               unverified
  hints:  { "SHA256:…": name from known_hosts }   unverified }
```

The agent only sends a request whose `data` is a public-key user-auth
request for the session its connection is bound to. The signer trusts
none of that and checks again, from the message alone:

1. `data` parses as `SSH_MSG_USERAUTH_REQUEST`, method `publickey` or
   `publickey-hostbound-v00@openssh.com`, service `ssh-connection`,
   algorithm `ecdsa-sha2-nistp256`, made with its own key;
2. there are 1 to 16 binds; each `sig` verifies as the signature of
   `sid` under `hostkey` (Ed25519, ECDSA P-256/384/521, RSA with SHA-2);
   all but the last are forwarding binds, the last is not;
3. the session id in `data` is the last bind's, and the host key named by
   a host-bound request is the last bind's;
4. `id` is the relay's, `exp` is in the future.

It then shows the user name taken from `data`, and the last host key
under the name **the signer itself** pinned for it — or as an unknown host
with its fingerprint. Approving an unknown host requires naming it; the
name is pinned only after the passkey verification succeeds.

## Response (signer → agent)

Sealed, header kind `response`:

```
{ t: "signed", id, req, sig: b64u(SSH signature blob) }
{ t: "denied", id, req, reason: "user" | "unverified" | "unknown-key" | "expired" | "malformed" }
```

`req` is `b64u(SHA-256(msg of the request, as received))`. `sig` is a
complete SSH signature (`string(algorithm) || string(blob)`), so the
format does not assume ECDSA. The agent checks `id` and `req`, verifies
the signature against the public key, and only then answers its client. A
request that fails to open gets no response at all.

## Relay API

Same origin as the page. JSON bodies, bearer tokens in `Authorization`.

| Method and path | Token | Purpose |
|---|---|---|
| `POST /api/channels` | enrolment secret | create a channel |
| `GET /api/ch/{ch}/pair` | pairing | fetch the hello |
| `POST /api/ch/{ch}/pair` | pairing | enrol the signer (once) |
| `GET /api/ch/{ch}/pair/answer?wait=` | agent | fetch the signer's answer |
| `POST /api/ch/{ch}/subscription` | signer | store the push subscription |
| `POST /api/ch/{ch}/requests` | agent | queue a request, send the push |
| `GET /api/ch/{ch}/requests?wait=&known=` | signer | pending requests |
| `POST /api/ch/{ch}/responses/{id}` | signer | answer a request |
| `GET /api/ch/{ch}/responses/{id}?wait=` | agent | fetch the answer |
| `POST /api/ch/{ch}/pair/open` | agent | let one more device pair |
| `POST /api/ch/{ch}/requests/{id}/cancel` | agent | withdraw a request (body `{}`) |
| `POST /api/ch/{ch}/revoke` | agent or signer | revoke the pairing or one device |
| `GET /api/vapid-public-key`, `GET /healthz` | none | |

`wait` is a long-poll in seconds, capped at 25 and at the request's
expiry. `known` is the comma-separated list of request ids the signer
already holds (possibly empty): the relay then answers only when the
pending set differs from it, so a request that stays on screen does not
make the long-poll return in a loop. "Nothing yet" is `204`. Normal outcomes are `200` with a `state`
(`queued`, `busy`, `duplicate`, `expired`, `unknown`, `accepted`, …);
`401` and `400` mean a wrong token or a malformed call and are never
retried by a client. `429` and `5xx` (from the relay or a proxy in front,
whose body may be HTML) are retried with a growing pause. The page starts
at most one call every 350 ms, whatever triggers it. Limits: 64 KiB per body, 8 pending requests per
channel, 300 s maximum lifetime, 15 minutes to complete a pairing.

The push is VAPID-signed, `aes128gcm`-encrypted, and its payload is the
constant `{"t":"sign"}`: the notification says only that a request waits.

## Several devices

A channel holds up to four signers, each with its own SSH key. To add one,
the agent sends `POST /api/ch/{ch}/pair/open` with its own token and body
`{ pair_auth, hello }`: the SHA-256 of a fresh pairing token and a new
hello, exactly as when creating a channel. The pairing code then names the
same channel with the new secret, and the rest of "Pairing" applies as is:
same agent keys, same 15-minute window, the secret works once. The relay
answers `full` when the channel already has four signers.

The agent offers every device's key to `ssh`, in its own order
(`clavix-agent devices`, `--first ID`). A sign request goes to the device
whose key `ssh` chose; only that device can sign it. When it does not
answer, `ssh` moves on to the next key once the agent fails the request:
at the expiry, or sooner with the **pickup** rule below. A denial makes
every request fail for 5 seconds, so the next key fails too: refusing on
one device refuses the login.

Pickup: with more than one device, the agent polls for the answer with
`GET …/responses/{id}?seen=1`. "Nothing yet" is then `200 {"state":
"pending", "seen": bool}`, `seen` telling whether the device has fetched
the request. If it has not after `--pickup` seconds (default 20), the
agent withdraws the request with `POST …/requests/{id}/cancel` (the device
no longer receives it; a late answer gets `expired`) and fails it, so that
`ssh` tries the next key at once instead of after the full timeout.

## Revocation

`POST /api/ch/{ch}/revoke` revokes, with the caller's own token:

| Token | Body | Revokes |
|---|---|---|
| agent | `{}` | the whole channel |
| agent | `{"signer": id}` | that device (`unknown-signer` if it is not there) |
| signer | `{}` | the calling device |

What goes with a device: its push subscription and the requests addressed
to it. A channel left without any device goes too. Long-polls on what was
revoked return `401`. It is a `POST` rather than a `DELETE` so that a proxy
allowing only `GET`, `POST` and `HEAD` lets it through. The answer is
`200 {"state": "revoked"}`; a channel that no longer exists answers `401`,
like a wrong token, so the relay does not tell who asks whether a channel
exists. A client therefore takes `401` on revocation as "already revoked".

- `clavix-agent unpair` revokes the whole pairing, `unpair --device ID`
  one device; then it updates its state file. When the relay cannot be
  reached it changes nothing, unless given `--local-only`. `clavix-agent
  pair` (without `--add`) revokes the pairing it replaces, once the new
  one is confirmed (best effort).
- The page's "Oublier cette machine" revokes this device, then forgets the
  pairing, keeping the SSH key and the pinned hosts; pairing again from
  the page revokes the replaced pairing (best effort). On a `401` while
  long-polling it says the machine was removed, and does not forget the
  pairing by itself: a proxy that dropped the `Authorization` header would
  otherwise erase it.

Revocation cuts the channel, not the key: a revoked device's SSH key still
opens every server whose `authorized_keys` lists it. Both ends say so.

## Approve mode

Format fixed, not implemented yet. In approve mode the requester holds
the SSH key and the signer only approves: it returns a signed "yes" that
the requester checks before signing with its own key. It is meant for
Clavix desktop ([`DESKTOP_APPROVAL.md`](DESKTOP_APPROVAL.md)), which takes
the agent's place on its own channel; "requester" below is that agent.
Everything not stated here is as in sign mode: sealed channel, relay API,
several devices, revocation.

A channel is in one mode for good, set at pairing; every device on it is
in that mode.

### Approval key

| Key | Held by | Use |
|---|---|---|
| Approval key, `ssh-ed25519` or `ecdsa-sha2-nistp256` | signer, usable only after user verification | signs approvals |

It is a key of its own: neither the SSH key of sign mode nor the
signer's Ed25519 identity key, which signs every sealed message and is
usable without user verification (an approval signed with it would prove
that the signer ran, not that the user verified). On the wire it is an
SSH public key blob, and a proof is an SSH signature blob, so both ends
reuse their SSH code and the format names its algorithm.

- The page holds an Ed25519 key, wrapped like the SSH key with
  `info = "clavix-approve/v1/approve-key-wrap"` and `aad` = its SSH
  public key blob; the PRF input is the same, so one user verification
  unlocks it.
- A native app may hold a P-256 key in a secure element (the iPhone's
  Secure Enclave offers only P-256), behind its own biometric control.

The requester accepts no other key type.

### Pairing in approve mode

As in "Pairing", with three changes, each one also changing a label so
that what the relay could flip is covered by a MAC or by the digits:

1. The hello gains `mode: "approve"`, and its MAC uses the label
   `"approve-hello"` in place of `"hello"`:
   `HMAC-SHA256(mac key, string("approve-hello") || string(channel) || string(kem) || string(sig) || string(label))`.
   A signer that does not know approve mode checks the `"hello"` MAC,
   which fails: it refuses the code instead of pairing in the wrong mode.
   A relay that strips or adds `mode` breaks the MAC the same way.
2. The signer's answer is `{ t: "pair", approve, comment, kem, mac }`,
   with `approve` = `b64u(approval key's SSH public key blob)` and no
   `key`. Its MAC is
   `HMAC-SHA256(mac key, string("approve-answer") || string(channel) || string(signer id) || string(signer kem) || string(signer sig) || string(approve blob) || string(agent kem) || string(agent sig))`.
   The requester accepts only an answer with `approve`, of an accepted
   type, under this MAC. A sign-mode agent finds no `key` and refuses it.
3. The six digits are the first four bytes of
   `SHA-256(string("clavix-approve/v1/approve-fingerprint") || string(agent kem) || string(agent sig) || string(signer kem) || string(signer sig) || string(approve blob))`
   as a big-endian integer modulo 10⁶.

`channel`, `signer id` and `label` are, as in sign mode, the bytes of
their text (the ids in lowercase hex). Adding a device
(`POST …/pair/open`) sends an approve-mode hello.

### Approval request (requester → signer)

Relay envelope and header as for a sign request (header kind `request`:
the relay does not learn the mode). Content:

```
{ t: "approve", id, iat, exp,
  key:     b64u(SSH public key blob the requester would sign with),
  keyName: key comment,                          unverified
  data:    b64u(bytes the requester would sign),
  flags, binds, caller, agent, hints }           as in a sign request
```

**Telling requests apart.** Every request content carries `t`: `"sign"`
in sign mode (it always has), `"approve"` here. A signer acts only on the
`t` of the mode it was paired in, and answers any other request with
`denied`, reason `malformed`, as signers already do for anything but
`"sign"`. A requester sends `"approve"` only on an approve-mode channel.

The signer checks it as a sign request ("Sign request", steps 1 to 4),
except that in step 1 the user-auth request must be made with the key
named in `key`, not with a key of its own, and may use `ssh-ed25519`,
`ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`,
`rsa-sha2-256` or `rsa-sha2-512`, the algorithm matching the key. It
shows the destination as in sign mode, and the key's comment and
fingerprint labelled as reported by the requester.

### Approval response (signer → requester)

Sealed, header kind `response`:

```
{ t: "approved", id, req, proof: b64u(SSH signature blob) }
{ t: "denied",   id, req, reason }               as in sign mode
```

`req` is the same in both modes:
`b64u(SHA-256(the request's msg))`, where the hashed bytes are the `msg`
field exactly as the relay lists it, that is the base64url text itself
(ASCII), not the bytes it decodes to. The requester hashes the `msg` it
posted.

`proof` is a complete SSH signature, `string(algorithm) || string(blob)`,
made with the approval key over

```
"clavix-approve/v1 approve" || string(channel) || string(signer id) || string(id) || string(digest)
```

where the first 25 bytes are that ASCII text with no length in front,
`channel`, `signer id` and `id` are the bytes of their lowercase hex text,
and `digest` is the 32 raw bytes of the SHA-256 above (not its base64url
form). For `ssh-ed25519` the blob is the Ed25519 signature of those bytes
(RFC 8709); for `ecdsa-sha2-nistp256` it is `mpint(r) || mpint(s)` of an
ECDSA P-256 signature over their SHA-256 (RFC 5656). Since the digest
covers the whole request, the proof names the data, key and bindings
that were shown.

The bare prefix keeps a proof apart from what an SSH key signs
elsewhere: a user-auth request starts with `string(session id)`, whose
first four bytes are a small length, and an `SSHSIG` blob with the bytes
`SSHSIG`; a proof starts with `clav`. Neither can be taken for the other.

The requester checks the sealed envelope, `id` and `req` as in sign mode,
then `proof` under the approval key recorded for that signer, and only
then signs. Vectors: `testdata/approve-proof.json`, one per key type,
made by `tools/approve-vectors.mjs` and checked with OpenSSL by
`tools/approve-vectors-check.sh`. An ECDSA signature differs on every run:
verify the vector, do not reproduce it.

### Withdrawing a request

There is no cancel message. When the request is settled elsewhere (the
local dialog answered first, or it timed out), the requester withdraws it
with `POST /api/ch/{ch}/requests/{id}/cancel`, as the pickup rule does.
No new relay entry is created and the signer sends nothing back: the
request leaves the signer's pending list, so its long-poll (whose `known`
no longer matches) returns and it drops the request. An answer posted
meanwhile gets `expired` from the relay; one that got through first is
ignored by the requester, which no longer waits for it. The relay learns
that a request was withdrawn, as it already does with pickup.

Withdrawing a notification already shown by a push service is the
relay's and the app's business, not part of this format.

## Agent behaviour worth knowing

- Default expiry 90 s (`--timeout`), under sshd's `LoginGraceTime`.
- At most 4 requests wait at once; after a denial, requests fail
  immediately for 5 s.
- It contacts the relay only while one of its own requests is pending.
- It logs one line per request: host key fingerprint, outcome, seconds
  waited.
- With several devices, see "Several devices" for the order of the keys
  and the pickup rule.
