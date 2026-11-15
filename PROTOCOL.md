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
| `GET /api/ch/{ch}/requests?wait=` | signer | pending requests |
| `POST /api/ch/{ch}/responses/{id}` | signer | answer a request |
| `GET /api/ch/{ch}/responses/{id}?wait=` | agent | fetch the answer |
| `GET /api/vapid-public-key`, `GET /healthz` | none | |

`wait` is a long-poll in seconds, capped at 25 and at the request's
expiry. "Nothing yet" is `204`. Normal outcomes are `200` with a `state`
(`queued`, `busy`, `duplicate`, `expired`, `unknown`, `accepted`, …);
`401` and `400` mean a wrong token or a malformed call and are never
retried by a client. Limits: 64 KiB per body, 8 pending requests per
channel, 300 s maximum lifetime, 15 minutes to complete a pairing.

The push is VAPID-signed, `aes128gcm`-encrypted, and its payload is the
constant `{"t":"sign"}`: the notification says only that a request waits.

## Agent behaviour worth knowing

- Default expiry 90 s (`--timeout`), under sshd's `LoginGraceTime`.
- At most 4 requests wait at once; after a denial, requests fail
  immediately for 5 s.
- It contacts the relay only while one of its own requests is pending.
- Several signers per channel are possible in the format (`to`, signer
  ids); the prototype pairs one.
