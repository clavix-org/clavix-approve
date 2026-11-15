# Experiments

Throwaway code kept as evidence for the two experiments described in
[`../DESIGN.md`](../DESIGN.md). Not a starting point for the product.
Comments and UI strings are in French.

## `sshd-webauthn/` — can a passkey be the SSH key?

Result: sshd accepts it, the stock `ssh` client does not (see "Passkey
experiment" in the design).

- `fake_passkey_agent.py` — SSH agent that exposes one
  `sk-ecdsa-sha2-nistp256@openssh.com` key whose application is a web
  RP ID, and answers sign requests with a browser-shaped WebAuthn
  assertion. `init` prints the public key, `serve` runs the agent
  (`PK_SOCK` overrides the socket path).
- `webauthn_client.py` — paramiko client that names the WebAuthn
  algorithm in the auth request, which the stock client never does.

To reproduce, run a scratch `sshd` on a loopback port with
`PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com`
and the printed key in its `AuthorizedKeysFile`.

Requires `python3-cryptography` and `paramiko`.

## `ios-web-prototype/` — can a home-screen web app do the phone's job?

Result: yes on iOS 18.7 (see "Web prototype experiment").

- `server.py` — serves the page on `127.0.0.1` and sends one test Web
  Push (VAPID + `aes128gcm`, standard library plus
  `python3-cryptography`). `--selftest` checks the encryption offline.
  Put any HTTPS front in front of it; the passkey binds to that host
  name.
- `index.html`, `app.js`, `sw.js`, `manifest.webmanifest` — the page:
  create a passkey with the PRF extension, wrap a P-256 key under the
  PRF secret, sign after Face ID, subscribe to push.
