# clavix-approve

Approve every SSH signature on your phone.

A key-less SSH agent runs on the machine that needs access (a server, a
remote shell, an unattended tool). The private key lives on the phone.
Each signature request shows up as a notification; the phone displays
the destination, asks for the passkey's user verification and signs.

**Status: phase 0 prototype.** The three parts exist and work together
on a development machine; they have not been deployed or tried on a real
phone yet, and nothing here has been audited. Do not rely on it.

- [`DESIGN.md`](DESIGN.md) — problem, architecture, phasing, open questions.
- [`DESKTOP_APPROVAL.md`](DESKTOP_APPROVAL.md) — proposal: approve the Clavix
  desktop agent's confirmations on the phone (not implemented).
- [`PROTOCOL.md`](PROTOCOL.md) — keys, pairing, messages, relay API.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — what each part can do to the
  others, residual risk, known weaknesses of the prototype.
- [`experiments/`](experiments/) — the throwaway code behind the two
  feasibility experiments recorded in the design.

## Layout

| Path | What |
|---|---|
| `core/` | `clavix-approve-core` (Rust library): the sealed channel, pairing in both modes, the relay client, and both requesters: approve mode (Clavix desktop) and sign mode (the agent, and Clavix desktop while its vault is locked) |
| `agent/` | `clavix-agent` (Rust, on `core/`): the SSH agent protocol on a Unix socket, no private key; forwards each signature request to the paired device through the relay |
| `relay/` | the relay (Python, standard library + `cryptography`, plus `httpx[http2]` for APNs): opaque messages, Web Push or APNs wake-up, serves the page |
| `web/` | the approval page (plain ES modules, no build step, no third-party code); `web/lib` holds everything security-relevant |
| `tools/fake-phone.mjs` | command-line stand-in for the phone, running the page's own modules |
| `tools/fake-desktop.mjs` | command-line stand-in for Clavix desktop in approve mode ([`DESKTOP_APPROVAL.md`](DESKTOP_APPROVAL.md)): holds the SSH key, asks the device for an approval |
| `tools/page-e2e.mjs` | drives the real page in headless Chrome with a virtual passkey |
| `tools/approve-e2e.mjs` | approve mode end to end: relay, fake desktop, fake phone |
| `testdata/` | vectors shared by the Rust and JavaScript sides |

## Trying it locally, without a phone

Needs Rust, Python 3 with `cryptography`, Node 22 and OpenSSH.

```sh
# 1. the relay (push disabled)
RELAY_ENROLL_SECRET=dev RELAY_STATE_DIR=./state RELAY_PUSH=off python3 relay/relay.py

# 2. pair: the agent prints a code…
cargo build -p clavix-agent
CLAVIX_ENROLL_SECRET=dev target/debug/clavix-agent pair --relay http://127.0.0.1:8765

# …which the stand-in enters (or the page, at http://localhost:8765)
node tools/fake-phone.mjs pair --relay http://127.0.0.1:8765 --state ./state/phone.json --code cva2-…

# 3. run both, then use ssh with the agent's socket
node tools/fake-phone.mjs run --state ./state/phone.json &
target/debug/clavix-agent run --socket ./state/agent.sock &
ssh -o IdentityAgent=./state/agent.sock user@host
```

The stand-in approves everything and keeps its key in a plain file: it is
a test tool, never give its key access to a real server.

## Tests

```sh
cargo test --workspace                          # channel, pairing, requester, agent, and end to end:
                                                #   ssh → agent → relay → fake phone → sshd
                                                #   requester → relay → fake phone (approve mode)
python3 -m unittest discover -s relay           # relay logic and HTTP
npm test                                        # the page's modules under Node
node tools/approve-e2e.mjs                      # approve mode: relay → fake desktop ↔ fake phone
node tools/page-e2e.mjs                         # the page itself in headless Chrome, both modes
```

The end-to-end tests start a scratch `sshd` on a loopback port and are
skipped when a tool is missing.

## Running the relay

One HTTP service serves the API and the page; put a TLS-terminating
reverse proxy in front. The host name is permanent in practice: the
passkey is bound to it, and nothing else should be served there.

| Variable | |
|---|---|
| `RELAY_ENROLL_SECRET` | required; lets an agent create a channel |
| `RELAY_STATE_DIR` | required; the only directory written to (VAPID key, channels, subscriptions) |
| `RELAY_BIND`, `RELAY_PORT` | default `127.0.0.1`, `8765` |
| `RELAY_VAPID_SUB` | contact sent to the push service, `mailto:` or `https:` |
| `RELAY_PUSH` | `off` logs instead of sending |
| `RELAY_WEB_DIR` | the page, default `../web` |
| `RELAY_APNS_KEY_FILE` | APNs auth key (`.p8`) from the Apple developer account, to wake the iOS app; APNs is off without it |
| `RELAY_APNS_KEY_ID`, `RELAY_APNS_TEAM_ID` | that key's id and the developer team id |
| `RELAY_APNS_TOPIC` | the app's bundle id, default `org.clavix.approve` |

The `Dockerfile` builds an image that runs as an unprivileged user on a
read-only root filesystem, with `/state` as its volume and `GET /healthz`
as health check. Requirements on the proxy: forward `Authorization`,
allow a 25-second response time, leave the service's own
`Content-Security-Policy` and `Permissions-Policy` headers in place, do
not cache.

## Things to know before relying on it

- **Removing the web app from the home screen erases its storage**: the
  encrypted SSH key and the pairing are gone (observed on iOS 18.7). A
  new key must then be created and installed on every server. Changing
  the icon or the label also requires removing it. Keep another way into
  your servers.
- **Revoking a pairing**: `clavix-agent unpair` on the machine (`--device
  ID` for one device), or "Oublier cette machine" on the phone, revokes it
  on the relay; the other end then gets nothing more. The phone's public key must
  still be removed from the servers' `authorized_keys` if the phone is
  lost: the command prints it.
- **Several devices**: `clavix-agent pair --add` pairs one more (four at
  most), each with its own key to install on the servers. The agent offers
  the keys in the order `clavix-agent devices` shows (`--first ID` to
  change it). A device that does not pick a request up within 20 seconds
  (`run --pickup`) is passed over, so `ssh` tries the next one; refusing on
  a device refuses the login.
- **A request left unanswered expires** after 90 seconds and `ssh` fails
  with `agent refused operation`.
- **Pairing with a QR code**: `clavix-agent pair` prints the code, the
  same code as a `clavix-approve://pair?relay=…#cva2-…` link (one line, to
  copy), and a QR code of that link, for the Clavix Approve app. The link
  never points to a page of the relay: the pairing secret must not reach
  code the relay serves. The web page pairs only with a pasted code.
- **Pairing is version 2**: codes start with `cva2-`. Pairings made with
  an earlier version are refused at both ends and must be made again.

## Needs the iPhone

A first trial (iOS 18.7, installed web app, synced passkey) showed that
passkey PRF, Ed25519, non-extractable keys in IndexedDB and Web Push to a
locked phone all work: 29 seconds from `ssh` to login, phone locked at
the start, unknown host to pin. Still open, and what phase 0 is for:

- Web Push delivery over days, in Focus and Low Power modes;
- whether the page's storage survives long idle periods (iOS reports it
  as not guaranteed persistent);
- a security key instead of a synced passkey.

Companion to [Clavix](https://github.com/clavix-org/clavix). Licensed
under GPL-3.0-or-later, like Clavix; the agent's protocol core derives
from Clavix's.
