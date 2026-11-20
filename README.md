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
| `relay/` | the relay (Python, standard library + `cryptography`, plus `httpx[http2]` for APNs): opaque messages, Web Push or APNs wake-up, per-client limits, serves the page (optional) |
| `web/` | the approval page (plain ES modules, no build step, no third-party code); `web/lib` holds everything security-relevant |
| `tools/fake-phone.mjs` | command-line stand-in for the phone, running the page's own modules |
| `tools/fake-desktop.mjs` | command-line stand-in for Clavix desktop in approve mode ([`DESKTOP_APPROVAL.md`](DESKTOP_APPROVAL.md)): holds the SSH key, asks the device for an approval |
| `tools/page-e2e.mjs` | drives the real page in headless Chrome with a virtual passkey |
| `tools/approve-e2e.mjs` | approve mode end to end: relay, fake desktop, fake phone |
| `testdata/` | vectors shared by the Rust and JavaScript sides |

## Trying it locally, without a phone

Needs Rust, Python 3 with `cryptography`, Node 22 and OpenSSH.

```sh
# 1. the relay (push disabled; without the secret, enrolment is open)
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

One HTTP service serves the API and, unless told not to, the page; put a
TLS-terminating reverse proxy in front. When it serves the page, the host
name is permanent in practice: the passkey is bound to it, and nothing
else should be served there. A public relay should not serve the page
(`RELAY_SERVE_WEB=off`): the code that handles keys then lives on an
origin of its own.

| Variable | Default | |
|---|---|---|
| `RELAY_STATE_DIR` | required | the only directory written to (VAPID key, `state.db`) |
| `RELAY_ENROLL_SECRET` | unset | when set, an agent needs it to create a channel (closed enrolment) |
| `RELAY_ENROLL` | after the secret | `open`: anyone may create a channel, any or no secret accepted; `closed`: the secret is required |
| `RELAY_BIND`, `RELAY_PORT` | `127.0.0.1`, `8765` | |
| `RELAY_SERVE_WEB` | `on` | `off` serves the API and `/healthz` only |
| `RELAY_WEB_DIR` | `../web` | the page |
| `RELAY_VAPID_SUB` | `mailto:webpush@example.com` | contact sent to the push service, `mailto:` or `https:` |
| `RELAY_PUSH` | `on` | `off` logs instead of sending |
| `RELAY_APNS_KEY_FILE` | unset | APNs auth key (`.p8`) from the Apple developer account, to wake the iOS app; APNs is off without it |
| `RELAY_APNS_KEY_ID`, `RELAY_APNS_TEAM_ID` | | that key's id and the developer team id |
| `RELAY_APNS_TOPIC` | `org.clavix.approve` | the app's bundle id |

Subscriptions, for a hosted relay that serves paying or trialling users
only. Everything is off by default: a development or self-hosted relay
checks nothing and stays free.

| Variable | Default | |
|---|---|---|
| `RELAY_ENTITLEMENT` | `off` | `on`: a request posted on a channel needs a current subscription linked to it, otherwise `402 {"error":"subscription_required"}`. Creating a channel and pairing stay free |
| `RELAY_APPSTORE_BUNDLE_ID` | `org.clavix.approve` | the app whose App Store transactions are accepted |
| `RELAY_APPSTORE_PRODUCTS` | `org.clavix.approve.personal.monthly,org.clavix.approve.personal.yearly` | comma-separated product ids accepted |
| `RELAY_APPSTORE_SANDBOX` | `off` | `on` also accepts Sandbox transactions (TestFlight builds buy in the Sandbox) |
| `RELAY_MACHINES_PER_SUBSCRIPTION` | `10` | channels (machines) one subscription covers; past it, `403 {"error":"machine_limit"}` |
| `RELAY_ENTITLEMENT_GRACE_HOURS` | `48` | hours requests are still served after the subscription's expiry, for a renewal the phone has not re-sent yet; `0` for none |

The phone sends its StoreKit 2 transaction (`PROTOCOL.md`, "Subscriptions");
the relay verifies it offline against Apple Root CA - G3, which is built
in. With `RELAY_ENTITLEMENT=on` it also takes App Store Server
Notifications v2 at `POST /api/appstore/notifications` (renewal, expiry,
refund, revocation): set that URL in App Store Connect.

Client address, which the per-address limits count against:

| Variable | Default | |
|---|---|---|
| `RELAY_CLIENT_IP_HEADER` | unset | a header the proxy sets to the client address, overwriting the client's own (for example `X-Real-IP`). When set it is the only source; a missing, malformed, private, loopback or link-local value counts as one shared address |
| `RELAY_TRUSTED_PROXIES` | `0` | without the header: how many proxies append to `X-Forwarded-For`, read from the right. `0` uses the TCP peer |

Limits, all positive integers:

| Variable | Default | |
|---|---|---|
| `RELAY_CHANNELS_PER_IP_HOUR`, `RELAY_CHANNELS_PER_IP_DAY` | `10`, `30` | channels one address may create (IPv6 by /64) |
| `RELAY_MAX_CHANNELS` | `100000` | global safety cap; past it, creation answers `full` |
| `RELAY_CHANNEL_IDLE_DAYS` | `90` | a channel unused that long is deleted, paired or not |
| `RELAY_MAX_DEVICES` | `4` | devices on one channel |
| `RELAY_CHANNELS_PER_DEVICE` | `32` | channels one device's push token serves (one phone, that many machines); past it the oldest loses push |
| `RELAY_REQUESTS_PER_MINUTE` | `60` | requests one channel may post |
| `RELAY_MAX_PENDING` | `8` | live requests on one channel (`busy` past it) |
| `RELAY_MAX_ENTRIES` | `32` | requests kept on one channel, answered, cancelled and expired ones included |
| `RELAY_MAX_MSG` | `16384` | bytes of one request or response |
| `RELAY_MAX_BODY` | `32768` | bytes of one HTTP body |
| `RELAY_PENDING_BUDGET` | `67108864` | bytes of request and response data held across all channels (`503` past it) |
| `RELAY_PUSH_INTERVAL`, `RELAY_PUSH_PER_DAY` | `10`, `100` | at most one push per interval, and so many a day, per channel and per device |
| `RELAY_PUSH_WORKERS`, `RELAY_PUSH_QUEUE` | `4`, `1000` | threads sending pushes, and pushes waiting (more are dropped) |
| `RELAY_POLLS_PER_TOKEN`, `RELAY_POLLS_PER_IP` | `8`, `64` | concurrent long-polls |
| `RELAY_MAX_CONNECTIONS` | `512` | concurrent connections; more get an immediate `503` |
| `RELAY_SOCKET_TIMEOUT` | `30` | seconds a client may stay silent in the middle of a request |

A client over a limit gets `429` with `Retry-After`; over the global data
budget, `503` with `Retry-After`. Clients must honour it and back off: a
proxy that bans an address after a burst of 4xx would otherwise ban it. A
channel that was revoked or expired answers `401` to every call; clients
stop polling it (and on `404`). The `429` and `413` a proxy sends may have
an HTML body: clients must not expect JSON on those statuses.

Channels are kept in SQLite (`state.db`, WAL), one row each, with the
subscriptions and which channel uses which; pending requests live in
memory. A `state.json` from an older version is imported
on first start and renamed `state.json.migrated`.

The `Dockerfile` builds an image that runs as an unprivileged user on a
read-only root filesystem, with `/state` as its volume and `GET /healthz`
as health check. Requirements on the proxy: forward `Authorization`,
allow a 25-second response time, leave the service's own
`Content-Security-Policy` and `Permissions-Policy` headers in place, do
not cache, cap request bodies above `RELAY_MAX_BODY`, and set the client
address header (or append to `X-Forwarded-For`) so per-address limits see
real clients. The relay only answers `GET`, `HEAD` and `POST`.

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
