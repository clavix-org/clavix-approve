# Clavix Approve for iOS (phase 3, in progress)

The native signer: the same protocol and relay as the approval page
(`web/`), with the SSH key in the Secure Enclave. Design: `DESIGN.md`,
"Phasing" step 3; messages: `PROTOCOL.md`.

## Layout

| Path | What |
|---|---|
| `ClavixCore/` | Swift package: the protocol, signer side. A line-for-line port of `web/lib` (HPKE, sealed channel, pairing, the checks of a sign request, relay client). No dependency beyond Apple's frameworks. |
| `ClavixApprove/` | The app: keys, state, screens. |
| `ClavixApprove.xcodeproj` | Xcode project; its source folder is synchronised, so new files need no project edit. |

## Keys

| Key | Where | Lock |
|---|---|---|
| SSH key, P-256 (sign mode) | Secure Enclave | biometry as enrolled when the key was made, at every signature; a new enrolment makes it unusable (pair again, install the new key) |
| Approval key, P-256 (approve mode) | Secure Enclave | same, at every approval |
| Channel HPKE key, P-256 | Secure Enclave | none once the device was unlocked after a restart (a request must be decrypted to be shown) |
| Channel Ed25519 key | keychain, this device only | same |
| Pairing record, bearer token | keychain, this device only | same |

The app's SSH key is a new key: install its line (Réglages → Clé SSH) in
`authorized_keys` next to the page's. Pair it as a second device with
`clavix-agent pair --add`; the page stays in service.

## Modes and machines

The app holds one pairing per machine, each in the mode its hello names
(`PROTOCOL.md`, "Approve mode"):

- sign mode, with `clavix-agent`: the iPhone signs with its SSH key;
- approve mode, with Clavix on a computer: the computer keeps its own keys
  and signs once the iPhone has answered with a proof made by the approval
  key. Nothing goes on the servers.

Add a machine with the + button. The pairing code is read from the QR code
(camera) or pasted, as a bare `cva1-…` code or as a link. Pairing again
with the same channel replaces that machine only; Réglages → Machines
appairées forgets one.

To try approve mode without Clavix, against a local relay:

```sh
RELAY_ENROLL_SECRET=dev RELAY_STATE_DIR=/tmp/relay RELAY_PUSH=off python3 relay/relay.py
CLAVIX_ENROLL_SECRET=dev node tools/fake-desktop.mjs pair --relay http://127.0.0.1:8765 --state /tmp/desktop.json
node tools/fake-desktop.mjs request --state /tmp/desktop.json --key-type rsa
```

On the simulator there is no Secure Enclave: software keys stand in, and
the app says so on screen. Signing for real needs an iPhone.

## Tests

```sh
swift test --package-path ios/ClavixCore
```

Against the page's own modules, in both directions (needs Node 22):

```sh
node tools/ios-interop.mjs make /tmp/js.json
CLAVIX_JS_VECTORS=/tmp/js.json CLAVIX_SWIFT_OUT=/tmp/swift.json swift test --package-path ios/ClavixCore
node tools/ios-interop.mjs check /tmp/js.json /tmp/swift.json
```

CI runs both on macOS (`.github/workflows/ci.yml`, job `ios`).

## Building on a device

1. Xcode → Settings → Accounts: the developer account.
2. Copy `ios/Local.xcconfig.example` to `ios/Local.xcconfig` and put the
   team ID in it. Signing settings live there, out of the repository: do
   not pick the team in Xcode's Signing & Capabilities tab, which would
   write it into the project file.
   With a free Personal Team, also uncomment the two lines that switch to
   `org.clavix.approve.personal` without push: an app ID taken by a free
   team could block the real one for the paid team later.
3. Connect the iPhone, enable Developer Mode on it, Run.

## Wake-up

The app registers for Apple push notifications and sends its device token
to the relay with `POST /api/ch/{ch}/subscription`, body
`{"apns": "<lowercase hex token>", "sandbox": true|false}` (`sandbox` for
a development build). A relay without an APNs key answers
`{"state": "unsupported"}`: the app notes it in its journal and shows
requests only while it is open. The push is content-free, as for the page,
and time-sensitive (entitlement in `ClavixApprove.entitlements`).

## Not done yet

- A notification extension that would show the destination on the lock
  screen.
- The paid team, hence push on the real bundle id (`org.clavix.approve`).
