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
| `ClavixApprove.storekit` | StoreKit configuration for local testing: the two plans and their free trial. |

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
(the in-app scanner, or the system camera through the `clavix-approve://`
URL scheme declared in `ClavixApprove-Info.plist`) or pasted, as a bare
`cva2-…` code or as the `clavix-approve://pair?relay=…#cva2-…` link. The
app then shows the relay, the machine's name and the mode, and answers
only once the user accepts; any relay but `approve.clavix.org` needs an
extra, explicit step. The new pairing accepts no request until the user
says the machine shows the same six digits. Relays must be https (http
only on a loopback address). Pairing again with the same channel replaces
that machine once confirmed; Réglages → Machines appairées forgets one.

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

## Subscription (hosted relay only)

Machines paired through the hosted relay, `approve.clavix.org`, need a
subscription; machines paired through any other relay never do, and the
app says nothing about it for them. One subscription covers up to 10
machines.

| Product | Period | Introductory offer |
|---|---|---|
| `org.clavix.approve.personal.monthly` | 1 month | free trial, 14 days |
| `org.clavix.approve.personal.yearly` | 1 year | free trial, 14 days |

Both are in one subscription group. App Store Connect sets the prices
(2,99 € and 24,99 € at launch); the app only shows StoreKit's
`displayPrice`.

StoreKit 2 lives in `ClavixApprove/Subscriptions.swift`: it listens to
`Transaction.updates` from launch, reads `Transaction.currentEntitlements`
(and each plan's latest transaction, to tell « Expiré » from « Aucun »),
buys through SwiftUI's `purchase` action, restores with `AppStore.sync()`,
and finishes each verified transaction once taken into account. The
decisions are in ClavixCore (`RelaySubscription.swift`, tested): the status
shown, the purchase in force, and which pairings need its proof.

The app hands the hosted relay the proof, for every confirmed pairing on
it: `POST /api/ch/{ch}/dev/{signer}/entitlement` with the pairing's own
bearer token, body `{"jws": "<Transaction.jwsRepresentation>"}`. The relay
answers:

| Answer | The app |
|---|---|
| `200 {"ok":true,"expires":<unix s>,"required":true}` | covered |
| `200 {"ok":true,"expires":null,"required":false}` | this relay checks no subscription: the machine is never counted nor prompted for (remembered) |
| `402 {"error":"subscription_required","state":"expired"\|"revoked"}` | « Abonnement expiré » / « révoqué » on the machine's card |
| `403 {"error":"machine_limit","limit":10}` | « Non couverte » on the card and in Réglages, with the relay's `limit` |
| `403 {"error":"invalid_transaction","reason":…}` | a journal line (expected for a purchase made with Xcode's StoreKit testing) |
| `401`, `400` | nothing more |

It is sent at launch, after a purchase or a restore, on each transaction
update, when a pairing is confirmed, and again when the app comes to the
front if it did not get through. Only network failures, `429` and `5xx`
are retried, with a growing pause; any other answer stands until the
transaction changes. Approvals never wait for it.

Without a subscription, each hosted pairing is asked once per launch
with an empty proof: a relay that checks no subscription answers
`required: false` without reading it, so the banner does not show for
it; a relay that checks answers `invalid_transaction`.

To try it in Xcode without App Store Connect: the shared scheme
`ClavixApprove` runs with `ClavixApprove.storekit` (Product → Scheme →
Edit Scheme → Run → Options → StoreKit Configuration). Debug → StoreKit →
Manage Transactions shows, refunds and expires the purchases; the file's
editor speeds up renewals. A purchase made this way is signed by Xcode,
not by the App Store: the relay refuses its JWS, which is expected.

## Not done yet

- A notification extension that would show the destination on the lock
  screen.
- The paid team, hence push on the real bundle id (`org.clavix.approve`).
