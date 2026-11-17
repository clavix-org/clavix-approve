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
| SSH key, P-256 | Secure Enclave | biometry as enrolled when the key was made, at every signature; a new enrolment makes it unusable (pair again, install the new key) |
| Channel HPKE key, P-256 | Secure Enclave | none once the device was unlocked after a restart (a request must be decrypted to be shown) |
| Channel Ed25519 key | keychain, this device only | same |
| Pairing record, bearer token | keychain, this device only | same |

The app's SSH key is a new key: install its line (Réglages → Clé SSH) in
`authorized_keys` next to the page's. Pair it as a second device with
`clavix-agent pair --add`; the page stays in service.

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

1. Xcode → Settings → Accounts: the paid developer account.
2. Open `ios/ClavixApprove.xcodeproj`, target ClavixApprove → Signing &
   Capabilities: choose the team. Push Notifications is already in the
   entitlements.
3. Connect the iPhone, enable Developer Mode on it, Run.

## Wake-up

The app registers for Apple push notifications and sends its device token
to the relay with `POST /api/ch/{ch}/subscription`, body
`{"apns": "<hex token>", "sandbox": true|false}` (`sandbox` for a
development build). **The relay does not accept that body yet**: it only
knows Web Push. Until it does, the app says so in its journal, and shows
requests only while it is open. The push stays content-free, as for the
page.

## Not done yet

- APNs on the relay (above).
- A notification extension that would show the destination on the lock
  screen.
- Several machines paired at once (the page has one pairing too).
