//! The requester of sign mode: what the key-less agent does, and what
//! Clavix desktop does while its vault is locked.
//!
//! The requester holds no SSH key. Each signature request goes, sealed,
//! through the relay to the paired device holding the requested key, which
//! signs with its own key after the user approved, refuses, or does not
//! answer. PROTOCOL.md, "Sign request", "Response", "Several devices" and
//! "Agent behaviour worth knowing".
//!
//! ```no_run
//! use std::time::Duration;
//! use clavix_approve_core::channel::Identity;
//! use clavix_approve_core::relay::RelayClient;
//! use clavix_approve_core::sign_requester::{SignDevice, SignRequest, SignRequester, DEFAULT_TIMEOUT};
//!
//! # async fn demo(me: Identity, devices: Vec<SignDevice>, data: Vec<u8>) -> Result<(), clavix_approve_core::sign_requester::SignError> {
//! let requester = SignRequester::new(
//!     RelayClient::new("https://approve.example")?,
//!     "channel-id", "agent-token", "my-desktop", me, devices, DEFAULT_TIMEOUT,
//! )?
//! .with_pickup(Duration::from_secs(20));
//! // Offer these keys to `ssh`, in this order.
//! let keys = requester.keys();
//! // For each sign request on one of them:
//! let request = SignRequest::new(keys[0].key_blob.clone(), data);
//! let signature = requester.sign(&request).await?; // an SSH signature blob
//! # let _ = signature; Ok(()) }
//! ```

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::bytes::{b64u, hex, random, unb64u};
use crate::channel::{self, request_header, response_header, Identity, Peer};
use crate::relay::{
    self, state_of, unix_now, RelayClient, RelayError, POLL_SECONDS, RETRY_PAUSE, THROTTLED_PAUSE,
};
pub use crate::requester::{Caller, SessionBind};

/// How long the user has to approve. Must stay under the server's
/// `LoginGraceTime` (120 s by default), which starts before we are asked.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
/// Requests waiting for the user at the same time.
const MAX_IN_FLIGHT: usize = 4;
/// After a denial, further requests fail at once for this long: a tool
/// that retries in a loop must not turn into a stream of notifications.
const BACKOFF_AFTER_DENIAL: Duration = Duration::from_secs(5);
/// After the relay said a subscription is required (HTTP 402), further
/// requests fail at once for this long without asking it again: only the
/// user can fix that, on the phone, and a tool retrying in a loop must not
/// pile up 4xx answers at a proxy that bans on them.
const BACKOFF_AFTER_UNPAID: Duration = Duration::from_secs(30);

/// Why no signature came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The user said no on the device. Further requests fail with
    /// [`SignError::BackingOff`] for 5 seconds.
    Denied,
    /// The device refused to even ask the user (`reason`: its check that
    /// failed, e.g. `unverified`, cleaned for display).
    Refused(String),
    /// Nobody answered in time.
    Expired,
    /// The relay no longer knows this pairing (HTTP 401): revoked from the
    /// device, or the relay lost its state. Pair again.
    Revoked,
    /// The relay no longer knows this device on the channel (forgotten on
    /// the device): it should be unpaired here.
    UnknownDevice(String),
    /// With several devices: `device` did not fetch the request within
    /// `after`, so the request was withdrawn; the next key may be tried.
    NotPickedUp { device: String, after: Duration },
    /// A request was denied less than 5 seconds ago.
    BackingOff,
    /// Too many requests are already waiting for the user.
    Busy,
    /// The relay could not be reached or answered with an error.
    Relay(RelayError),
    /// Bad input (no device holds the key), an unexpected relay answer, or
    /// an answer that is not authentic or not about this request.
    Invalid(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => f.write_str("denied by the signer"),
            Self::Refused(reason) => write!(f, "the signer refused the request ({reason})"),
            Self::Expired => f.write_str("no answer from signer"),
            Self::Revoked => f.write_str("the relay no longer knows this pairing"),
            Self::UnknownDevice(device) => write!(f, "device {device} is no longer paired"),
            Self::NotPickedUp { device, after } => write!(
                f,
                "device {device} did not pick the request up within {} s",
                after.as_secs()
            ),
            Self::BackingOff => f.write_str("a request was just denied; backing off"),
            Self::Busy => f.write_str("too many requests already waiting"),
            Self::Relay(e) => e.fmt(f),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for SignError {}

impl From<RelayError> for SignError {
    fn from(e: RelayError) -> Self {
        match e {
            RelayError::Status(401) => Self::Revoked,
            e => Self::Relay(e),
        }
    }
}

impl From<String> for SignError {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

/// A paired device, as given to [`SignRequester::new`].
pub struct SignDevice {
    /// Signer id on the channel.
    pub id: String,
    /// Its SSH public key, as an `authorized_keys` line.
    pub public_key: String,
    /// Its channel keys, agreed at pairing.
    pub peer: Peer,
}

/// A public key to offer to `ssh`: a paired device's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignKey {
    /// SSH wire-format public key blob.
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// One sign request: what must be signed, and what the device should show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// The SSH public key blob that must sign: one of [`SignRequester::keys`].
    pub key: Vec<u8>,
    /// The bytes to sign (a public-key user-auth request).
    pub data: Vec<u8>,
    /// The agent protocol's signature flags.
    pub flags: u32,
    /// The session bindings, outermost first.
    pub binds: Vec<SessionBind>,
    /// The process that asked, when known. An empty name goes out as
    /// unknown (`null`).
    pub caller: Option<Caller>,
    /// Names for host keys, by `SHA256:…` fingerprint, shown as unverified.
    pub hints: BTreeMap<String, String>,
}

impl SignRequest {
    /// A request with no flags, no binding, no caller and no hint.
    pub fn new(key: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            key,
            data,
            flags: 0,
            binds: Vec::new(),
            caller: None,
            hints: BTreeMap::new(),
        }
    }
}

/// The signature of a sign request, to await: an SSH signature blob
/// (`string algorithm, string blob`).
pub type SignFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, SignError>> + Send>>;

struct DeviceKeys {
    id: String,
    key: SignKey,
    peer: Arc<Peer>,
}

/// Sends each sign request to the device holding the requested key and
/// waits for its answer.
pub struct SignRequester {
    client: RelayClient,
    ch: String,
    token: String,
    label: String,
    /// In the order their keys are offered to `ssh`.
    devices: Vec<DeviceKeys>,
    /// Our channel keys.
    me: Arc<Identity>,
    timeout: Duration,
    /// With more than one device: how long a device may take to fetch a
    /// request before the requester gives up on it, so that `ssh` moves on
    /// to the next key instead of waiting for the full timeout.
    pickup: Option<Duration>,
    slots: Arc<Semaphore>,
    backoff_until: Arc<Mutex<Option<Instant>>>,
    unpaid_until: Arc<Mutex<Option<Instant>>>,
}

impl SignRequester {
    /// `me` holds the requester's channel keys; `devices` the paired
    /// devices, in the order their keys are offered. `timeout`: how long
    /// the user has to approve each request.
    pub fn new(
        client: RelayClient,
        ch: &str,
        token: &str,
        label: &str,
        me: Identity,
        devices: Vec<SignDevice>,
        timeout: Duration,
    ) -> Result<Self, SignError> {
        if devices.is_empty() {
            return Err(SignError::Invalid("no paired device".into()));
        }
        let devices = devices
            .into_iter()
            .map(|d| {
                let key = ssh_key::PublicKey::from_openssh(&d.public_key)
                    .map_err(|e| format!("invalid signer public key: {e}"))?;
                Ok(DeviceKeys {
                    id: d.id,
                    key: SignKey {
                        key_blob: key
                            .to_bytes()
                            .map_err(|e| format!("signer public key: {e}"))?,
                        comment: key.comment().to_string(),
                    },
                    peer: Arc::new(d.peer),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            client,
            ch: ch.to_string(),
            token: token.to_string(),
            label: label.to_string(),
            devices,
            me: Arc::new(me),
            timeout,
            pickup: None,
            slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            backoff_until: Arc::new(Mutex::new(None)),
            unpaid_until: Arc::new(Mutex::new(None)),
        })
    }

    /// Give up on a device that has not fetched a request after `pickup`
    /// (zero: never). Only with more than one device: alone, there is no
    /// other key to fall back on.
    pub fn with_pickup(mut self, pickup: Duration) -> Self {
        self.pickup = (!pickup.is_zero()).then_some(pickup);
        self
    }

    /// The devices' public keys, in the order they are to be offered.
    /// Cheap and local.
    pub fn keys(&self) -> Vec<SignKey> {
        self.devices.iter().map(|d| d.key.clone()).collect()
    }

    /// The pickup delay in force: none with a single device.
    fn pickup(&self) -> Option<Duration> {
        self.pickup.filter(|_| self.devices.len() > 1)
    }

    fn request_body(&self, request: &SignRequest, id: &str, now: u64, exp: u64) -> Value {
        let binds: Vec<Value> = request
            .binds
            .iter()
            .map(|b| {
                json!({
                    "hostkey": b64u(&b.host_key),
                    "sid": b64u(&b.session_id),
                    "sig": b64u(&b.signature),
                    "fwd": b.forwarded,
                })
            })
            .collect();
        let caller = request.caller.as_ref().map(|c| {
            let name = (!c.name.is_empty()).then_some(c.name.as_str());
            json!({ "pid": c.pid, "name": name })
        });
        json!({
            "t": "sign",
            "id": id,
            "iat": now,
            "exp": exp,
            "key": b64u(&request.key),
            "data": b64u(&request.data),
            "flags": request.flags,
            "binds": binds,
            "caller": caller,
            "agent": self.label,
            "hints": request.hints,
        })
    }

    /// Send `request` to the device holding `request.key` and wait for its
    /// signature. The request is prepared, and its deadline set, when this
    /// is called; the relay is contacted only once the future is awaited.
    /// The future needs a Tokio runtime (for its pauses between retries).
    pub fn sign(&self, request: &SignRequest) -> SignFuture {
        let Some(device) = self.devices.iter().find(|d| d.key.key_blob == request.key) else {
            return Box::pin(async {
                Err(SignError::Invalid("no paired device holds this key".into()))
            });
        };
        let pickup = self.pickup();
        let id = hex(&random::<16>());
        let now = unix_now();
        let exp = now + self.timeout.as_secs();
        let sealed = channel::seal(
            &self.me,
            &device.peer,
            &request_header(&self.ch, &device.id, &id, exp),
            &self.request_body(request, &id, now, exp),
        );
        let answer_header = response_header(&self.ch, &device.id, &id);
        let (me, peer) = (self.me.clone(), device.peer.clone());
        let to = device.id.clone();

        let client = self.client.clone();
        let ch = self.ch.clone();
        let token = self.token.clone();
        let base = format!("/api/ch/{}", self.ch);
        let deadline = Instant::now() + self.timeout;
        let slots = self.slots.clone();
        let backoff_until = self.backoff_until.clone();
        let unpaid_until = self.unpaid_until.clone();

        Box::pin(async move {
            let sent = sealed.map_err(SignError::Invalid)?;
            let envelope = json!({ "id": id, "to": to, "exp": exp, "msg": sent });
            if backoff_until
                .lock()
                .unwrap()
                .is_some_and(|until| Instant::now() < until)
            {
                return Err(SignError::BackingOff);
            }
            if unpaid_until
                .lock()
                .unwrap()
                .is_some_and(|until| Instant::now() < until)
            {
                return Err(SignError::Relay(RelayError::SubscriptionRequired));
            }
            let Ok(_slot) = slots.try_acquire_owned() else {
                return Err(SignError::Busy);
            };

            // From here on, giving up for any reason but an answer (local
            // deadline, future dropped because ssh went away or the agent
            // stopped) takes the request off the relay, so that the device
            // stops offering it. Armed before the POST: dropped while it
            // is in flight, the request may have been queued.
            let mut withdraw = WithdrawOnDrop {
                client: client.clone(),
                ch: ch.clone(),
                token: token.clone(),
                id: id.clone(),
                armed: true,
            };
            let queued = match client
                .post(&format!("{base}/requests"), &token, &envelope)
                .await
            {
                Ok(queued) => queued,
                // Not queued (or the relay is unreachable, and so would
                // the cancellation be).
                Err(RelayError::SubscriptionRequired) => {
                    withdraw.disarm();
                    *unpaid_until.lock().unwrap() = Some(Instant::now() + BACKOFF_AFTER_UNPAID);
                    return Err(SignError::Relay(RelayError::SubscriptionRequired));
                }
                Err(e) => {
                    withdraw.disarm();
                    return Err(e.into());
                }
            };
            match state_of(&queued) {
                "queued" => {}
                "unknown-signer" => {
                    withdraw.disarm();
                    return Err(SignError::UnknownDevice(to));
                }
                other => {
                    withdraw.disarm();
                    return Err(SignError::Invalid(format!(
                        "relay did not queue the request ({other})"
                    )));
                }
            }

            let pickup_at = pickup.map(|p| (Instant::now() + p, p));
            let mut seen = false;
            let answer = loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    // Still on the relay: `withdraw` takes it off.
                    return Err(SignError::Expired);
                }
                // Never ask the relay to hold the connection past the expiry.
                let mut wait = (left.as_secs() + 1).min(POLL_SECONDS);
                if let (Some((at, allowed)), false) = (pickup_at, seen) {
                    let until = at.saturating_duration_since(Instant::now());
                    if until.is_zero() {
                        // The device never fetched it: give up, so that
                        // ssh tries the next key, and take it off the relay.
                        withdraw.disarm();
                        let _ = relay::cancel(&client, &ch, &token, &id).await;
                        return Err(SignError::NotPickedUp {
                            device: to,
                            after: allowed,
                        });
                    }
                    wait = wait.min(until.as_secs().max(1));
                }
                let report = if pickup_at.is_some() { "&seen=1" } else { "" };
                let poll = format!("{base}/responses/{id}?wait={wait}{report}");
                let ended = match client.get(&poll, &token).await {
                    Ok(None) => continue,
                    Ok(Some(value)) => match state_of(&value) {
                        "pending" => {
                            seen |= value.get("seen").and_then(Value::as_bool) == Some(true);
                            continue;
                        }
                        "answered" => match value.get("msg").and_then(Value::as_str) {
                            Some(msg) => Ok(msg.to_string()),
                            None => Err(SignError::Invalid("answer without content".into())),
                        },
                        "expired" => Err(SignError::Expired),
                        other => Err(SignError::Invalid(format!(
                            "relay lost the request ({other})"
                        ))),
                    },
                    // Throttled: back off for real, each 429 counts
                    // against us at a proxy that bans.
                    Err(RelayError::Status(429)) => {
                        tokio::time::sleep(THROTTLED_PAUSE).await;
                        continue;
                    }
                    Err(e) if e.is_transient() => {
                        tokio::time::sleep(RETRY_PAUSE).await;
                        continue;
                    }
                    // A refusal (revoked pairing...): cancelling would
                    // only get the same refusal.
                    Err(e) => Err(e.into()),
                };
                // The relay answered, expired or lost the request: nothing
                // left to withdraw.
                withdraw.disarm();
                break ended?;
            };

            // Only the paired device can have produced this.
            let inner = channel::open(&me, &peer, &answer_header, &answer).map_err(|e| {
                SignError::Invalid(format!("unauthentic answer from the relay: {e}"))
            })?;
            let result = read_response(&inner, &id, &sent);
            if result == Err(SignError::Denied) {
                *backoff_until.lock().unwrap() = Some(Instant::now() + BACKOFF_AFTER_DENIAL);
            }
            result
        })
    }
}

/// Takes a queued request off the relay when dropped armed: in a
/// background task, best effort, never blocking the drop. Without a Tokio
/// runtime at drop time nothing is sent, and the request expires on its
/// own.
struct WithdrawOnDrop {
    client: RelayClient,
    ch: String,
    token: String,
    id: String,
    armed: bool,
}

impl WithdrawOnDrop {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WithdrawOnDrop {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            let (ch, token, id) = (
                std::mem::take(&mut self.ch),
                std::mem::take(&mut self.token),
                std::mem::take(&mut self.id),
            );
            runtime.spawn(async move {
                let _ = relay::cancel(&client, &ch, &token, &id).await;
            });
        }
    }
}

/// Read the device's (already opened) answer to the request `id` whose
/// wire form was `sent`.
fn read_response(inner: &Value, id: &str, sent: &str) -> Result<Vec<u8>, SignError> {
    let bad = |what: &str| SignError::Invalid(format!("unusable answer from the signer: {what}"));
    let field = |name: &str| inner.get(name).and_then(Value::as_str);
    // The answer must be for this very request, not a replay of another.
    if field("id") != Some(id) || field("req") != Some(&b64u(&Sha256::digest(sent.as_bytes()))) {
        return Err(bad("it answers another request"));
    }
    match field("t") {
        // A complete SSH signature blob: it names its own algorithm.
        Some("signed") => field("sig")
            .and_then(unb64u)
            .ok_or_else(|| bad("no signature")),
        Some("denied") => match field("reason") {
            Some("user") | None => Err(SignError::Denied),
            Some(reason) => Err(SignError::Refused(
                reason
                    .chars()
                    .filter(char::is_ascii_graphic)
                    .take(24)
                    .collect(),
            )),
        },
        _ => Err(bad("unknown type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_relay;

    fn answer(sent: &str, fields: Value) -> Value {
        let mut inner = json!({ "id": "id-1", "req": b64u(&Sha256::digest(sent.as_bytes())) });
        inner
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        inner
    }

    #[test]
    fn a_signed_answer_yields_the_signature() {
        let msg = answer("sent", json!({ "t": "signed", "sig": b64u(b"signature") }));
        assert_eq!(
            read_response(&msg, "id-1", "sent"),
            Ok(b"signature".to_vec())
        );
    }

    #[test]
    fn a_denial_is_told_apart_from_a_refusal_to_even_ask() {
        let msg = answer("sent", json!({ "t": "denied", "reason": "user" }));
        assert_eq!(read_response(&msg, "id-1", "sent"), Err(SignError::Denied));
        let msg = answer("sent", json!({ "t": "denied" }));
        assert_eq!(read_response(&msg, "id-1", "sent"), Err(SignError::Denied));
        let msg = answer("sent", json!({ "t": "denied", "reason": "unverified" }));
        assert_eq!(
            read_response(&msg, "id-1", "sent"),
            Err(SignError::Refused("unverified".into()))
        );
        // The reason is cleaned for display.
        let msg = answer(
            "sent",
            json!({ "t": "denied", "reason": "bad\n<b> reason" }),
        );
        assert_eq!(
            read_response(&msg, "id-1", "sent"),
            Err(SignError::Refused("bad<b>reason".into()))
        );
    }

    #[test]
    fn an_answer_to_another_request_is_rejected() {
        let msg = answer("sent", json!({ "t": "signed", "sig": b64u(b"s") }));
        assert!(matches!(
            read_response(&msg, "id-2", "sent"),
            Err(SignError::Invalid(_))
        ));
        assert!(matches!(
            read_response(&msg, "id-1", "other"),
            Err(SignError::Invalid(_))
        ));
        let msg = answer("sent", json!({ "t": "signed" }));
        assert!(matches!(
            read_response(&msg, "id-1", "sent"),
            Err(SignError::Invalid(_))
        ));
        // An approve-mode answer is no signature.
        let msg = answer("sent", json!({ "t": "approved", "proof": "AAAA" }));
        assert!(matches!(
            read_response(&msg, "id-1", "sent"),
            Err(SignError::Invalid(_))
        ));
    }

    #[test]
    fn a_401_means_revoked() {
        assert_eq!(SignError::from(RelayError::Status(401)), SignError::Revoked);
        assert_eq!(
            SignError::from(RelayError::Status(403)),
            SignError::Relay(RelayError::Status(403))
        );
    }

    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g phone-a";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAfHh0cGxoZGBcWFRQTEhEQDw4NDAsKCQgHBgUEAwIB phone-b";

    fn device(id: &str, public_key: &str) -> SignDevice {
        let phone = Identity::generate();
        SignDevice {
            id: id.into(),
            public_key: public_key.into(),
            peer: Peer::new(phone.kem_public(), &phone.sig_public()).unwrap(),
        }
    }

    /// A requester whose relay is never reached by these tests (a closed
    /// loopback port, should one be).
    fn requester(devices: Vec<SignDevice>) -> Result<SignRequester, SignError> {
        SignRequester::new(
            RelayClient::new("http://127.0.0.1:9").unwrap(),
            &"ab".repeat(16),
            "token",
            "desk",
            Identity::generate(),
            devices,
            DEFAULT_TIMEOUT,
        )
    }

    #[test]
    fn devices_are_checked_and_offered_in_order() {
        assert_eq!(
            requester(vec![]).err(),
            Some(SignError::Invalid("no paired device".into()))
        );
        assert!(requester(vec![device("01", "not a key")])
            .is_err_and(|e| e.to_string().contains("invalid signer public key")));
        let r = requester(vec![device("01", KEY_B), device("02", KEY_A)]).unwrap();
        let keys = r.keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].comment, "phone-b");
        assert_eq!(keys[1].comment, "phone-a");
        assert_eq!(
            keys[1].key_blob,
            ssh_key::PublicKey::from_openssh(KEY_A)
                .unwrap()
                .to_bytes()
                .unwrap()
        );
    }

    #[test]
    fn pickup_applies_only_with_several_devices() {
        let alone = requester(vec![device("01", KEY_A)]).unwrap();
        assert_eq!(alone.with_pickup(Duration::from_secs(20)).pickup(), None);
        let two = || requester(vec![device("01", KEY_A), device("02", KEY_B)]).unwrap();
        assert_eq!(
            two().with_pickup(Duration::from_secs(20)).pickup(),
            Some(Duration::from_secs(20))
        );
        assert_eq!(two().with_pickup(Duration::ZERO).pickup(), None);
        assert_eq!(two().pickup(), None);
    }

    #[test]
    fn the_request_body_is_the_sign_message() {
        let r = requester(vec![device("01", KEY_A)]).unwrap();
        let mut request = SignRequest::new(b"key".to_vec(), b"data".to_vec());
        request.flags = 4;
        request.binds = vec![
            SessionBind {
                host_key: b"hk1".to_vec(),
                session_id: b"sid1".to_vec(),
                signature: b"sig1".to_vec(),
                forwarded: true,
            },
            SessionBind {
                host_key: b"hk2".to_vec(),
                session_id: b"sid2".to_vec(),
                signature: b"sig2".to_vec(),
                forwarded: false,
            },
        ];
        request.caller = Some(Caller {
            pid: 42,
            name: "ssh".into(),
        });
        request
            .hints
            .insert("SHA256:abc".into(), "build.example".into());
        let body = r.request_body(&request, "id-1", 100, 190);
        assert_eq!(
            body,
            json!({
                "t": "sign", "id": "id-1", "iat": 100, "exp": 190,
                "key": b64u(b"key"), "data": b64u(b"data"), "flags": 4,
                "binds": [
                    { "hostkey": b64u(b"hk1"), "sid": b64u(b"sid1"), "sig": b64u(b"sig1"), "fwd": true },
                    { "hostkey": b64u(b"hk2"), "sid": b64u(b"sid2"), "sig": b64u(b"sig2"), "fwd": false },
                ],
                "caller": { "pid": 42, "name": "ssh" },
                "agent": "desk",
                "hints": { "SHA256:abc": "build.example" },
            })
        );
        // An unknown caller, and a caller whose name is unknown.
        request.caller = None;
        request.hints.clear();
        let body = r.request_body(&request, "id-1", 100, 190);
        assert_eq!(body["caller"], Value::Null);
        assert_eq!(body["hints"], json!({}));
        request.caller = Some(Caller {
            pid: 7,
            name: String::new(),
        });
        let body = r.request_body(&request, "id-1", 100, 190);
        assert_eq!(body["caller"], json!({ "pid": 7, "name": null }));
    }

    #[tokio::test]
    async fn requests_fail_at_once_without_the_relay_when_they_cannot_go() {
        let r = requester(vec![device("01", KEY_A)]).unwrap();
        let key = r.keys()[0].key_blob.clone();
        // No device holds this key.
        assert_eq!(
            r.sign(&SignRequest::new(b"other".to_vec(), vec![])).await,
            Err(SignError::Invalid("no paired device holds this key".into()))
        );
        // Just after a denial.
        *r.backoff_until.lock().unwrap() = Some(Instant::now() + BACKOFF_AFTER_DENIAL);
        assert_eq!(
            r.sign(&SignRequest::new(key.clone(), vec![])).await,
            Err(SignError::BackingOff)
        );
        *r.backoff_until.lock().unwrap() = None;
        // Just after the relay asked for a subscription.
        *r.unpaid_until.lock().unwrap() = Some(Instant::now() + BACKOFF_AFTER_UNPAID);
        assert_eq!(
            r.sign(&SignRequest::new(key.clone(), vec![])).await,
            Err(SignError::Relay(RelayError::SubscriptionRequired))
        );
        *r.unpaid_until.lock().unwrap() = None;
        // All slots taken.
        let held = r.slots.clone().try_acquire_many_owned(MAX_IN_FLIGHT as u32);
        assert!(held.is_ok());
        assert_eq!(
            r.sign(&SignRequest::new(key, vec![])).await,
            Err(SignError::Busy)
        );
    }

    fn requester_on(base: &str, timeout: Duration) -> SignRequester {
        SignRequester::new(
            RelayClient::new(base).unwrap(),
            &"ab".repeat(16),
            "token",
            "desk",
            Identity::generate(),
            vec![device("01", KEY_A)],
            timeout,
        )
        .unwrap()
    }

    /// A stand-in relay that queues every request and keeps it pending
    /// (or, with `expire`, says it expired).
    async fn fake_relay(expire: bool) -> (String, test_relay::Calls) {
        test_relay::serve(move |call| {
            let state = if call.ends_with("/cancel") {
                "cancelled"
            } else if call.starts_with("POST ") {
                "queued"
            } else if expire {
                "expired"
            } else {
                "pending"
            };
            (200, json!({ "state": state }).to_string())
        })
        .await
    }

    /// The relay id of the request, from its first poll.
    fn polled_id(calls: &test_relay::Calls) -> String {
        let calls = calls.lock().unwrap();
        let poll = calls.iter().find(|c| c.starts_with("GET ")).unwrap();
        poll.rsplit('/').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn a_request_given_up_on_is_withdrawn_from_the_relay() {
        let (base, calls) = fake_relay(false).await;
        let r = requester_on(&base, DEFAULT_TIMEOUT);
        let key = r.keys()[0].key_blob.clone();
        let future = r.sign(&SignRequest::new(key, b"data".to_vec()));
        // ssh went away (or the agent stopped) while the phone was asked:
        // the future is dropped.
        let gave_up = tokio::time::timeout(Duration::from_millis(400), future).await;
        assert!(gave_up.is_err());
        let cancel = test_relay::until_cancelled(&calls).await;
        let id = polled_id(&calls);
        assert_eq!(
            cancel,
            vec![format!(
                "POST /api/ch/{}/requests/{id}/cancel",
                "ab".repeat(16)
            )]
        );
    }

    #[tokio::test]
    async fn a_request_past_its_deadline_is_withdrawn_from_the_relay() {
        let (base, calls) = fake_relay(false).await;
        let r = requester_on(&base, Duration::from_secs(1));
        let key = r.keys()[0].key_blob.clone();
        let result = r.sign(&SignRequest::new(key, b"data".to_vec())).await;
        assert_eq!(result, Err(SignError::Expired));
        let cancel = test_relay::until_cancelled(&calls).await;
        assert!(
            cancel.len() == 1 && cancel[0].contains(&polled_id(&calls)),
            "{:?}",
            calls.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn a_request_the_relay_expired_is_not_cancelled_again() {
        let (base, calls) = fake_relay(true).await;
        let r = requester_on(&base, DEFAULT_TIMEOUT);
        let key = r.keys()[0].key_blob.clone();
        let result = r.sign(&SignRequest::new(key, b"data".to_vec())).await;
        assert_eq!(result, Err(SignError::Expired));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            test_relay::cancels(&calls).is_empty(),
            "{:?}",
            calls.lock().unwrap()
        );
    }
}
