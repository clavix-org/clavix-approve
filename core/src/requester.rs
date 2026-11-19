//! The requester of approve mode: what Clavix desktop does.
//!
//! The requester holds the SSH key. It pairs with one or more devices like
//! an agent does, with a hello that says `mode: "approve"`, sends them
//! approval requests, and signs only after a proof made with a device's
//! approval key. PROTOCOL.md, "Approve mode"; the JavaScript reference is
//! `web/lib/requester.js`.
//!
//! ```no_run
//! use std::time::Duration;
//! use clavix_approve_core::requester::{ApprovalRequest, ApproveOffer, Outcome, Requester};
//!
//! # async fn demo(key_blob: Vec<u8>, data: Vec<u8>) -> Result<(), clavix_approve_core::requester::Error> {
//! // Once: pair a phone. Show `code()` or `link()`, then the digits.
//! let offer = ApproveOffer::open("https://approve.example", "enrolment-secret", "my-desktop").await?;
//! println!("{}", offer.link());
//! let paired = offer.wait(Duration::from_secs(14 * 60)).await?;
//! println!("same digits on the phone? {}", paired.digits);
//! let channel = offer.into_channel(paired.device); // serde: store it
//!
//! // For each signature the local policy wants confirmed:
//! let requester = Requester::new(&channel)?;
//! let request = ApprovalRequest::new(key_blob, data);
//! let (_withdraw, outcome) = requester.request_approval(&request);
//! // If the local dialog answers first: `requester.withdraw(&request.id)`.
//! match outcome.await? {
//!     Outcome::Approved { .. } => { /* sign with the vault key */ }
//!     Outcome::Denied { .. } | Outcome::Expired | Outcome::Withdrawn => { /* refuse */ }
//! }
//! # Ok(()) }
//! ```
//!
//! ## Behind Clavix's `PhoneApprover`
//!
//! - `approve(req)` → [`Requester::request_approval`]; Clavix's request id
//!   goes in [`ApprovalRequest::id`] (a local id: the crate draws one
//!   random relay id per device), `ttl_s` in `ttl`, `agent` in `agent`,
//!   its binds in [`SessionBind`] (outermost first).
//! - The answer: `Ok(Approved)` → `Approved` (the proof has verified);
//!   `Ok(Denied { reason })` → `Denied(reason)`; `Ok(Expired)`,
//!   `Ok(Withdrawn)` and every `Err` → `Unavailable` (the local dialog
//!   decides). [`Error::Revoked`] means the pairing is gone: pair again.
//! - `withdraw(id)` → [`Requester::withdraw`], synchronous; it cancels
//!   every relay entry of that request in a background task.
//! - `is_paired()` → whether a stored [`ApproveChannel`] with devices
//!   exists; [`Requester::new`] refuses one without.
//! - Pairing: [`ApproveOffer::open`] (`code()`, `link()`), then
//!   [`ApproveOffer::wait`] → digits and the device (its name in
//!   [`ApproveDevice::name`]), then [`ApproveOffer::into_channel`]: the
//!   serde state to store (encrypted: it holds the channel keys).

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signature::Verifier;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::bytes::{b64u, hex, random, unb64u, write_string};
use crate::channel::{self, request_header, response_header, Identity, Peer};
use crate::pairing::{pairing_url, Mode, Offer, PairingError, APPROVE_KEY_TYPES};
use crate::relay::{
    self, state_of, unix_now, RelayClient, RelayError, POLL_SECONDS, RETRY_PAUSE, THROTTLED_PAUSE,
};

/// How long a device has to answer. Must stay under the server's
/// `LoginGraceTime` (120 s by default), which starts before we are asked.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
/// The bare prefix of what an approval key signs.
const APPROVE_PREFIX: &[u8] = b"clavix-approve/v1 approve";

/// What can go wrong, apart from a refusal or an expiry (see [`Outcome`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The relay no longer knows this pairing, or this device: revoked
    /// from the device, or the relay lost its state. Pair again.
    Revoked,
    /// The relay could not be reached or answered something unexpected.
    Relay(RelayError),
    /// Bad input, a corrupt stored channel, or an answer that is not
    /// authentic or not about this request.
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Revoked => write!(f, "the relay no longer knows this pairing"),
            Self::Relay(e) => e.fmt(f),
            Self::Invalid(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for Error {}

impl From<RelayError> for Error {
    fn from(e: RelayError) -> Self {
        match e {
            RelayError::Status(401) => Self::Revoked,
            e => Self::Relay(e),
        }
    }
}

impl From<PairingError> for Error {
    fn from(e: PairingError) -> Self {
        match e {
            PairingError::Relay(e) => e.into(),
            PairingError::Gone => Self::Revoked,
            e => Self::Invalid(e.to_string()),
        }
    }
}

impl From<String> for Error {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

impl From<&str> for Error {
    fn from(reason: &str) -> Self {
        Self::Invalid(reason.to_string())
    }
}

/// An approve-mode pairing, to be stored by the application (it holds the
/// requester's channel keys: keep it private). No SSH key in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveChannel {
    /// Base URL of the relay.
    pub relay: String,
    /// Channel id (32 hex digits).
    pub ch: String,
    /// Our bearer token on the channel.
    pub token: String,
    /// Name of this machine, as the device shows it.
    pub label: String,
    /// Our channel keys (base64url): HPKE private key and Ed25519 seed.
    pub kem_private: String,
    pub sig_private: String,
    /// The paired devices.
    pub devices: Vec<ApproveDevice>,
}

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveDevice {
    /// Signer id on the channel (16 hex digits).
    pub id: String,
    /// Its approval key, as an OpenSSH public key line (`ssh-ed25519 …
    /// name` or `ecdsa-sha2-nistp256 … name`). It never goes on a server.
    pub approve_key: String,
    /// Its channel keys (base64url): HPKE public key and Ed25519 key.
    pub kem_public: String,
    pub sig_public: String,
}

impl ApproveDevice {
    /// The name the device gave itself.
    pub fn name(&self) -> &str {
        self.approve_key.splitn(3, ' ').nth(2).unwrap_or("")
    }
}

fn identity_of(channel: &ApproveChannel) -> Result<Identity, Error> {
    let field = |b64: &str| unb64u(b64).ok_or("corrupt channel: bad base64");
    Ok(Identity::from_secrets(
        &field(&channel.kem_private)?,
        &field(&channel.sig_private)?,
    )?)
}

impl ApproveChannel {
    /// Revoke one device on the relay and forget it here. `Ok(true)` when
    /// the relay removed it, `Ok(false)` when it no longer knew it; either
    /// way it is gone from `devices`.
    pub async fn forget_device(&mut self, id: &str) -> Result<bool, Error> {
        let client = RelayClient::new(&self.relay)?;
        let removed = relay::revoke_device(&client, &self.ch, &self.token, id).await?;
        self.devices.retain(|d| d.id != id);
        Ok(removed)
    }

    /// Revoke the whole pairing on the relay. `Ok(false)` when the relay no
    /// longer knew it. The caller then deletes what it stored.
    pub async fn revoke(&self) -> Result<bool, Error> {
        let client = RelayClient::new(&self.relay)?;
        Ok(relay::revoke(&client, &self.ch, &self.token).await?)
    }
}

/// A pairing in progress: the channel is open on the relay, its code is
/// to be shown to the user.
pub struct ApproveOffer {
    offer: Offer,
    client: RelayClient,
    label: String,
}

/// A device that answered the code, not trusted yet: the user must see
/// the same digits on it.
#[derive(Debug, Clone)]
pub struct PairedDevice {
    /// Six digits, e.g. "042 917", to compare with the device's display.
    pub digits: String,
    /// To keep once the user confirmed the digits.
    pub device: ApproveDevice,
}

impl ApproveOffer {
    /// Open a new approve-mode channel. `enroll_secret` is the relay's
    /// admission secret; `label` names this machine on the device.
    pub async fn open(relay: &str, enroll_secret: &str, label: &str) -> Result<Self, Error> {
        let client = RelayClient::new(relay)?;
        let offer = Offer::new_in(Mode::Approve);
        offer.open(&client, enroll_secret, label).await?;
        Ok(Self {
            offer,
            client,
            label: label.to_string(),
        })
    }

    /// Open the existing `channel` to one more device. Once paired, push
    /// the new device onto `channel.devices`.
    pub async fn add_device(channel: &ApproveChannel) -> Result<Self, Error> {
        let client = RelayClient::new(&channel.relay)?;
        let offer = Offer::for_existing(
            &channel.ch,
            &channel.token,
            identity_of(channel)?,
            Mode::Approve,
        )?;
        offer.open_on_channel(&client, &channel.label).await?;
        Ok(Self {
            offer,
            client,
            label: channel.label.clone(),
        })
    }

    /// The code to enter on the device (valid 15 minutes, works once).
    pub fn code(&self) -> &str {
        &self.offer.code
    }

    /// The code as a `clavix-approve://pair?relay=…#code` link, for a QR
    /// code or to copy: it opens the Clavix Approve app, which then needs
    /// no relay typed in. Never show the code as a link to a web page.
    pub fn link(&self) -> String {
        pairing_url(self.client.base(), &self.offer.code)
    }

    /// Wait for a device to answer, at most `max` (the relay keeps an
    /// unanswered code 15 minutes). Once the answer is authenticated, our
    /// nonce is revealed to the device, which then shows its digits.
    /// If the user says the digits differ, revoke the device
    /// ([`ApproveChannel::revoke`] or the relay's revoke call) rather than
    /// just dropping it.
    pub async fn wait(&self, max: Duration) -> Result<PairedDevice, Error> {
        let answer = self.offer.wait_for_answer(&self.client, max).await?;
        Ok(PairedDevice {
            digits: answer.fingerprint.clone(),
            device: ApproveDevice {
                approve_key: answer.public_key_line()?,
                kem_public: b64u(answer.peer.kem_public()),
                sig_public: b64u(&answer.peer.sig_public()),
                id: answer.id,
            },
        })
    }

    /// The new channel, with its first device (after the user confirmed
    /// the digits). Not for an offer made by [`ApproveOffer::add_device`].
    pub fn into_channel(self, first: ApproveDevice) -> ApproveChannel {
        let (kem_private, sig_private) = self.offer.identity.secrets();
        ApproveChannel {
            relay: self.client.base().to_string(),
            ch: self.offer.ch,
            token: self.offer.agent_token,
            label: self.label,
            kem_private: b64u(&kem_private),
            sig_private: b64u(&sig_private),
            devices: vec![first],
        }
    }
}

/// One session binding (OpenSSH `session-bind@openssh.com`), as received
/// from the SSH client: the host key, the session id, the host's signature
/// of it, and whether the agent was forwarded there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBind {
    pub host_key: Vec<u8>,
    pub session_id: Vec<u8>,
    pub signature: Vec<u8>,
    pub forwarded: bool,
}

/// The process that asked for the signature, when known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    pub name: String,
}

/// What the requester would sign, and what the device should show. The
/// device checks `data` as an SSH login made with `key`, bound to the
/// sessions in `binds`, and refuses anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The caller's own id for this request (any text, e.g. 32 hex
    /// digits), to withdraw it with [`Requester::withdraw`]. It is local:
    /// it never reaches the relay, which gets a random id per device.
    pub id: String,
    /// How long the devices have to answer (default 90 s; must stay under
    /// the server's `LoginGraceTime`).
    pub ttl: Duration,
    /// The machine's name as the device shows it; `None`: the channel's
    /// label.
    pub agent: Option<String>,
    /// The SSH public key blob the requester would sign with.
    pub key: Vec<u8>,
    /// Its name, shown as reported (unverified).
    pub key_name: String,
    /// The bytes the requester would sign.
    pub data: Vec<u8>,
    /// The agent protocol's signature flags.
    pub flags: u32,
    /// The session bindings, outermost first.
    pub binds: Vec<SessionBind>,
    pub caller: Option<Caller>,
    /// Names for host keys, by `SHA256:…` fingerprint, shown as unverified.
    pub hints: BTreeMap<String, String>,
}

impl ApprovalRequest {
    /// A request with a random local id, the default time to answer, and
    /// nothing to show but the login itself.
    pub fn new(key: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            id: hex(&random::<16>()),
            ttl: DEFAULT_TIMEOUT,
            agent: None,
            key,
            key_name: String::new(),
            data,
            flags: 0,
            binds: Vec::new(),
            caller: None,
            hints: BTreeMap::new(),
        }
    }
}

/// How an approval request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A device approved, with a proof that verifies under its approval
    /// key: the requester may sign now.
    Approved { device: String },
    /// A device refused (`reason` is `user` for a tap on "refuse", or the
    /// device's check that failed). A refusal from any device is final.
    Denied { device: String, reason: String },
    /// No device answered in time.
    Expired,
    /// Withdrawn with [`Withdraw::withdraw`] before any device answered.
    Withdrawn,
}

/// A request in flight: its withdrawal signal, and the relay ids it was
/// sent under (one per device).
struct Pending {
    signal: watch::Sender<bool>,
    relay_ids: Mutex<Vec<String>>,
}

/// Withdraws a pending approval request (the local dialog answered
/// first): the devices drop it, and the outcome becomes `Withdrawn`.
/// Same as [`Requester::withdraw`] with the request's id.
#[derive(Clone)]
pub struct Withdraw {
    pending: Arc<Pending>,
    requester: Requester,
}

impl Withdraw {
    /// Synchronous: signals the request's future, and takes the request
    /// off the relay in a background task (when called inside a Tokio
    /// runtime), even if nobody awaits the future any more.
    pub fn withdraw(&self) {
        self.requester.withdraw_pending(&self.pending);
    }
}

/// The outcome of an approval request, to await.
pub type ApprovalFuture = Pin<Box<dyn Future<Output = Result<Outcome, Error>> + Send>>;

struct DeviceKeys {
    id: String,
    peer: Peer,
    approve: ssh_key::PublicKey,
}

/// Sends approval requests to the paired devices.
#[derive(Clone)]
pub struct Requester {
    client: RelayClient,
    ch: String,
    token: String,
    label: String,
    me: Arc<Identity>,
    devices: Arc<Vec<DeviceKeys>>,
    /// Requests in flight, by the caller's id.
    pending: Arc<Mutex<HashMap<String, Arc<Pending>>>>,
}

/// How one device's request ended.
enum DeviceEnd {
    Approved,
    Denied(String),
    Expired,
    Failed(Error),
}

impl Requester {
    pub fn new(channel: &ApproveChannel) -> Result<Self, Error> {
        if channel.devices.is_empty() {
            return Err("no paired device".into());
        }
        let devices = channel
            .devices
            .iter()
            .map(|d| {
                let approve = ssh_key::PublicKey::from_openssh(&d.approve_key)
                    .map_err(|e| format!("invalid approval key: {e}"))?;
                if !APPROVE_KEY_TYPES.contains(&approve.algorithm().as_str()) {
                    return Err(Error::from("unsupported approval key type"));
                }
                let bytes = |b64: &str| unb64u(b64).ok_or("corrupt channel: bad base64");
                Ok(DeviceKeys {
                    id: d.id.clone(),
                    peer: Peer::new(&bytes(&d.kem_public)?, &bytes(&d.sig_public)?)?,
                    approve,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self {
            client: RelayClient::new(&channel.relay)?,
            ch: channel.ch.clone(),
            token: channel.token.clone(),
            label: channel.label.clone(),
            me: Arc::new(identity_of(channel)?),
            devices: Arc::new(devices),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Always true: a requester is only built from a channel with at
    /// least one device. For callers that hold an `Option<Requester>`.
    pub fn is_paired(&self) -> bool {
        !self.devices.is_empty()
    }

    /// Ask every paired device to approve `request`. The first answer
    /// decides: an approval (whose proof verified) or a refusal; the
    /// requests left on the other devices are withdrawn. A device that
    /// fails (no longer paired, unauthentic answer) is passed over; if all
    /// fail, the first failure is returned. The future needs a Tokio
    /// runtime (it spawns one task per device).
    pub fn request_approval(&self, request: &ApprovalRequest) -> (Withdraw, ApprovalFuture) {
        let (signal, rx) = watch::channel(false);
        let pending = Arc::new(Pending {
            signal,
            relay_ids: Mutex::new(Vec::new()),
        });
        self.pending
            .lock()
            .unwrap()
            .insert(request.id.clone(), pending.clone());
        let this = self.clone();
        let request = request.clone();
        let handle = Withdraw {
            pending: pending.clone(),
            requester: self.clone(),
        };
        (
            handle,
            Box::pin(async move {
                let outcome = this.run(&request, &pending, rx).await;
                let mut map = this.pending.lock().unwrap();
                if map
                    .get(&request.id)
                    .is_some_and(|p| Arc::ptr_eq(p, &pending))
                {
                    map.remove(&request.id);
                }
                outcome
            }),
        )
    }

    /// Withdraw the request whose [`ApprovalRequest::id`] is `id`, if it is
    /// still in flight. Synchronous: the request's future ends with
    /// `Withdrawn`, and the relay entries (one per device) are cancelled in
    /// a background task when called inside a Tokio runtime.
    pub fn withdraw(&self, id: &str) {
        let pending = self.pending.lock().unwrap().get(id).cloned();
        if let Some(pending) = pending {
            self.withdraw_pending(&pending);
        }
    }

    fn withdraw_pending(&self, pending: &Arc<Pending>) {
        let _ = pending.signal.send(true);
        let ids = pending.relay_ids.lock().unwrap().clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let this = self.clone();
            runtime.spawn(async move { this.withdraw_all(&ids).await });
        }
    }

    async fn run(
        &self,
        request: &ApprovalRequest,
        pending: &Pending,
        mut withdrawn: watch::Receiver<bool>,
    ) -> Result<Outcome, Error> {
        let now = unix_now();
        let exp = now + request.ttl.as_secs();
        let deadline = Instant::now() + request.ttl;
        let mut tasks = JoinSet::new();
        let mut sent = Vec::new();
        for (index, device) in self.devices.iter().enumerate() {
            let id = hex(&random::<16>());
            let msg = channel::seal(
                &self.me,
                &device.peer,
                &request_header(&self.ch, &device.id, &id, exp),
                &self.body(request, &id, now, exp),
            )?;
            sent.push(id.clone());
            pending.relay_ids.lock().unwrap().push(id.clone());
            let this = self.clone();
            tasks.spawn(async move {
                let end = this.ask(index, &id, exp, &msg, deadline).await;
                (index, end)
            });
        }
        // Resolves on `withdraw()`; never once the handle is dropped
        // without withdrawing.
        let withdrawal = async move {
            loop {
                if withdrawn.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
                if *withdrawn.borrow() {
                    return;
                }
            }
        };
        tokio::pin!(withdrawal);

        let mut first_failure = None;
        let mut expired = false;
        let outcome = loop {
            tokio::select! {
                joined = tasks.join_next() => match joined {
                    None => break if expired || first_failure.is_none() {
                        Ok(Outcome::Expired)
                    } else {
                        Err(first_failure.take().unwrap())
                    },
                    Some(Err(e)) => {
                        first_failure.get_or_insert(Error::Invalid(format!("device task: {e}")));
                    }
                    Some(Ok((index, end))) => {
                        let device = self.devices[index].id.clone();
                        match end {
                            DeviceEnd::Approved => break Ok(Outcome::Approved { device }),
                            DeviceEnd::Denied(reason) => break Ok(Outcome::Denied { device, reason }),
                            DeviceEnd::Expired => expired = true,
                            DeviceEnd::Failed(e) => { first_failure.get_or_insert(e); }
                        }
                    }
                },
                () = &mut withdrawal => break Ok(Outcome::Withdrawn),
                () = tokio::time::sleep_until(deadline + Duration::from_secs(2)) => break Ok(Outcome::Expired),
            }
        };
        // Whatever decided, the other devices must drop their request.
        tasks.abort_all();
        self.withdraw_all(&sent).await;
        outcome
    }

    /// Best effort: take every request off the relay.
    async fn withdraw_all(&self, ids: &[String]) {
        for id in ids {
            let _ = relay::cancel(&self.client, &self.ch, &self.token, id).await;
        }
    }

    fn body(&self, request: &ApprovalRequest, id: &str, now: u64, exp: u64) -> Value {
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
        json!({
            "t": "approve",
            "id": id,
            "iat": now,
            "exp": exp,
            "key": b64u(&request.key),
            "keyName": request.key_name,
            "data": b64u(&request.data),
            "flags": request.flags,
            "binds": binds,
            "caller": request.caller.as_ref().map(|c| json!({ "pid": c.pid, "name": c.name })),
            "agent": request.agent.as_deref().unwrap_or(&self.label),
            "hints": request.hints,
        })
    }

    /// Post the request for one device and wait for its answer.
    async fn ask(
        &self,
        index: usize,
        id: &str,
        exp: u64,
        msg: &str,
        deadline: Instant,
    ) -> DeviceEnd {
        let device = &self.devices[index];
        let base = format!("/api/ch/{}", self.ch);
        let envelope = json!({ "id": id, "to": device.id, "exp": exp, "msg": msg });
        let queued = match self
            .client
            .post(&format!("{base}/requests"), &self.token, &envelope)
            .await
        {
            Ok(v) => v,
            Err(e) => return DeviceEnd::Failed(e.into()),
        };
        match state_of(&queued) {
            "queued" => {}
            "unknown-signer" => return DeviceEnd::Failed(Error::Revoked),
            other => {
                return DeviceEnd::Failed(Error::Invalid(format!(
                    "relay did not queue the request ({other})"
                )))
            }
        }
        let answer = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return DeviceEnd::Expired;
            }
            // Never ask the relay to hold the connection past the expiry.
            let wait = (left.as_secs() + 1).min(POLL_SECONDS);
            match self
                .client
                .get(&format!("{base}/responses/{id}?wait={wait}"), &self.token)
                .await
            {
                Ok(None) => continue,
                Ok(Some(value)) => match state_of(&value) {
                    "pending" => continue,
                    "answered" => match value.get("msg").and_then(Value::as_str) {
                        Some(msg) => break msg.to_string(),
                        None => return DeviceEnd::Failed("answer without content".into()),
                    },
                    "expired" => return DeviceEnd::Expired,
                    other => {
                        return DeviceEnd::Failed(Error::Invalid(format!(
                            "relay lost the request ({other})"
                        )))
                    }
                },
                Err(RelayError::Status(429)) => tokio::time::sleep(THROTTLED_PAUSE).await,
                Err(e) if e.is_transient() => tokio::time::sleep(RETRY_PAUSE).await,
                Err(e) => return DeviceEnd::Failed(e.into()),
            }
        };
        // Only the paired device can have produced this.
        let inner = match channel::open(
            &self.me,
            &device.peer,
            &response_header(&self.ch, &device.id, id),
            &answer,
        ) {
            Ok(inner) => inner,
            Err(e) => {
                return DeviceEnd::Failed(Error::Invalid(format!(
                    "unauthentic answer from the relay: {e}"
                )))
            }
        };
        match read_approval(&inner, &self.ch, &device.id, id, msg, &device.approve) {
            Ok(None) => DeviceEnd::Approved,
            Ok(Some(reason)) => DeviceEnd::Denied(reason),
            Err(e) => DeviceEnd::Failed(e),
        }
    }
}

/// What the approval key signs (PROTOCOL.md, "Approval response"): a bare
/// prefix, then the channel, the signer id, the request id and the raw
/// SHA-256 of the request's `msg` as the relay lists it.
pub fn approval_bytes(ch: &str, signer: &str, id: &str, msg: &str) -> Vec<u8> {
    let mut out = APPROVE_PREFIX.to_vec();
    write_string(&mut out, ch.as_bytes());
    write_string(&mut out, signer.as_bytes());
    write_string(&mut out, id.as_bytes());
    write_string(&mut out, &Sha256::digest(msg.as_bytes()));
    out
}

/// Does `proof` (an SSH signature blob) approve `bytes` under `approve`,
/// an approval key of an accepted type?
pub fn verify_approval(approve: &ssh_key::PublicKey, bytes: &[u8], proof: &[u8]) -> bool {
    if !APPROVE_KEY_TYPES.contains(&approve.algorithm().as_str()) {
        return false;
    }
    let Ok(signature) = ssh_key::Signature::try_from(proof) else {
        return false;
    };
    signature.algorithm() == approve.algorithm()
        && Verifier::verify(approve.key_data(), bytes, &signature).is_ok()
}

/// Read a device's (opened) answer to the request `id` whose wire form was
/// `sent`. `Ok(None)` is an approval whose proof verifies, `Ok(Some(reason))`
/// a refusal.
fn read_approval(
    inner: &Value,
    ch: &str,
    signer: &str,
    id: &str,
    sent: &str,
    approve: &ssh_key::PublicKey,
) -> Result<Option<String>, Error> {
    let bad = |what: &str| Error::Invalid(format!("unusable answer from the device: {what}"));
    let field = |name: &str| inner.get(name).and_then(Value::as_str);
    // The answer must be for this very request, not a replay of another.
    if field("id") != Some(id) || field("req") != Some(&b64u(&Sha256::digest(sent.as_bytes()))) {
        return Err(bad("it answers another request"));
    }
    match field("t") {
        Some("approved") => {
            let proof = field("proof")
                .and_then(unb64u)
                .ok_or_else(|| bad("no proof"))?;
            if verify_approval(approve, &approval_bytes(ch, signer, id, sent), &proof) {
                Ok(None)
            } else {
                Err(bad("the proof does not verify"))
            }
        }
        Some("denied") => Ok(Some(
            field("reason")
                .unwrap_or("user")
                .chars()
                .filter(char::is_ascii_graphic)
                .take(24)
                .collect(),
        )),
        _ => Err(bad("unknown type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::unhex;

    fn proof_vector() -> Value {
        serde_json::from_str(include_str!("../../testdata/approve-proof.json")).unwrap()
    }

    fn key_of(blob_b64u: &str) -> ssh_key::PublicKey {
        ssh_key::PublicKey::from_bytes(&unb64u(blob_b64u).unwrap()).unwrap()
    }

    /// testdata/approve-proof.json: the signed bytes, and both proofs.
    #[test]
    fn proofs_match_the_shared_vector() {
        let v = proof_vector();
        let s = |k: &str| v[k].as_str().unwrap();
        let bytes = approval_bytes(s("channel"), s("signer"), s("id"), s("msg"));
        assert_eq!(hex(&bytes), s("signed"));
        assert_eq!(
            b64u(&Sha256::digest(s("msg").as_bytes())),
            s("req"),
            "req is the hash of the msg text"
        );
        for case in v["keys"].as_array().unwrap() {
            let key = key_of(case["approve"].as_str().unwrap());
            assert_eq!(key.algorithm().as_str(), case["type"].as_str().unwrap());
            let proof = unb64u(case["proof"].as_str().unwrap()).unwrap();
            assert!(verify_approval(&key, &bytes, &proof));
            // Another request, another key: refused.
            let other = approval_bytes(s("channel"), s("signer"), "00", s("msg"));
            assert!(!verify_approval(&key, &other, &proof));
            let mut bad = proof.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(!verify_approval(&key, &bytes, &bad));
        }
        let (ed, p256) = (
            key_of(v["keys"][0]["approve"].as_str().unwrap()),
            unb64u(v["keys"][1]["proof"].as_str().unwrap()).unwrap(),
        );
        assert!(!verify_approval(&ed, &bytes, &p256));
    }

    fn answer(t: &str, id: &str, sent: &str, extra: Value) -> Value {
        let mut v = json!({ "t": t, "id": id, "req": b64u(&Sha256::digest(sent.as_bytes())) });
        v.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        v
    }

    #[test]
    fn an_answer_is_read_only_for_its_own_request() {
        let v = proof_vector();
        let s = |k: &str| v[k].as_str().unwrap();
        let key = key_of(v["keys"][0]["approve"].as_str().unwrap());
        let proof = json!({ "proof": v["keys"][0]["proof"] });
        let (ch, signer, id, msg) = (s("channel"), s("signer"), s("id"), s("msg"));

        let ok = answer("approved", id, msg, proof.clone());
        assert_eq!(read_approval(&ok, ch, signer, id, msg, &key), Ok(None));
        // Another request id, another msg, another channel.
        assert!(read_approval(&ok, ch, signer, "ff", msg, &key).is_err());
        assert!(read_approval(&ok, ch, signer, id, "other", &key).is_err());
        assert!(read_approval(&ok, "00", signer, id, msg, &key).is_err());
        // A refusal, its reason cleaned.
        let no = answer("denied", id, msg, json!({ "reason": "user\n<b>" }));
        assert_eq!(
            read_approval(&no, ch, signer, id, msg, &key),
            Ok(Some("user<b>".into()))
        );
        // A sign-mode answer is no approval.
        let signed = answer("signed", id, msg, json!({ "sig": "AAAA" }));
        assert!(read_approval(&signed, ch, signer, id, msg, &key).is_err());
        let empty = answer("approved", id, msg, json!({}));
        assert!(read_approval(&empty, ch, signer, id, msg, &key).is_err());
    }

    #[test]
    fn a_stored_channel_is_checked() {
        let v = proof_vector();
        let channel = ApproveChannel {
            relay: "https://approve.example".into(),
            ch: "ab".repeat(16),
            token: "t".into(),
            label: "desk".into(),
            kem_private: b64u(&Identity::generate().secrets().0),
            sig_private: b64u(&[7u8; 32]),
            devices: vec![],
        };
        assert!(Requester::new(&channel).is_err_and(|e| e.to_string().contains("no paired")));
        let phone = Identity::generate();
        let device = |line: String| ApproveDevice {
            id: "cd".repeat(8),
            approve_key: line,
            kem_public: b64u(phone.kem_public()),
            sig_public: b64u(&phone.sig_public()),
        };
        let ed = key_of(v["keys"][0]["approve"].as_str().unwrap())
            .to_openssh()
            .unwrap();
        let ok = ApproveChannel {
            devices: vec![device(format!("{ed} phone"))],
            ..channel.clone()
        };
        assert!(Requester::new(&ok).is_ok());
        assert_eq!(ok.devices[0].name(), "phone");
        // An RSA key is no approval key.
        let rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDMpUKQoq7RjbpvNj9HBHZ+mGGgl1uVLjRyXdPqEgNkdQlVZWOA6Xp6Lc/0f7s4WIjtk0AYnMPLxAfjhGg39oK5y4oWzkhhEW3kQxQR5o+7EoKmt9Mw5nb4hmSrtTzYPIx1QRSBmxbWrc8Gi26CPDQ2l+JnBEtyGBRVSGJP0tq6+Q== x";
        let bad = ApproveChannel {
            devices: vec![device(rsa.into())],
            ..channel.clone()
        };
        assert!(Requester::new(&bad).is_err());
        // Survives serde, as the application stores it.
        let again: ApproveChannel =
            serde_json::from_str(&serde_json::to_string(&ok).unwrap()).unwrap();
        assert_eq!(again, ok);
        let _ = unhex;
    }
}
