//! The relay client, and the [`Signer`] built on it: every signature
//! request goes to the paired device through the relay and comes back
//! approved, denied or not at all.
//!
//! Rules of conduct towards the relay (it may sit behind a proxy that
//! bans misbehaving clients):
//!
//! - nothing is sent while idle: the agent only talks to the relay while
//!   one of its own requests is waiting;
//! - one POST per request, then long-poll GETs;
//! - a 4xx answer is never retried — it means our configuration is wrong
//!   — except 429, which is retried slowly.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::channel::{self, request_header, response_header, Peer};
use crate::proto::{Identity, SignError, SignFuture, SignJob, Signer};

/// How long the user has to approve. Must stay under the server's
/// `LoginGraceTime` (120 s by default), which starts before we are asked.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(90);
/// Long-poll duration asked of the relay.
const POLL_SECONDS: u64 = 25;
/// Requests waiting for the user at the same time.
const MAX_IN_FLIGHT: usize = 4;
/// After a denial, further requests fail at once for this long: a tool
/// that retries in a loop must not turn into a stream of notifications.
const BACKOFF_AFTER_DENIAL: Duration = Duration::from_secs(5);
/// Pause before retrying after a network error or a 5xx.
const RETRY_PAUSE: Duration = Duration::from_secs(2);
/// Pause after the relay (or a proxy in front) said "too many requests".
const THROTTLED_PAUSE: Duration = Duration::from_secs(10);

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// What the relay stores of a bearer token.
pub fn token_auth(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug)]
pub enum RelayError {
    /// The relay (or a proxy in front of it) answered with this status.
    Status(u16),
    /// The relay could not be reached.
    Transport(String),
    /// The relay answered something we do not understand.
    Protocol(String),
}

impl RelayError {
    /// Worth trying again? Never for a 4xx, except "too many requests".
    fn is_transient(&self) -> bool {
        match self {
            Self::Status(code) => *code >= 500 || *code == 429,
            Self::Transport(_) => true,
            Self::Protocol(_) => false,
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(code) => write!(f, "relay answered HTTP {code}"),
            Self::Transport(reason) => write!(f, "relay unreachable: {reason}"),
            Self::Protocol(reason) => write!(f, "unexpected relay answer: {reason}"),
        }
    }
}

/// HTTP access to one relay.
#[derive(Clone)]
pub struct RelayClient {
    http: reqwest::Client,
    base: String,
}

impl RelayClient {
    /// `base` must be HTTPS, except for a loopback address (tests): the
    /// bearer tokens travel in a header.
    pub fn new(base: &str) -> Result<Self, String> {
        let base = base.trim_end_matches('/').to_string();
        let url = reqwest::Url::parse(&base).map_err(|e| format!("invalid relay URL: {e}"))?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err("the relay URL must use https".into());
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(POLL_SECONDS + 15))
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        Ok(Self { http, base })
    }

    /// `Ok(None)` is HTTP 204: nothing yet.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        token: &str,
    ) -> Result<Option<Value>, RelayError> {
        let response = request
            .bearer_auth(token)
            .send()
            .await
            // The error's Display may include the URL, never the token.
            .map_err(|e| RelayError::Transport(e.without_url().to_string()))?;
        let status = response.status();
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(RelayError::Status(status.as_u16()));
        }
        // A proxy may answer 200 with a page of its own: not JSON.
        response
            .json::<Value>()
            .await
            .map(Some)
            .map_err(|_| RelayError::Protocol("not JSON".into()))
    }

    pub async fn post(&self, path: &str, token: &str, body: &Value) -> Result<Value, RelayError> {
        let request = self.http.post(format!("{}{path}", self.base)).json(body);
        self.send(request, token)
            .await?
            .ok_or_else(|| RelayError::Protocol("empty answer".into()))
    }

    pub async fn get(&self, path: &str, token: &str) -> Result<Option<Value>, RelayError> {
        self.send(self.http.get(format!("{}{path}", self.base)), token)
            .await
    }
}

fn state_of(value: &Value) -> &str {
    value.get("state").and_then(Value::as_str).unwrap_or("")
}

/// Names a host key, for display only.
type HintFn = Arc<dyn Fn(&[u8]) -> Option<String> + Send + Sync>;

/// Sends each sign job to the paired device and waits for its answer.
pub struct RelaySigner {
    client: RelayClient,
    ch: String,
    token: String,
    signer_id: String,
    label: String,
    identity: Identity,
    /// Our channel keys and the paired device's.
    me: Arc<channel::Identity>,
    peer: Arc<Peer>,
    timeout: Duration,
    hints: HintFn,
    slots: Arc<Semaphore>,
    backoff_until: Arc<Mutex<Option<Instant>>>,
}

impl RelaySigner {
    /// `public_key` is the signer's `authorized_keys` line; `me` and
    /// `peer` are the channel keys agreed at pairing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: RelayClient,
        ch: &str,
        token: &str,
        signer_id: &str,
        public_key: &str,
        label: &str,
        me: channel::Identity,
        peer: Peer,
        timeout: Duration,
    ) -> Result<Self, String> {
        let key = ssh_key::PublicKey::from_openssh(public_key)
            .map_err(|e| format!("invalid signer public key: {e}"))?;
        let identity = Identity {
            key_blob: key
                .to_bytes()
                .map_err(|e| format!("signer public key: {e}"))?,
            comment: key.comment().to_string(),
        };
        Ok(Self {
            client,
            ch: ch.to_string(),
            token: token.to_string(),
            signer_id: signer_id.to_string(),
            label: label.to_string(),
            identity,
            me: Arc::new(me),
            peer: Arc::new(peer),
            timeout,
            hints: Arc::new(|_| None),
            slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            backoff_until: Arc::new(Mutex::new(None)),
        })
    }

    /// Name a host key for display on the device (from `known_hosts`).
    /// The device shows such names as unverified.
    pub fn with_hints(
        mut self,
        hints: impl Fn(&[u8]) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.hints = Arc::new(hints);
        self
    }

    fn request_body(&self, job: &SignJob, id: &str, now: u64, exp: u64) -> Value {
        let mut hints = serde_json::Map::new();
        for hop in &job.hops {
            if let Some(name) = (self.hints)(&hop.key_blob) {
                hints.insert(hop.fingerprint.clone(), Value::String(name));
            }
        }
        let binds: Vec<Value> = job
            .hops
            .iter()
            .map(|hop| {
                json!({
                    "hostkey": b64u(&hop.key_blob),
                    "sid": b64u(&hop.session_id),
                    "sig": b64u(&hop.signature),
                    "fwd": hop.forwarded,
                })
            })
            .collect();
        json!({
            "t": "sign",
            "id": id,
            "iat": now,
            "exp": exp,
            "key": b64u(&job.key_blob),
            "data": b64u(&job.data),
            "flags": job.flags,
            "binds": binds,
            "caller": job.caller.as_ref().map(|c| json!({ "pid": c.pid, "name": c.name })),
            "agent": self.label,
            "hints": hints,
        })
    }
}

/// Read the device's (already opened) answer to the request `id` whose
/// wire form was `sent`.
fn read_response(inner: &Value, id: &str, sent: &str) -> Result<Vec<u8>, SignError> {
    let bad = |what: &str| SignError::Backend(format!("unusable answer from the signer: {what}"));
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
            Some(reason) => Err(SignError::Backend(format!(
                "the signer refused the request ({})",
                reason
                    .chars()
                    .filter(char::is_ascii_graphic)
                    .take(24)
                    .collect::<String>()
            ))),
        },
        _ => Err(bad("unknown type")),
    }
}

impl Signer for RelaySigner {
    fn identities(&self) -> Vec<Identity> {
        vec![self.identity.clone()]
    }

    fn sign(&self, job: SignJob) -> SignFuture {
        let id = hex(&random::<16>());
        let now = unix_now();
        let exp = now + self.timeout.as_secs();
        let sealed = channel::seal(
            &self.me,
            &self.peer,
            &request_header(&self.ch, &self.signer_id, &id, exp),
            &self.request_body(&job, &id, now, exp),
        );
        let answer_header = response_header(&self.ch, &self.signer_id, &id);
        let (me, peer) = (self.me.clone(), self.peer.clone());
        let to = self.signer_id.clone();

        let client = self.client.clone();
        let token = self.token.clone();
        let base = format!("/api/ch/{}", self.ch);
        let deadline = Instant::now() + self.timeout;
        let slots = self.slots.clone();
        let backoff_until = self.backoff_until.clone();

        Box::pin(async move {
            let sent = sealed.map_err(SignError::Backend)?;
            let envelope = json!({ "id": id, "to": to, "exp": exp, "msg": sent });
            if backoff_until
                .lock()
                .unwrap()
                .is_some_and(|until| Instant::now() < until)
            {
                return Err(SignError::Backend(
                    "a request was just denied; backing off".into(),
                ));
            }
            let Ok(_slot) = slots.try_acquire_owned() else {
                return Err(SignError::Backend(
                    "too many requests already waiting".into(),
                ));
            };

            let queued = client
                .post(&format!("{base}/requests"), &token, &envelope)
                .await
                .map_err(|e| SignError::Backend(e.to_string()))?;
            if state_of(&queued) != "queued" {
                return Err(SignError::Backend(format!(
                    "relay did not queue the request ({})",
                    state_of(&queued)
                )));
            }

            let answer = loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(SignError::Expired);
                }
                // Never ask the relay to hold the connection past the expiry.
                let wait = (left.as_secs() + 1).min(POLL_SECONDS);
                let poll = format!("{base}/responses/{id}?wait={wait}");
                match client.get(&poll, &token).await {
                    Ok(None) => continue,
                    Ok(Some(value)) => match state_of(&value) {
                        "answered" => match value.get("msg").and_then(Value::as_str) {
                            Some(msg) => break msg.to_string(),
                            None => {
                                return Err(SignError::Backend("answer without content".into()))
                            }
                        },
                        "expired" => return Err(SignError::Expired),
                        other => {
                            return Err(SignError::Backend(format!(
                                "relay lost the request ({other})"
                            )))
                        }
                    },
                    // Throttled: back off for real, each 429 counts
                    // against us at a proxy that bans.
                    Err(RelayError::Status(429)) => tokio::time::sleep(THROTTLED_PAUSE).await,
                    Err(e) if e.is_transient() => tokio::time::sleep(RETRY_PAUSE).await,
                    Err(e) => return Err(SignError::Backend(e.to_string())),
                }
            };

            // Only the paired device can have produced this.
            let inner = channel::open(&me, &peer, &answer_header, &answer).map_err(|e| {
                SignError::Backend(format!("unauthentic answer from the relay: {e}"))
            })?;
            let result = read_response(&inner, &id, &sent);
            if result == Err(SignError::Denied) {
                *backoff_until.lock().unwrap() = Some(Instant::now() + BACKOFF_AFTER_DENIAL);
            }
            result
        })
    }
}

/// Look a host key up in an OpenSSH `known_hosts` file and return the
/// first name it is listed under. Hashed entries cannot be named, and
/// revoked or CA lines are ignored.
pub fn known_host_name(known_hosts: &str, key_blob: &[u8]) -> Option<String> {
    let wanted = STANDARD.encode(key_blob);
    known_hosts.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let names = fields.next()?;
        let _key_type = fields.next()?;
        if names.starts_with(['#', '@', '|']) || fields.next()? != wanted {
            return None;
        }
        let name = names.split(',').next()?;
        // "[host]:port" for non-default ports.
        Some(name.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_url_must_be_https_unless_loopback() {
        assert!(RelayClient::new("https://relay.example").is_ok());
        assert!(RelayClient::new("http://127.0.0.1:8765/").is_ok());
        assert!(RelayClient::new("http://localhost:8765").is_ok());
        assert!(RelayClient::new("http://relay.example").is_err());
        assert!(RelayClient::new("ftp://relay.example").is_err());
        assert!(RelayClient::new("not a url").is_err());
    }

    #[test]
    fn only_server_errors_and_network_errors_are_retried() {
        assert!(RelayError::Status(502).is_transient());
        assert!(RelayError::Transport("reset".into()).is_transient());
        assert!(RelayError::Status(429).is_transient());
        for code in [400, 401, 403, 404] {
            assert!(!RelayError::Status(code).is_transient(), "{code}");
        }
        assert!(!RelayError::Protocol("html".into()).is_transient());
    }

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
        let msg = answer("sent", json!({ "t": "denied", "reason": "unverified" }));
        assert!(matches!(
            read_response(&msg, "id-1", "sent"),
            Err(SignError::Backend(reason)) if reason.contains("unverified")
        ));
    }

    #[test]
    fn an_answer_to_another_request_is_rejected() {
        let msg = answer("sent", json!({ "t": "signed", "sig": b64u(b"s") }));
        assert!(matches!(
            read_response(&msg, "id-2", "sent"),
            Err(SignError::Backend(_))
        ));
        assert!(matches!(
            read_response(&msg, "id-1", "other"),
            Err(SignError::Backend(_))
        ));
        let msg = answer("sent", json!({ "t": "signed" }));
        assert!(matches!(
            read_response(&msg, "id-1", "sent"),
            Err(SignError::Backend(_))
        ));
    }

    #[test]
    fn known_hosts_lookup_names_plain_entries_only() {
        let blob = b"host-key-blob";
        let b64 = STANDARD.encode(blob);
        let file = format!(
            "# comment\n\
             |1|c2FsdA==|aGFzaA== ssh-ed25519 {b64}\n\
             @revoked old.example ssh-ed25519 {b64}\n\
             other.example ssh-ed25519 AAAAother\n\
             [build.example]:2222,10.0.0.7 ssh-ed25519 {b64} trailing comment\n\
             later.example ssh-ed25519 {b64}\n"
        );
        assert_eq!(
            known_host_name(&file, blob),
            Some("[build.example]:2222".into())
        );
        assert_eq!(known_host_name(&file, b"unknown"), None);
        assert_eq!(known_host_name("", blob), None);
    }
}
