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
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::channel::{self, request_header, response_header, Peer};
use crate::proto::{CallerInfo, Identity, SignError, SignFuture, SignJob, Signer};

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

/// Delete the pairing on the relay. `Ok(true)` when this call deleted it,
/// `Ok(false)` when the relay no longer knew it (already revoked from the
/// other end, or the relay lost its state).
pub async fn revoke(client: &RelayClient, ch: &str, token: &str) -> Result<bool, RelayError> {
    match client
        .post(&format!("/api/ch/{ch}/revoke"), token, &json!({}))
        .await
    {
        Ok(value) if state_of(&value) == "revoked" => Ok(true),
        Ok(value) => Err(RelayError::Protocol(format!(
            "revocation not confirmed ({})",
            state_of(&value)
        ))),
        Err(RelayError::Status(401)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// A relay failure as the agent reports it. A 401 on a paired channel
/// means the pairing is gone, most likely revoked from the device.
fn relay_failure(e: RelayError) -> SignError {
    match e {
        RelayError::Status(401) => SignError::Backend(
            "the relay no longer knows this pairing (revoked from the device?); \
             run `clavix-agent pair` again"
                .into(),
        ),
        e => SignError::Backend(e.to_string()),
    }
}

fn state_of(value: &Value) -> &str {
    value.get("state").and_then(Value::as_str).unwrap_or("")
}

/// Names a host key, for display only. The caller is the process that
/// asked for the signature, when known; the flag says whether this host
/// is the only one in the request (no forwarded agent in between).
type HintFn = Arc<dyn Fn(&[u8], Option<&CallerInfo>, bool) -> Option<String> + Send + Sync>;

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
            hints: Arc::new(|_, _, _| None),
            slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            backoff_until: Arc::new(Mutex::new(None)),
        })
    }

    /// Name a host key for display on the device (from `known_hosts`, or
    /// the caller's command line). The device shows such names as
    /// unverified.
    pub fn with_hints(
        mut self,
        hints: impl Fn(&[u8], Option<&CallerInfo>, bool) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.hints = Arc::new(hints);
        self
    }

    fn request_body(&self, job: &SignJob, id: &str, now: u64, exp: u64) -> Value {
        let mut hints = serde_json::Map::new();
        let sole = job.hops.len() == 1;
        for hop in &job.hops {
            if let Some(name) = (self.hints)(&hop.key_blob, job.caller.as_ref(), sole) {
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
                .map_err(relay_failure)?;
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
                    Err(e) => return Err(relay_failure(e)),
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
/// first name it is listed under. A hashed entry (`HashKnownHosts yes`,
/// the default on Debian) cannot be read back: it is named only when one
/// of `candidates` hashes to it. Revoked and CA lines are ignored.
pub fn known_host_name(
    known_hosts: &str,
    key_blob: &[u8],
    candidates: &[String],
) -> Option<String> {
    let wanted = STANDARD.encode(key_blob);
    known_hosts.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let names = fields.next()?;
        let _key_type = fields.next()?;
        if names.starts_with(['#', '@']) || fields.next()? != wanted {
            return None;
        }
        if let Some(hashed) = names.strip_prefix("|1|") {
            // "|1|salt|HMAC-SHA1(salt, name)", both in base64.
            let (salt, hash) = hashed.split_once('|')?;
            let salt = STANDARD.decode(salt).ok()?;
            let hash = STANDARD.decode(hash).ok()?;
            return candidates
                .iter()
                .find(|name| {
                    Hmac::<Sha1>::new_from_slice(&salt).is_ok_and(|mut mac| {
                        mac.update(name.as_bytes());
                        mac.verify_slice(&hash).is_ok()
                    })
                })
                .cloned();
        }
        if names.starts_with('|') {
            return None;
        }
        let name = names.split(',').next()?;
        // "[host]:port" for non-default ports.
        Some(name.to_string())
    })
}

/// Most arguments of a command line looked at, and most names tried.
const MAX_CANDIDATE_ARGS: usize = 64;
const MAX_CANDIDATE_HOSTS: usize = 32;
const MAX_CANDIDATE_PORTS: usize = 4;

/// Every host name a command line (of `ssh`, `scp`, `git`…) may be
/// naming, in the forms `known_hosts` uses. Deliberately generous, with
/// no knowledge of any program's options: a candidate is only ever used
/// if it hashes to a `known_hosts` entry, so a wrong guess costs nothing.
pub fn host_candidates(args: &[String]) -> Vec<String> {
    fn push(list: &mut Vec<String>, max: usize, value: &str) {
        let usable = !value.is_empty()
            && !value.starts_with('-')
            && !value.chars().any(|c| c.is_control() || c.is_whitespace());
        if usable && list.len() < max && !list.iter().any(|v| v == value) {
            list.push(value.to_string());
        }
    }
    let is_port = |s: &str| !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit());

    let mut hosts = Vec::new();
    let mut ports = Vec::new();
    for arg in args.iter().take(MAX_CANDIDATE_ARGS) {
        if arg.is_empty() || arg.len() > 255 {
            continue;
        }
        // "2222" after -p, "-p2222", "-P2222", "-oPort=2222", "Port=2222".
        let port = ["-p", "-P"]
            .iter()
            .find_map(|flag| arg.strip_prefix(flag))
            .or_else(|| arg.rsplit_once('=').map(|(_, value)| value))
            .unwrap_or(arg);
        if is_port(port) {
            push(&mut ports, MAX_CANDIDATE_PORTS, port);
            continue;
        }
        // "host", "user@host", "host:path", "ssh://user@host:port/".
        let lower = arg.to_lowercase();
        let rest = lower.strip_prefix("ssh://").unwrap_or(&lower);
        let rest = rest.split('/').next().unwrap_or(rest);
        let rest = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
        push(&mut hosts, MAX_CANDIDATE_HOSTS, rest);
        if let Some((host, tail)) = rest.split_once(':') {
            push(&mut hosts, MAX_CANDIDATE_HOSTS, host);
            if is_port(tail) {
                push(&mut ports, MAX_CANDIDATE_PORTS, tail);
            }
        }
        if let Some(inner) = rest.strip_prefix('[').and_then(|r| r.split(']').next()) {
            push(&mut hosts, MAX_CANDIDATE_HOSTS, inner);
        }
    }

    let mut candidates = Vec::new();
    for host in &hosts {
        for port in ports.iter().filter(|p| p.as_str() != "22") {
            candidates.push(format!("[{host}]:{port}"));
        }
    }
    candidates.extend(hosts);
    candidates
}

/// The destination named on an `ssh` command line, as typed: an alias
/// stays an alias, which is what the user knows the host by. `None` when
/// the command is not `ssh` or names no usable host. The port is added
/// when one other than 22 is given with `-p`.
///
/// Only meaningful when the request has a single host: through a
/// forwarded agent, the local `ssh` names the first host, not the one
/// that asks.
pub fn ssh_destination(args: &[String]) -> Option<String> {
    // OpenSSH options that take a value (ssh(1)).
    const WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";
    let (program, rest) = args.split_first()?;
    if program.rsplit('/').next() != Some("ssh") {
        return None;
    }
    let mut port: Option<&str> = None;
    let mut dest: Option<&str> = None;
    let mut it = rest.iter().take(MAX_CANDIDATE_ARGS);
    while let Some(arg) = it.next() {
        if arg == "--" {
            dest = it.next().map(String::as_str);
            break;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            dest = Some(arg);
            break;
        };
        // "-4At", "-p2222", "-p 2222", "-oFoo=bar"…
        for (i, c) in flags.char_indices() {
            if WITH_VALUE.contains(c) {
                let inline = &flags[i + c.len_utf8()..];
                let value = if inline.is_empty() {
                    it.next().map(String::as_str)
                } else {
                    Some(inline)
                };
                if c == 'p' {
                    port = value;
                }
                break;
            }
        }
    }

    let dest = dest?.to_lowercase();
    let (host, url_port) = match dest.strip_prefix("ssh://") {
        Some(url) => {
            let authority = url.split('/').next().unwrap_or(url);
            let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            match host_port.strip_prefix('[') {
                Some(v6) => {
                    let (host, tail) = v6.split_once(']')?;
                    (host.to_string(), tail.strip_prefix(':').map(str::to_string))
                }
                None => match host_port.split_once(':') {
                    Some((h, p)) => (h.to_string(), Some(p.to_string())),
                    None => (host_port.to_string(), None),
                },
            }
        }
        None => (
            dest.rsplit_once('@')
                .map_or(dest.as_str(), |(_, h)| h)
                .to_string(),
            None,
        ),
    };
    let usable = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if !usable {
        return None;
    }
    let port = url_port.as_deref().or(port).filter(|p| {
        *p != "22" && !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit())
    });
    Some(match port {
        Some(p) if host.contains(':') => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
        None => host,
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
            known_host_name(&file, blob, &[]),
            Some("[build.example]:2222".into())
        );
        assert_eq!(known_host_name(&file, b"unknown", &[]), None);
        assert_eq!(known_host_name("", blob, &[]), None);
    }

    /// Two lines written by `ssh-keygen -H`, for `build.example` and
    /// `[build.example]:2222`.
    const HASHED: &str = "\
        |1|/qGM3rQScKfdke/wdZbvyaHd+YM=|Zs/sGQ8N5QNYwliMkc469uQtG6I= ssh-ed25519 aG9zdC1rZXktYmxvYg==\n\
        |1|d5T9vOAE7VUJi5pI1pX1WOqvhUA=|ZMZ35/g9I2XlV1Y+bcURkNjdS8k= ssh-ed25519 aG9zdC1rZXktYmxvYg==\n";

    fn args(line: &str) -> Vec<String> {
        line.split(' ').map(String::from).collect()
    }

    #[test]
    fn hashed_known_hosts_entries_are_named_by_a_matching_candidate_only() {
        let blob = b"host-key-blob";
        let named = |line: &str| known_host_name(HASHED, blob, &host_candidates(&args(line)));

        assert_eq!(known_host_name(HASHED, blob, &[]), None);
        assert_eq!(named("ssh other.example"), None);
        assert_eq!(
            named("ssh -o BatchMode=yes deploy@Build.Example uptime"),
            Some("build.example".into())
        );
        assert_eq!(
            named("scp -q file build.example:/tmp/"),
            Some("build.example".into())
        );
        // The first line is the port-22 entry; without it, the port is needed.
        let second = HASHED.lines().nth(1).unwrap();
        let named = |line: &str| known_host_name(second, blob, &host_candidates(&args(line)));
        assert_eq!(named("ssh build.example"), None);
        for line in [
            "ssh -p 2222 build.example",
            "ssh -p2222 root@build.example",
            "ssh -oPort=2222 build.example",
            "scp -P 2222 file build.example:",
            "git-remote ssh://git@build.example:2222/repo.git",
        ] {
            assert_eq!(named(line), Some("[build.example]:2222".into()), "{line}");
        }
        // Another key under the same hashed names stays unnamed.
        assert_eq!(
            known_host_name(
                HASHED,
                b"another-key",
                &host_candidates(&args("ssh build.example"))
            ),
            None
        );
    }

    #[test]
    fn ssh_destination_is_the_host_as_typed() {
        let dest = |line: &str| ssh_destination(&args(line));
        assert_eq!(dest("ssh build"), Some("build".into()));
        assert_eq!(
            dest("/usr/bin/ssh Me@Build.Example"),
            Some("build.example".into())
        );
        assert_eq!(
            dest("ssh -A -i key -p 2222 build ls -l"),
            Some("build:2222".into())
        );
        assert_eq!(dest("ssh -4At -p22 -oUser=me build"), Some("build".into()));
        assert_eq!(dest("ssh -J jump -l me build"), Some("build".into()));
        // How git and scp run it.
        assert_eq!(
            dest("ssh -o SendEnv=GIT_PROTOCOL git@github.com git-upload-pack 'x.git'"),
            Some("github.com".into())
        );
        assert_eq!(
            dest("ssh -x -oForwardAgent=no -l me -s -- files.example sftp"),
            Some("files.example".into())
        );
        assert_eq!(dest("ssh ssh://me@build:2200/"), Some("build:2200".into()));
        assert_eq!(
            dest("ssh ssh://[fd00::7]:2200"),
            Some("[fd00::7]:2200".into())
        );
    }

    #[test]
    fn ssh_destination_needs_ssh_and_a_plain_host() {
        let dest = |line: &str| ssh_destination(&args(line));
        assert_eq!(dest("git fetch origin"), None);
        assert_eq!(dest("sshd -D"), None);
        assert_eq!(dest("ssh"), None);
        assert_eq!(dest("ssh -p"), None);
        assert_eq!(dest("ssh -i key"), None);
        assert_eq!(dest("ssh b\u{202e}ad"), None);
        assert_eq!(dest("ssh me@"), None);
        assert_eq!(ssh_destination(&[]), None);
    }

    #[test]
    fn host_candidates_are_bounded_and_printable() {
        let many: Vec<String> = (0..500).map(|i| format!("host{i}")).collect();
        assert!(host_candidates(&many).len() <= MAX_CANDIDATE_HOSTS);
        let odd = vec![
            "a\u{7}b".to_string(),
            "x".repeat(300),
            String::new(),
            "-v".into(),
        ];
        assert!(host_candidates(&odd).is_empty());
    }
}
