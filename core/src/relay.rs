//! HTTP access to the relay.
//!
//! Rules of conduct towards the relay (it may sit behind a proxy that
//! bans misbehaving clients):
//!
//! - nothing is sent while idle: a client only talks to the relay while
//!   one of its own requests is waiting;
//! - one POST per request, then long-poll GETs;
//! - a 4xx answer is never retried — it means our configuration is wrong
//!   — except 429, which is retried slowly;
//! - a hosted relay may require a subscription: `402` is
//!   [`RelayError::SubscriptionRequired`], which only the user can fix (on
//!   the phone), so it is never retried either.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// Long-poll duration asked of the relay.
pub const POLL_SECONDS: u64 = 25;
/// Pause before retrying after a network error or a 5xx.
pub const RETRY_PAUSE: Duration = Duration::from_secs(2);
/// Pause after the relay (or a proxy in front) said "too many requests".
pub const THROTTLED_PAUSE: Duration = Duration::from_secs(10);

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The relay (or a proxy in front of it) answered with this status.
    Status(u16),
    /// The relay could not be reached.
    Transport(String),
    /// The relay answered something we do not understand.
    Protocol(String),
    /// HTTP 402 `subscription_required`: the relay serves subscribers only
    /// and no current subscription covers this channel. The user
    /// subscribes, or renews, in the iPhone app.
    SubscriptionRequired,
    /// HTTP 403 `machine_limit`: the subscription already covers as many
    /// machines as it may.
    MachineLimit,
}

impl RelayError {
    /// Worth trying again? Never for a 4xx, except "too many requests".
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Status(code) => *code >= 500 || *code == 429,
            Self::Transport(_) => true,
            Self::Protocol(_) | Self::SubscriptionRequired | Self::MachineLimit => false,
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(code) => write!(f, "relay answered HTTP {code}"),
            Self::Transport(reason) => write!(f, "relay unreachable: {reason}"),
            Self::Protocol(reason) => write!(f, "unexpected relay answer: {reason}"),
            Self::SubscriptionRequired => {
                f.write_str("the relay requires a subscription: open Clavix Approve on the iPhone")
            }
            Self::MachineLimit => {
                f.write_str("the subscription already covers as many machines as it may")
            }
        }
    }
}

impl std::error::Error for RelayError {}

/// HTTP access to one relay.
#[derive(Clone)]
pub struct RelayClient {
    http: reqwest::Client,
    base: String,
}

impl RelayClient {
    /// `base` must be HTTPS, except for a literal loopback IP address
    /// (`127.0.0.1`, `[::1]`; tests and local relays): the bearer tokens
    /// travel in a header. The name `localhost` is not accepted over plain
    /// HTTP, since a resolver could send it elsewhere. Redirects are never
    /// followed: one could carry a request, and its token, to another host.
    pub fn new(base: &str) -> Result<Self, String> {
        let base = base.trim_end_matches('/').to_string();
        let url = reqwest::Url::parse(&base).map_err(|e| format!("invalid relay URL: {e}"))?;
        let loopback = url
            .host_str()
            .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
            return Err("the relay URL must use https".into());
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!loopback)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(POLL_SECONDS + 15))
            .build()
            .map_err(|e| format!("HTTP client: {e}"))?;
        Ok(Self { http, base })
    }

    /// The base URL, without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
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
            let code = status.as_u16();
            // Only a 403 needs its body; a proxy's may be a page of its
            // own, which names no relay error.
            let body = if code == 403 {
                response.json::<Value>().await.unwrap_or(Value::Null)
            } else {
                Value::Null
            };
            return Err(status_error(code, &body));
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

/// The error for a refusal with this status and JSON body.
fn status_error(code: u16, body: &Value) -> RelayError {
    match (code, body.get("error").and_then(Value::as_str)) {
        (402, _) => RelayError::SubscriptionRequired,
        (403, Some("machine_limit")) => RelayError::MachineLimit,
        _ => RelayError::Status(code),
    }
}

/// The `state` field of a relay answer, or "".
pub fn state_of(value: &Value) -> &str {
    value.get("state").and_then(Value::as_str).unwrap_or("")
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

/// Revoke one device of the pairing. `Ok(true)` when this call removed it,
/// `Ok(false)` when the relay no longer knew it (or the whole pairing).
pub async fn revoke_device(
    client: &RelayClient,
    ch: &str,
    token: &str,
    signer: &str,
) -> Result<bool, RelayError> {
    match client
        .post(
            &format!("/api/ch/{ch}/revoke"),
            token,
            &json!({ "signer": signer }),
        )
        .await
    {
        Ok(value) if state_of(&value) == "revoked" => Ok(true),
        Ok(value) if state_of(&value) == "unknown-signer" => Ok(false),
        Ok(value) => Err(RelayError::Protocol(format!(
            "revocation not confirmed ({})",
            state_of(&value)
        ))),
        Err(RelayError::Status(401)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Withdraw a request the device has not answered: it leaves the device's
/// list, and a late answer gets `expired`. Best effort: errors are
/// returned for logging only.
pub async fn cancel(
    client: &RelayClient,
    ch: &str,
    token: &str,
    id: &str,
) -> Result<(), RelayError> {
    client
        .post(
            &format!("/api/ch/{ch}/requests/{id}/cancel"),
            token,
            &json!({}),
        )
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_url_must_be_https_unless_loopback() {
        assert!(RelayClient::new("https://relay.example").is_ok());
        assert!(RelayClient::new("http://127.0.0.1:8765/").is_ok());
        assert!(RelayClient::new("http://[::1]:8765").is_ok());
        assert!(RelayClient::new("https://localhost:8765").is_ok());
        // Plain HTTP only to a literal loopback IP, never to a name.
        assert!(RelayClient::new("http://localhost:8765").is_err());
        assert!(RelayClient::new("http://LOCALHOST:8765").is_err());
        assert!(RelayClient::new("http://127.0.0.1.relay.example").is_err());
        assert!(RelayClient::new("http://[::2]").is_err());
        assert!(RelayClient::new("http://10.0.0.1").is_err());
        assert!(RelayClient::new("http://relay.example").is_err());
        assert!(RelayClient::new("ftp://relay.example").is_err());
        assert!(RelayClient::new("not a url").is_err());
    }

    /// An HTTP server on loopback that answers every request with
    /// `response`, and returns how many it served once idle for 500 ms.
    async fn canned_server(response: &'static str) -> (String, tokio::task::JoinHandle<usize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut served = 0;
            while let Ok(Ok((mut socket, _))) =
                tokio::time::timeout(Duration::from_millis(500), listener.accept()).await
            {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
                served += 1;
            }
            served
        });
        (base, task)
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        // The redirect points back at the same server: following it would
        // make a second request.
        let (base, server) = canned_server(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /elsewhere\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let client = RelayClient::new(&base).unwrap();
        let result = client.post("/api/channels", "token", &json!({})).await;
        assert_eq!(result, Err(RelayError::Status(307)));
        assert!(!RelayError::Status(307).is_transient());
        assert_eq!(server.await.unwrap(), 1, "the redirect was followed");
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

    #[test]
    fn a_missing_subscription_is_its_own_error_and_never_retried() {
        assert!(!RelayError::SubscriptionRequired.is_transient());
        assert!(!RelayError::MachineLimit.is_transient());
        let body = json!({ "error": "subscription_required" });
        assert_eq!(status_error(402, &body), RelayError::SubscriptionRequired);
        assert_eq!(
            status_error(402, &Value::Null),
            RelayError::SubscriptionRequired
        );
        let body = json!({ "error": "machine_limit", "limit": 10 });
        assert_eq!(status_error(403, &body), RelayError::MachineLimit);
        assert_eq!(status_error(403, &Value::Null), RelayError::Status(403));
        assert_eq!(
            status_error(403, &json!({ "error": "invalid_transaction" })),
            RelayError::Status(403)
        );
        assert!(RelayError::SubscriptionRequired
            .to_string()
            .contains("open Clavix Approve on the iPhone"));
    }
}
