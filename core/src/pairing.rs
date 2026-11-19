//! One-time pairing with the device that will sign or approve.
//!
//! The agent opens a channel on the relay and shows a pairing code: the
//! channel id and a one-time secret. The user enters it on the device,
//! which answers with its public keys. The relay only ever sees a token
//! derived from the secret; a MAC keyed by another derivation
//! authenticates the keys both sides exchange through it.
//!
//! The MAC does not hold once the secret leaks to the relay. The six
//! digits both ends show are therefore a short authentication string
//! (pairing protocol version 2): the hello commits to a random nonce of
//! the agent, the device answers with its keys and a nonce of its own, and
//! only then does the agent reveal its nonce. Neither side can choose its
//! keys or nonce after seeing the other's, so a relay in the middle gets
//! one chance in a million per code. PROTOCOL.md, "Pairing". Mirrored by
//! `web/lib/pairing.js` and `ios/ClavixCore`.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::bytes::{b64u, hex, random, token_auth, unb64u, unhex, write_string};
use crate::channel::{open_introduction, pair_header, Identity, Peer};
use crate::relay::{RelayClient, RelayError};
use crate::state;

/// Prefix of a pairing code of this protocol version.
pub const CODE_PREFIX: &str = "cva2-";
/// The pairing protocol version, in the hello and in the device's answer.
pub const PAIRING_VERSION: u64 = 2;
/// The URL scheme of the Clavix Approve app: the QR code opens the app,
/// never a page served by the relay.
pub const APP_SCHEME: &str = "clavix-approve";
/// The relay forgets a channel nobody joined after 15 minutes.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(14 * 60);
const KEY_ALGORITHM: &str = "ecdsa-sha2-nistp256";
/// Approval keys a requester accepts (PROTOCOL.md, "Approval key").
pub const APPROVE_KEY_TYPES: [&str; 2] = ["ssh-ed25519", "ecdsa-sha2-nistp256"];
/// Length of either side's nonce.
pub const NONCE_LENGTH: usize = 32;

const HELLO_LABEL: &str = "clavix-approve/v2/pair-hello";
const ANSWER_LABEL: &str = "clavix-approve/v2/pair-answer";
const COMMIT_LABEL: &str = "clavix-approve/v2/pair-commit";
const DIGITS_LABEL: &str = "clavix-approve/v2/pair-digits";

/// Why a pairing did not complete. `Display` gives the same texts as
/// before this type existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingError {
    /// The relay could not be reached (`RelayError::Transport`), answered
    /// with an HTTP error (`Status`) or with something that is not JSON
    /// (`Protocol`).
    Relay(RelayError),
    /// The relay no longer knows the channel (`open_on_channel` got a
    /// 401): pair again from scratch.
    Gone,
    /// The relay answered, but refused: the channel exists already, has as
    /// many devices as it allows, and the like.
    Refused(String),
    /// Nobody entered the code before the window closed.
    Expired,
    /// The device's answer is not authentic, of an older protocol
    /// version, or carries a key that is not accepted.
    Invalid(String),
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relay(e) => e.fmt(f),
            Self::Gone => f.write_str(
                "the relay no longer knows this pairing; run `clavix-agent pair` without --add",
            ),
            Self::Refused(reason) | Self::Invalid(reason) => f.write_str(reason),
            Self::Expired => f.write_str("nobody entered the pairing code in time"),
        }
    }
}

impl std::error::Error for PairingError {}

impl From<RelayError> for PairingError {
    fn from(e: RelayError) -> Self {
        Self::Relay(e)
    }
}

impl From<String> for PairingError {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

impl From<&str> for PairingError {
    fn from(reason: &str) -> Self {
        Self::Invalid(reason.to_string())
    }
}

impl From<PairingError> for String {
    fn from(e: PairingError) -> Self {
        e.to_string()
    }
}

/// What a channel is for, set at pairing and for good (PROTOCOL.md,
/// "Approve mode"). The mode is in every MAC and in the digits, so that a
/// relay flipping it breaks a MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The device holds the SSH key and signs (`clavix-agent`).
    Sign,
    /// The requester holds the SSH key; the device only approves, with
    /// its approval key (Clavix desktop).
    Approve,
}

impl Mode {
    /// As in the hello and in every transcript.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Approve => "approve",
        }
    }

    /// The field of the device's answer that carries its key.
    fn key_field(self) -> &'static str {
        match self {
            Self::Sign => "key",
            Self::Approve => "approve",
        }
    }

    fn accepts(self, algorithm: &str) -> bool {
        match self {
            Self::Sign => algorithm == KEY_ALGORITHM,
            Self::Approve => APPROVE_KEY_TYPES.contains(&algorithm),
        }
    }
}

fn derive(secret: &[u8], purpose: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(format!("clavix-approve/v1/{purpose}").as_bytes(), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// What the relay sees of the pairing secret: a token derived from it.
pub fn pair_token(secret: &[u8]) -> String {
    b64u(&derive(secret, "relay-pair"))
}

fn transcript(kind: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    write_string(&mut out, kind.as_bytes());
    for field in fields {
        write_string(&mut out, field);
    }
    out
}

fn mac(secret: &[u8], transcript: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&derive(secret, "pair-mac"))
        .expect("HMAC accepts any key length");
    mac.update(transcript);
    mac
}

/// The commitment to the agent's nonce that the hello carries.
pub fn commitment(nonce: &[u8]) -> [u8; 32] {
    Sha256::digest(transcript(COMMIT_LABEL, &[nonce])).into()
}

/// Everything the six digits are made of.
pub struct DigitsInput<'a> {
    pub mode: Mode,
    pub ch: &'a str,
    pub signer: &'a str,
    pub agent_kem: &'a [u8],
    pub agent_sig: &'a [u8],
    pub signer_kem: &'a [u8],
    pub signer_sig: &'a [u8],
    /// The device's SSH key (sign mode) or approval key (approve mode).
    pub key_blob: &'a [u8],
    pub agent_nonce: &'a [u8],
    pub signer_nonce: &'a [u8],
}

/// The six digits both ends display, e.g. "042 917".
pub fn digits(d: &DigitsInput) -> String {
    let digest = Sha256::digest(transcript(
        DIGITS_LABEL,
        &[
            d.mode.name().as_bytes(),
            d.ch.as_bytes(),
            d.signer.as_bytes(),
            d.agent_kem,
            d.agent_sig,
            d.signer_kem,
            d.signer_sig,
            d.key_blob,
            d.agent_nonce,
            d.signer_nonce,
        ],
    ));
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// A pairing in progress.
pub struct Offer {
    /// Channel id, 32 hex digits.
    pub ch: String,
    /// What the user enters on the device: the channel and a one-time secret.
    pub code: String,
    /// The agent's bearer token on the channel.
    pub agent_token: String,
    /// The agent's new long-term keys.
    pub identity: Identity,
    /// What the channel is for.
    pub mode: Mode,
    secret: [u8; 16],
    /// Committed to in the hello, revealed once the device has answered.
    nonce: [u8; NONCE_LENGTH],
}

/// A completed sign-mode pairing, not yet confirmed by the user.
pub struct Paired {
    pub signer: state::Signer,
    /// To compare with the device's display before trusting the pairing.
    pub fingerprint: String,
}

/// A device's answer, authenticated by the pairing secret, in either mode.
#[derive(Debug, Clone)]
pub struct Answer {
    /// Signer id on the channel (16 hex digits).
    pub id: String,
    /// The device's channel keys.
    pub peer: Peer,
    /// Its SSH key (sign mode) or approval key (approve mode), as an SSH
    /// public key blob of an accepted type.
    pub key_blob: Vec<u8>,
    /// The name it gives itself, reduced to `[A-Za-z0-9-_.@]`, never empty.
    pub comment: String,
    /// To compare with the device's display before trusting the pairing.
    pub fingerprint: String,
}

impl Answer {
    /// The key as an `authorized_keys`-style line.
    pub fn public_key_line(&self) -> Result<String, String> {
        let key = ssh_key::PublicKey::from_bytes(&self.key_blob)
            .map_err(|e| format!("invalid device key: {e}"))?;
        Ok(format!(
            "{} {} {}",
            key.algorithm().as_str(),
            STANDARD.encode(&self.key_blob),
            self.comment
        ))
    }
}

impl Offer {
    /// A new sign-mode channel.
    pub fn new() -> Self {
        Self::new_in(Mode::Sign)
    }

    /// A new channel in `mode`.
    pub fn new_in(mode: Mode) -> Self {
        Self::from_parts(random::<16>(), random::<16>(), random::<32>(), mode)
    }

    fn from_parts(ch: [u8; 16], secret: [u8; 16], token: [u8; 32], mode: Mode) -> Self {
        Self {
            ch: hex(&ch),
            code: format!("{CODE_PREFIX}{}", b64u(&[ch, secret].concat())),
            agent_token: b64u(&token),
            identity: Identity::generate(),
            mode,
            secret,
            nonce: random::<NONCE_LENGTH>(),
        }
    }

    /// A pairing of one more device on an existing sign-mode channel: same
    /// channel, same agent keys and token, a fresh one-time secret.
    pub fn for_channel(existing: &state::State) -> Result<Self, String> {
        let field = |b64: &str| unb64u(b64).ok_or("corrupt state: bad base64");
        let identity = Identity::from_secrets(
            &field(&existing.kem_private)?,
            &field(&existing.sig_private)?,
        )?;
        Self::for_existing(&existing.ch, &existing.agent_token, identity, Mode::Sign)
    }

    /// One more device on the channel `ch`, whose keys and token we hold.
    pub fn for_existing(
        ch: &str,
        agent_token: &str,
        identity: Identity,
        mode: Mode,
    ) -> Result<Self, String> {
        let raw: [u8; 16] = unhex(ch)
            .and_then(|v| v.try_into().ok())
            .ok_or("corrupt state: bad channel id")?;
        let secret = random::<16>();
        Ok(Self {
            ch: ch.to_string(),
            code: format!("{CODE_PREFIX}{}", b64u(&[raw, secret].concat())),
            agent_token: agent_token.to_string(),
            identity,
            mode,
            secret,
            nonce: random::<NONCE_LENGTH>(),
        })
    }

    /// Our public keys, the mode and the commitment to our nonce,
    /// authenticated by the pairing secret.
    fn hello(&self, label: &str) -> String {
        let (kem, sig) = (self.identity.kem_public(), self.identity.sig_public());
        let commit = commitment(&self.nonce);
        let tag = mac(
            &self.secret,
            &transcript(
                HELLO_LABEL,
                &[
                    self.mode.name().as_bytes(),
                    self.ch.as_bytes(),
                    kem,
                    &sig,
                    label.as_bytes(),
                    &commit,
                ],
            ),
        )
        .finalize()
        .into_bytes();
        let hello = json!({
            "v": PAIRING_VERSION,
            "mode": self.mode.name(),
            "label": label,
            "kem": b64u(kem),
            "sig": b64u(&sig),
            "commit": b64u(&commit),
            "mac": b64u(&tag),
        });
        b64u(hello.to_string().as_bytes())
    }

    /// Create the channel on the relay. `enroll_secret` is the relay's
    /// own admission secret.
    pub async fn open(
        &self,
        client: &RelayClient,
        enroll_secret: &str,
        label: &str,
    ) -> Result<(), PairingError> {
        let body = json!({
            "ch": self.ch,
            "agent_auth": token_auth(&self.agent_token),
            "pair_auth": token_auth(&pair_token(&self.secret)),
            "hello": self.hello(label),
        });
        let answer = client.post("/api/channels", enroll_secret, &body).await?;
        match answer.get("state").and_then(Value::as_str) {
            Some("created") => Ok(()),
            other => Err(PairingError::Refused(format!(
                "the relay did not create the channel ({})",
                other.unwrap_or("?")
            ))),
        }
    }

    /// Open the existing channel to one more device (see `for_channel`).
    pub async fn open_on_channel(
        &self,
        client: &RelayClient,
        label: &str,
    ) -> Result<(), PairingError> {
        let body = json!({
            "pair_auth": token_auth(&pair_token(&self.secret)),
            "hello": self.hello(label),
        });
        let answer = client
            .post(
                &format!("/api/ch/{}/pair/open", self.ch),
                &self.agent_token,
                &body,
            )
            .await
            .map_err(|e| match e {
                RelayError::Status(401) => PairingError::Gone,
                e => PairingError::Relay(e),
            })?;
        match answer.get("state").and_then(Value::as_str) {
            Some("open") => Ok(()),
            Some("full") => Err(PairingError::Refused(
                "this pairing already has as many devices as the relay allows".into(),
            )),
            other => Err(PairingError::Refused(format!(
                "the relay did not open the pairing ({})",
                other.unwrap_or("?")
            ))),
        }
    }

    /// Wait for the device to answer, at most `max` (sign mode).
    pub async fn wait_for_signer(
        &self,
        client: &RelayClient,
        max: Duration,
    ) -> Result<Paired, PairingError> {
        self.wait_for_answer(client, max).await.map(Self::paired)
    }

    /// Wait for the device to answer, at most `max`, in the offer's mode;
    /// then reveal our nonce to it, so that it can compute the digits.
    pub async fn wait_for_answer(
        &self,
        client: &RelayClient,
        max: Duration,
    ) -> Result<Answer, PairingError> {
        let deadline = Instant::now() + max;
        let path = format!("/api/ch/{}/pair/answer?wait=25", self.ch);
        loop {
            if Instant::now() >= deadline {
                return Err(PairingError::Expired);
            }
            // Any error ends the wait: a 4xx must not be retried, and a
            // relay that went away took the channel with it.
            match client.get(&path, &self.agent_token).await? {
                None => continue,
                Some(reply) => {
                    let answer = self.read_reply(&reply)?;
                    self.reveal(client, &answer.id).await?;
                    return Ok(answer);
                }
            }
        }
    }

    /// Hand our nonce to the device `signer`, through the relay. Only once
    /// its answer has been read and authenticated: its keys and nonce are
    /// then fixed, and nobody can steer the digits any more.
    /// [`Offer::wait_for_answer`] does it; a caller of
    /// [`Offer::read_reply`] must do it itself.
    pub async fn reveal(&self, client: &RelayClient, signer: &str) -> Result<(), PairingError> {
        let answer = client
            .post(
                &format!("/api/ch/{}/pair/reveal", self.ch),
                &self.agent_token,
                &json!({ "signer": signer, "nonce": b64u(&self.nonce) }),
            )
            .await?;
        match answer.get("state").and_then(Value::as_str) {
            Some("revealed") => Ok(()),
            other => Err(PairingError::Refused(format!(
                "the relay did not pass the pairing on ({})",
                other.unwrap_or("?")
            ))),
        }
    }

    /// A sign-mode answer, as the agent stores it.
    fn paired(answer: Answer) -> Paired {
        Paired {
            signer: state::Signer {
                public_key: format!(
                    "{KEY_ALGORITHM} {} {}",
                    STANDARD.encode(&answer.key_blob),
                    answer.comment
                ),
                kem_public: b64u(answer.peer.kem_public()),
                sig_public: b64u(&answer.peer.sig_public()),
                id: answer.id,
            },
            fingerprint: answer.fingerprint,
        }
    }

    #[cfg(test)]
    fn read_answer(&self, answer: &Value) -> Result<Paired, PairingError> {
        self.read_reply(answer).map(Self::paired)
    }

    /// Read the device's answer (`{ signer, msg }` from the relay) and
    /// authenticate it with the pairing secret, in the offer's mode. It
    /// does not reveal our nonce: see [`Offer::reveal`].
    pub fn read_reply(&self, answer: &Value) -> Result<Answer, PairingError> {
        let text = |v: &Value, name: &str| v.get(name).and_then(Value::as_str).map(str::to_string);
        let bytes = |v: &Value, name: &str| text(v, name).and_then(|s| unb64u(&s));

        let id = text(answer, "signer")
            .filter(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("pairing answer without a valid signer id")?;
        let msg = text(answer, "msg").ok_or("pairing answer without content")?;
        let (inner, sender_sig) =
            open_introduction(&self.identity, &pair_header(&self.ch, &id), &msg)
                .map_err(|e| format!("unreadable pairing answer: {e}"))?;

        if inner.get("v").and_then(Value::as_u64) != Some(PAIRING_VERSION) {
            return Err("the device uses an older pairing protocol: \
                        update the Clavix Approve app, then pair again"
                .into());
        }
        let blob = bytes(&inner, self.mode.key_field()).ok_or(match self.mode {
            Mode::Sign => "pairing answer without a key",
            Mode::Approve => "pairing answer without an approval key: not an approve-mode device",
        })?;
        let kem = bytes(&inner, "kem").ok_or("pairing answer without an HPKE key")?;
        let nonce = bytes(&inner, "nonce")
            .filter(|n| n.len() == NONCE_LENGTH)
            .ok_or("pairing answer without a valid nonce")?;
        let tag = bytes(&inner, "mac").ok_or("pairing answer without a MAC")?;
        let signer = Peer::new(&kem, &sender_sig)?;
        let commit = commitment(&self.nonce);

        // Only someone who was given the pairing code can produce this.
        mac(
            &self.secret,
            &transcript(
                ANSWER_LABEL,
                &[
                    self.mode.name().as_bytes(),
                    self.ch.as_bytes(),
                    id.as_bytes(),
                    signer.kem_public(),
                    &signer.sig_public(),
                    &blob,
                    &nonce,
                    self.identity.kem_public(),
                    &self.identity.sig_public(),
                    &commit,
                ],
            ),
        )
        .verify_slice(&tag)
        .map_err(|_| "the pairing answer was not made with this pairing code")?;

        let key = ssh_key::PublicKey::from_bytes(&blob)
            .map_err(|e| format!("invalid signer key: {e}"))?;
        if !self.mode.accepts(key.algorithm().as_str()) {
            return Err(PairingError::Invalid(format!(
                "unsupported signer key type {}",
                key.algorithm().as_str()
            )));
        }
        // The comment ends up in a file the user will paste into authorized_keys.
        let comment: String = text(&inner, "comment")
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "-_.@".contains(*c))
            .take(32)
            .collect();
        let comment = if comment.is_empty() {
            "clavix-approve".to_string()
        } else {
            comment
        };
        let fingerprint = digits(&DigitsInput {
            mode: self.mode,
            ch: &self.ch,
            signer: &id,
            agent_kem: self.identity.kem_public(),
            agent_sig: &self.identity.sig_public(),
            signer_kem: signer.kem_public(),
            signer_sig: &signer.sig_public(),
            key_blob: &blob,
            agent_nonce: &self.nonce,
            signer_nonce: &nonce,
        });
        Ok(Answer {
            fingerprint,
            id,
            peer: signer,
            key_blob: blob,
            comment,
        })
    }
}

/// The pairing code as a link for the Clavix Approve app, for a QR code:
/// `clavix-approve://pair?relay=<relay URL>#<code>`. The system camera
/// hands it to the app; no web page, least of all one the relay serves,
/// ever sees the code.
pub fn pairing_url(relay: &str, code: &str) -> String {
    let mut encoded = String::new();
    for b in relay.trim_end_matches('/').bytes() {
        // Unreserved characters, and ':' '/' '@', which a query holds as is.
        if b.is_ascii_alphanumeric() || b"-._~:/@".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    format!("{APP_SCHEME}://pair?relay={encoded}#{code}")
}

impl Default for Offer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::channel::seal;

    use super::*;

    const P256_LINE: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHwf2HMM5TRXvo2SQJjsNkiDD5KqiiNjrGVv3UUh+mMT5RHxiRtOnlqvjhQtBq0VpmpCV/PwUdhOig4vkbqAcEc=";
    const SIGNER_ID: &str = "0123456789abcdef";
    const PHONE_NONCE: [u8; NONCE_LENGTH] = [9; NONCE_LENGTH];

    fn blob_of(line: &str) -> Vec<u8> {
        ssh_key::PublicKey::from_openssh(line)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    /// The reply the relay hands the agent, with `inner` sealed by `phone`.
    fn reply(offer: &Offer, phone: &Identity, inner: &Value) -> Value {
        let agent = Peer::new(offer.identity.kem_public(), &offer.identity.sig_public()).unwrap();
        let sealed = seal(phone, &agent, &pair_header(&offer.ch, SIGNER_ID), inner).unwrap();
        let intro = [&phone.sig_public()[..], &unb64u(&sealed).unwrap()].concat();
        json!({ "state": "answered", "signer": SIGNER_ID, "msg": b64u(&intro) })
    }

    /// What a device that knows `secret` would answer, in the offer's mode.
    fn answer(offer: &Offer, phone: &Identity, secret: &[u8], key: &[u8], comment: &str) -> Value {
        let tag = mac(
            secret,
            &transcript(
                ANSWER_LABEL,
                &[
                    offer.mode.name().as_bytes(),
                    offer.ch.as_bytes(),
                    SIGNER_ID.as_bytes(),
                    phone.kem_public(),
                    &phone.sig_public(),
                    key,
                    &PHONE_NONCE,
                    offer.identity.kem_public(),
                    &offer.identity.sig_public(),
                    &commitment(&offer.nonce),
                ],
            ),
        )
        .finalize()
        .into_bytes();
        let inner = json!({
            "t": "pair", "v": 2, "key": b64u(key), "comment": comment,
            "kem": b64u(phone.kem_public()), "nonce": b64u(&PHONE_NONCE), "mac": b64u(&tag),
        });
        reply(offer, phone, &inner)
    }

    #[test]
    fn the_code_carries_the_channel_and_the_secret_but_not_the_token() {
        let offer = Offer::from_parts([0xab; 16], [0xcd; 16], [0xef; 32], Mode::Sign);
        assert_eq!(offer.ch, "ab".repeat(16));
        assert!(offer.code.starts_with("cva2-"));
        let raw = unb64u(offer.code.strip_prefix(CODE_PREFIX).unwrap()).unwrap();
        assert_eq!(raw, [[0xab; 16], [0xcd; 16]].concat());
        assert_ne!(Offer::new().code, Offer::new().code);
        assert_ne!(Offer::new().nonce, Offer::new().nonce);
    }

    /// Fixed vector shared with the JavaScript side (web/test).
    #[test]
    fn pair_token_matches_the_shared_vector() {
        assert_eq!(
            pair_token(&[7u8; 16]),
            include_str!("../../testdata/pair-token-07.txt").trim()
        );
    }

    #[test]
    fn an_answer_made_with_the_code_pairs_and_its_comment_is_cleaned() {
        let offer = Offer::new();
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        let paired = offer
            .read_answer(&answer(
                &offer,
                &phone,
                &offer.secret,
                &blob,
                "my phone\n ssh-rsa AAAA evil",
            ))
            .unwrap();
        assert_eq!(paired.signer.id, SIGNER_ID);
        assert_eq!(
            paired.signer.public_key,
            format!("{P256_LINE} myphonessh-rsaAAAAevil")
        );
        assert_eq!(paired.signer.kem_public, b64u(phone.kem_public()));
        assert_eq!(paired.signer.sig_public, b64u(&phone.sig_public()));
        assert_eq!(paired.fingerprint.len(), 7);
        assert!(paired
            .fingerprint
            .chars()
            .all(|c| c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn the_digits_depend_on_the_agents_hidden_nonce() {
        // The same device answer, given to two offers that differ only by
        // their nonce, gives other digits: a relay that holds the secret
        // cannot pick the device's keys to match the agent's digits.
        let mut offer = Offer::new();
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        offer.nonce = [1; NONCE_LENGTH];
        let first = offer
            .read_reply(&answer(&offer, &phone, &offer.secret, &blob, "x"))
            .unwrap();
        offer.nonce = [2; NONCE_LENGTH];
        let second = offer
            .read_reply(&answer(&offer, &phone, &offer.secret, &blob, "x"))
            .unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
        // And an answer made for another commitment does not authenticate.
        let mut stale = answer(&offer, &phone, &offer.secret, &blob, "x");
        offer.nonce = [3; NONCE_LENGTH];
        assert!(offer
            .read_reply(&stale)
            .is_err_and(|e| e.to_string().contains("pairing code")));
        stale["signer"] = json!("../../etc");
        assert!(offer.read_reply(&stale).is_err());
    }

    #[test]
    fn an_answer_made_without_the_code_is_refused() {
        let offer = Offer::new();
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        // The relay, or anyone who saw the channel id, knows no secret.
        let forged = answer(&offer, &phone, &[0u8; 16], &blob, "x");
        assert!(offer
            .read_answer(&forged)
            .is_err_and(|e| e.to_string().contains("pairing code")));
        // A genuine answer replayed to another offer does not open.
        let other = Offer::new();
        let genuine = answer(&offer, &phone, &offer.secret, &blob, "x");
        assert!(other.read_answer(&genuine).is_err());
    }

    #[test]
    fn an_answer_of_the_first_protocol_version_is_refused_clearly() {
        let offer = Offer::new();
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        let old = reply(
            &offer,
            &phone,
            &json!({
                "t": "pair", "key": b64u(&blob), "comment": "x",
                "kem": b64u(phone.kem_public()), "mac": b64u(&[0u8; 32]),
            }),
        );
        assert!(offer
            .read_reply(&old)
            .is_err_and(|e| e.to_string().contains("older pairing protocol")));
        // Without a nonce of the right length, even under version 2.
        let mut inner = json!({
            "t": "pair", "v": 2, "key": b64u(&blob), "comment": "x",
            "kem": b64u(phone.kem_public()), "nonce": b64u(&[1u8; 16]), "mac": b64u(&[0u8; 32]),
        });
        assert!(offer
            .read_reply(&reply(&offer, &phone, &inner))
            .is_err_and(|e| e.to_string().contains("nonce")));
        inner.as_object_mut().unwrap().remove("nonce");
        assert!(offer
            .read_reply(&reply(&offer, &phone, &inner))
            .is_err_and(|e| e.to_string().contains("nonce")));
    }

    #[test]
    fn other_key_types_and_garbage_are_refused() {
        let offer = Offer::new();
        let phone = Identity::generate();
        let ed = blob_of(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        );
        assert!(offer
            .read_answer(&answer(&offer, &phone, &offer.secret, &ed, "x"))
            .is_err_and(|e| e.to_string().contains("unsupported")));
        assert!(offer
            .read_answer(&answer(&offer, &phone, &offer.secret, b"junk", "x"))
            .is_err());
        assert!(offer.read_answer(&json!({ "state": "answered" })).is_err());
        assert!(offer
            .read_answer(&json!({ "signer": "../../etc", "msg": "AAAA" }))
            .is_err());
    }

    #[test]
    fn the_link_opens_the_app_with_the_code_in_the_fragment() {
        let url = pairing_url("https://approve.example/", "cva2-abc");
        assert_eq!(
            url,
            "clavix-approve://pair?relay=https://approve.example#cva2-abc"
        );
        // What a query cannot hold as is gets escaped.
        assert_eq!(
            pairing_url("https://relay.example:8443/a b?c=d&e#f", "cva2-x"),
            "clavix-approve://pair?relay=https://relay.example:8443/a%20b%3Fc%3Dd%26e%23f#cva2-x"
        );
    }

    #[test]
    fn the_hello_is_authenticated_by_the_secret_and_commits_to_the_nonce() {
        let offer = Offer::new();
        let hello: Value =
            serde_json::from_slice(&unb64u(&offer.hello("build-box")).unwrap()).unwrap();
        assert_eq!(hello["v"], 2);
        assert_eq!(hello["mode"], "sign");
        assert_eq!(hello["label"], "build-box");
        assert_eq!(hello["kem"], b64u(offer.identity.kem_public()));
        let commit = commitment(&offer.nonce);
        assert_eq!(hello["commit"], b64u(&commit));
        // The nonce itself is nowhere in the hello.
        assert!(!hello.to_string().contains(&b64u(&offer.nonce)));
        let expected = transcript(
            HELLO_LABEL,
            &[
                b"sign",
                offer.ch.as_bytes(),
                offer.identity.kem_public(),
                &offer.identity.sig_public(),
                b"build-box",
                &commit,
            ],
        );
        let tag = unb64u(hello["mac"].as_str().unwrap()).unwrap();
        assert!(mac(&offer.secret, &expected).verify_slice(&tag).is_ok());
        assert!(mac(&[0u8; 16], &expected).verify_slice(&tag).is_err());
    }

    /// The vectors shared with the page and the iOS app
    /// (testdata/pairing.json): same commitment, MACs and digits, in both
    /// modes.
    #[test]
    fn pairing_matches_the_shared_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../testdata/pairing.json")).unwrap();
        let s = |path: &[&str]| {
            path.iter()
                .fold(&v, |v, k| &v[*k])
                .as_str()
                .unwrap()
                .to_string()
        };
        let identity = |who: &str| {
            Identity::from_secrets(
                &unhex(&s(&[who, "kem_private"])).unwrap(),
                &unhex(&s(&[who, "sig_seed"])).unwrap(),
            )
            .unwrap()
        };
        let phone = identity("signer_keys");
        let secret: [u8; 16] = unhex(&s(&["secret"])).unwrap().try_into().unwrap();
        let nonce: [u8; NONCE_LENGTH] = unhex(&s(&["agent_nonce"])).unwrap().try_into().unwrap();
        let phone_nonce = unhex(&s(&["signer_nonce"])).unwrap();
        let ch = s(&["channel"]);
        let signer = s(&["signer"]);
        assert_eq!(b64u(&commitment(&nonce)), s(&["commit"]));

        for case in v["modes"].as_array().unwrap() {
            let mode: Mode = serde_json::from_value(case["mode"].clone()).unwrap();
            let offer = Offer {
                code: s(&["code"]),
                ch: ch.clone(),
                agent_token: "t".into(),
                identity: identity("agent"),
                mode,
                secret,
                nonce,
            };
            assert_eq!(hex(offer.identity.kem_public()), s(&["agent", "kem"]));
            assert_eq!(
                offer.code,
                format!(
                    "{CODE_PREFIX}{}",
                    b64u(&[unhex(&ch).unwrap(), secret.to_vec()].concat())
                )
            );
            let hello: Value =
                serde_json::from_slice(&unb64u(&offer.hello(&s(&["label"]))).unwrap()).unwrap();
            assert_eq!(hello["mac"], case["hello_mac"]);
            assert_eq!(hello["mode"], case["mode"]);

            for a in case["answers"].as_array().unwrap() {
                let blob = unb64u(a["key"].as_str().unwrap()).unwrap();
                // A device answering with the vector's MAC is accepted, and
                // both ends show the vector's digits.
                let inner = json!({
                    "t": "pair", "v": 2, mode.key_field(): a["key"], "comment": "phone",
                    "kem": b64u(phone.kem_public()), "nonce": b64u(&phone_nonce),
                    "mac": a["answer_mac"],
                });
                let sealed = seal(
                    &phone,
                    &Peer::new(offer.identity.kem_public(), &offer.identity.sig_public()).unwrap(),
                    &pair_header(&ch, &signer),
                    &inner,
                )
                .unwrap();
                let intro = [&phone.sig_public()[..], &unb64u(&sealed).unwrap()].concat();
                let reply = json!({ "signer": signer, "msg": b64u(&intro) });
                let answer = offer.read_reply(&reply).unwrap();
                assert_eq!(answer.fingerprint, a["digits"].as_str().unwrap());
                assert_eq!(answer.key_blob, blob);
                assert_eq!(answer.comment, "phone");
                // The same answer given to the other mode does not pass.
                let other = Offer {
                    code: s(&["code"]),
                    ch: ch.clone(),
                    agent_token: "t".into(),
                    identity: identity("agent"),
                    mode: if mode == Mode::Sign {
                        Mode::Approve
                    } else {
                        Mode::Sign
                    },
                    secret,
                    nonce,
                };
                assert!(other.read_reply(&reply).is_err());
            }
        }
    }

    #[test]
    fn an_approve_mode_answer_needs_an_approval_key() {
        let offer = Offer::new_in(Mode::Approve);
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        // A sign-mode answer (`key`) to an approve-mode offer.
        let sign_answer = answer(&offer, &phone, &offer.secret, &blob, "x");
        assert!(offer
            .read_reply(&sign_answer)
            .is_err_and(|e| e.to_string().contains("approval key")));
    }
}
