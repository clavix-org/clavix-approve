//! One-time pairing with the device that will sign.
//!
//! The agent opens a channel on the relay and shows a pairing code: the
//! channel id and a one-time secret. The user enters it on the device,
//! which answers with its public keys. The relay only ever sees a token
//! derived from the secret; a MAC keyed by another derivation
//! authenticates the keys both sides exchange through it. The six digits
//! shown at the end are a last check by eye that both ends hold the same
//! keys. Mirrored by `web/lib/pairing.js`.

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

pub const CODE_PREFIX: &str = "cva1-";
/// The relay forgets a channel nobody joined after 15 minutes.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(14 * 60);
const KEY_ALGORITHM: &str = "ecdsa-sha2-nistp256";
/// Approval keys a requester accepts (PROTOCOL.md, "Approval key").
pub const APPROVE_KEY_TYPES: [&str; 2] = ["ssh-ed25519", "ecdsa-sha2-nistp256"];

/// What a channel is for, set at pairing and for good (PROTOCOL.md,
/// "Approve mode"). Each mode has its own labels, so that a relay flipping
/// the mode breaks a MAC or the digits.
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
    fn hello_label(self) -> &'static str {
        match self {
            Self::Sign => "hello",
            Self::Approve => "approve-hello",
        }
    }

    fn answer_label(self) -> &'static str {
        match self {
            Self::Sign => "answer",
            Self::Approve => "approve-answer",
        }
    }

    fn fingerprint_label(self) -> &'static str {
        match self {
            Self::Sign => "clavix-approve/v1/fingerprint",
            Self::Approve => "clavix-approve/v1/approve-fingerprint",
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

/// Six digits both ends display once paired, e.g. "042 917" (sign mode).
pub fn fingerprint(agent: &Identity, signer: &Peer, key_blob: &[u8]) -> String {
    fingerprint_in(Mode::Sign, agent, signer, key_blob)
}

/// The six digits of a pairing in `mode`; `key_blob` is the device's SSH
/// key (sign mode) or approval key (approve mode).
pub fn fingerprint_in(mode: Mode, agent: &Identity, signer: &Peer, key_blob: &[u8]) -> String {
    let digest = Sha256::digest(transcript(
        mode.fingerprint_label(),
        &[
            agent.kem_public(),
            &agent.sig_public(),
            signer.kem_public(),
            &signer.sig_public(),
            key_blob,
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
        })
    }

    /// Our public keys, authenticated by the pairing secret. An
    /// approve-mode hello says so, under its own MAC label.
    fn hello(&self, label: &str) -> String {
        let (kem, sig) = (self.identity.kem_public(), self.identity.sig_public());
        let tag = mac(
            &self.secret,
            &transcript(
                self.mode.hello_label(),
                &[self.ch.as_bytes(), kem, &sig, label.as_bytes()],
            ),
        )
        .finalize()
        .into_bytes();
        let mut hello =
            json!({ "label": label, "kem": b64u(kem), "sig": b64u(&sig), "mac": b64u(&tag) });
        if self.mode == Mode::Approve {
            hello["mode"] = json!("approve");
        }
        b64u(hello.to_string().as_bytes())
    }

    /// Create the channel on the relay. `enroll_secret` is the relay's
    /// own admission secret.
    pub async fn open(
        &self,
        client: &RelayClient,
        enroll_secret: &str,
        label: &str,
    ) -> Result<(), String> {
        let body = json!({
            "ch": self.ch,
            "agent_auth": token_auth(&self.agent_token),
            "pair_auth": token_auth(&pair_token(&self.secret)),
            "hello": self.hello(label),
        });
        let answer = client
            .post("/api/channels", enroll_secret, &body)
            .await
            .map_err(|e| e.to_string())?;
        match answer.get("state").and_then(Value::as_str) {
            Some("created") => Ok(()),
            other => Err(format!(
                "the relay did not create the channel ({})",
                other.unwrap_or("?")
            )),
        }
    }

    /// Open the existing channel to one more device (see `for_channel`).
    pub async fn open_on_channel(&self, client: &RelayClient, label: &str) -> Result<(), String> {
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
                RelayError::Status(401) => {
                    "the relay no longer knows this pairing; run `clavix-agent pair` without --add"
                        .to_string()
                }
                e => e.to_string(),
            })?;
        match answer.get("state").and_then(Value::as_str) {
            Some("open") => Ok(()),
            Some("full") => {
                Err("this pairing already has as many devices as the relay allows".into())
            }
            other => Err(format!(
                "the relay did not open the pairing ({})",
                other.unwrap_or("?")
            )),
        }
    }

    /// Wait for the device to answer, at most `max` (sign mode).
    pub async fn wait_for_signer(
        &self,
        client: &RelayClient,
        max: Duration,
    ) -> Result<Paired, String> {
        self.wait_for_answer(client, max).await.map(Self::paired)
    }

    /// Wait for the device to answer, at most `max`, in the offer's mode.
    pub async fn wait_for_answer(
        &self,
        client: &RelayClient,
        max: Duration,
    ) -> Result<Answer, String> {
        let deadline = Instant::now() + max;
        let path = format!("/api/ch/{}/pair/answer?wait=25", self.ch);
        loop {
            if Instant::now() >= deadline {
                return Err("nobody entered the pairing code in time".into());
            }
            // Any error ends the wait: a 4xx must not be retried, and a
            // relay that went away took the channel with it.
            match client
                .get(&path, &self.agent_token)
                .await
                .map_err(|e| e.to_string())?
            {
                None => continue,
                Some(answer) => return self.read_reply(&answer),
            }
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
    fn read_answer(&self, answer: &Value) -> Result<Paired, String> {
        self.read_reply(answer).map(Self::paired)
    }

    /// Read the device's answer (`{ signer, msg }` from the relay) and
    /// authenticate it with the pairing secret, in the offer's mode.
    pub fn read_reply(&self, answer: &Value) -> Result<Answer, String> {
        let text = |v: &Value, name: &str| v.get(name).and_then(Value::as_str).map(str::to_string);
        let bytes = |v: &Value, name: &str| text(v, name).and_then(|s| unb64u(&s));

        let id = text(answer, "signer")
            .filter(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("pairing answer without a valid signer id")?;
        let msg = text(answer, "msg").ok_or("pairing answer without content")?;
        let (inner, sender_sig) =
            open_introduction(&self.identity, &pair_header(&self.ch, &id), &msg)
                .map_err(|e| format!("unreadable pairing answer: {e}"))?;

        let blob = bytes(&inner, self.mode.key_field()).ok_or(match self.mode {
            Mode::Sign => "pairing answer without a key",
            Mode::Approve => "pairing answer without an approval key: not an approve-mode device",
        })?;
        let kem = bytes(&inner, "kem").ok_or("pairing answer without an HPKE key")?;
        let tag = bytes(&inner, "mac").ok_or("pairing answer without a MAC")?;
        let signer = Peer::new(&kem, &sender_sig)?;

        // Only someone who was given the pairing code can produce this.
        mac(
            &self.secret,
            &transcript(
                self.mode.answer_label(),
                &[
                    self.ch.as_bytes(),
                    id.as_bytes(),
                    signer.kem_public(),
                    &signer.sig_public(),
                    &blob,
                    self.identity.kem_public(),
                    &self.identity.sig_public(),
                ],
            ),
        )
        .verify_slice(&tag)
        .map_err(|_| "the pairing answer was not made with this pairing code")?;

        let key = ssh_key::PublicKey::from_bytes(&blob)
            .map_err(|e| format!("invalid signer key: {e}"))?;
        if !self.mode.accepts(key.algorithm().as_str()) {
            return Err(format!(
                "unsupported signer key type {}",
                key.algorithm().as_str()
            ));
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
        Ok(Answer {
            fingerprint: fingerprint_in(self.mode, &self.identity, &signer, &blob),
            id,
            peer: signer,
            key_blob: blob,
            comment,
        })
    }
}

/// The pairing code as a link to the approval page, for a QR code: the
/// phone's camera opens the page with the code in the URL fragment, which
/// is never sent to the server.
pub fn pairing_url(relay: &str, code: &str) -> String {
    format!("{}/#{code}", relay.trim_end_matches('/'))
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

    fn blob_of(line: &str) -> Vec<u8> {
        ssh_key::PublicKey::from_openssh(line)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    /// What a device that knows `secret` would answer.
    fn answer(offer: &Offer, phone: &Identity, secret: &[u8], key: &[u8], comment: &str) -> Value {
        let agent = Peer::new(offer.identity.kem_public(), &offer.identity.sig_public()).unwrap();
        let tag = mac(
            secret,
            &transcript(
                "answer",
                &[
                    offer.ch.as_bytes(),
                    SIGNER_ID.as_bytes(),
                    phone.kem_public(),
                    &phone.sig_public(),
                    key,
                    agent.kem_public(),
                    &agent.sig_public(),
                ],
            ),
        )
        .finalize()
        .into_bytes();
        let inner = json!({
            "t": "pair", "key": b64u(key), "comment": comment,
            "kem": b64u(phone.kem_public()), "mac": b64u(&tag),
        });
        let sealed = seal(phone, &agent, &pair_header(&offer.ch, SIGNER_ID), &inner).unwrap();
        let intro = [&phone.sig_public()[..], &unb64u(&sealed).unwrap()].concat();
        json!({ "state": "answered", "signer": SIGNER_ID, "msg": b64u(&intro) })
    }

    #[test]
    fn the_code_carries_the_channel_and_the_secret_but_not_the_token() {
        let offer = Offer::from_parts([0xab; 16], [0xcd; 16], [0xef; 32], Mode::Sign);
        assert_eq!(offer.ch, "ab".repeat(16));
        let raw = unb64u(offer.code.strip_prefix(CODE_PREFIX).unwrap()).unwrap();
        assert_eq!(raw, [[0xab; 16], [0xcd; 16]].concat());
        assert_ne!(Offer::new().code, Offer::new().code);
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
    fn an_answer_made_without_the_code_is_refused() {
        let offer = Offer::new();
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        // The relay, or anyone who saw the channel id, knows no secret.
        let forged = answer(&offer, &phone, &[0u8; 16], &blob, "x");
        assert!(offer
            .read_answer(&forged)
            .is_err_and(|e| e.contains("pairing code")));
        // A genuine answer replayed to another offer does not open.
        let other = Offer::new();
        let genuine = answer(&offer, &phone, &offer.secret, &blob, "x");
        assert!(other.read_answer(&genuine).is_err());
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
            .is_err_and(|e| e.contains("unsupported")));
        assert!(offer
            .read_answer(&answer(&offer, &phone, &offer.secret, b"junk", "x"))
            .is_err());
        assert!(offer.read_answer(&json!({ "state": "answered" })).is_err());
        assert!(offer
            .read_answer(&json!({ "signer": "../../etc", "msg": "AAAA" }))
            .is_err());
    }

    #[test]
    fn the_link_puts_the_code_in_the_fragment() {
        let url = pairing_url("https://approve.example/", "cva1-abc");
        assert_eq!(url, "https://approve.example/#cva1-abc");
    }

    #[test]
    fn the_hello_is_authenticated_by_the_secret() {
        let offer = Offer::new();
        let hello: Value =
            serde_json::from_slice(&unb64u(&offer.hello("build-box")).unwrap()).unwrap();
        assert_eq!(hello["label"], "build-box");
        assert_eq!(hello["kem"], b64u(offer.identity.kem_public()));
        let expected = transcript(
            "hello",
            &[
                offer.ch.as_bytes(),
                offer.identity.kem_public(),
                &offer.identity.sig_public(),
                b"build-box",
            ],
        );
        let tag = unb64u(hello["mac"].as_str().unwrap()).unwrap();
        assert!(mac(&offer.secret, &expected).verify_slice(&tag).is_ok());
        assert!(mac(&[0u8; 16], &expected).verify_slice(&tag).is_err());
        assert!(hello.get("mode").is_none());
    }

    /// The approve-mode vector shared with the page and the iOS app
    /// (testdata/approve-pairing.json): same MACs, same digits.
    #[test]
    fn approve_mode_matches_the_shared_vector() {
        let v: Value =
            serde_json::from_str(include_str!("../../testdata/approve-pairing.json")).unwrap();
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
        let ch = s(&["channel"]);
        let offer_in = |mode| Offer {
            code: s(&["code"]),
            ch: ch.clone(),
            agent_token: "t".into(),
            identity: identity("agent"),
            mode,
            secret,
        };
        let offer = offer_in(Mode::Approve);
        assert_eq!(hex(offer.identity.kem_public()), s(&["agent", "kem"]));
        assert_eq!(
            offer.code,
            format!(
                "{CODE_PREFIX}{}",
                b64u(&[unhex(&ch).unwrap(), secret.to_vec()].concat())
            )
        );

        // The hello: its MAC, and the mode it announces.
        let hello: Value =
            serde_json::from_slice(&unb64u(&offer.hello(&s(&["label"]))).unwrap()).unwrap();
        assert_eq!(hello["mac"], s(&["hello_mac"]));
        assert_eq!(hello["mode"], "approve");

        let signer = s(&["signer"]);
        let agent = Peer::new(offer.identity.kem_public(), &offer.identity.sig_public()).unwrap();
        for case in v["answers"].as_array().unwrap() {
            let blob = unb64u(case["approve"].as_str().unwrap()).unwrap();
            // A device answering with the vector's MAC is accepted, and both
            // ends show the vector's digits.
            let inner = json!({
                "t": "pair", "approve": case["approve"], "comment": "phone",
                "kem": b64u(phone.kem_public()), "mac": case["answer_mac"],
            });
            let sealed = seal(&phone, &agent, &pair_header(&ch, &signer), &inner).unwrap();
            let intro = [&phone.sig_public()[..], &unb64u(&sealed).unwrap()].concat();
            let reply = json!({ "signer": signer, "msg": b64u(&intro) });
            let answer = offer.read_reply(&reply).unwrap();
            assert_eq!(answer.fingerprint, case["digits"].as_str().unwrap());
            assert_eq!(answer.key_blob, blob);
            assert_eq!(answer.comment, "phone");
            // The same answer is no sign-mode one: no `key`, other labels.
            assert!(offer_in(Mode::Sign).read_reply(&reply).is_err());
        }
    }

    #[test]
    fn an_approve_mode_answer_needs_an_approval_key_under_its_own_mac() {
        let offer = Offer::new_in(Mode::Approve);
        let phone = Identity::generate();
        let blob = blob_of(P256_LINE);
        // A sign-mode answer (`key`, label "answer") to an approve-mode offer.
        let sign_answer = answer(&offer, &phone, &offer.secret, &blob, "x");
        assert!(offer
            .read_reply(&sign_answer)
            .is_err_and(|e| e.contains("approval key")));
    }
}
