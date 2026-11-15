//! The end-to-end channel between the agent and the signer.
//!
//! Every message is encrypted to the recipient's static key (HPKE, RFC
//! 9180: DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, base mode)
//! and signed by the sender's (Ed25519). The relay in between sees sizes
//! and timing only, and cannot forge, alter or redirect a message: what it
//! could tamper with (channel, request id, expiry) is bound to the
//! ciphertext through the header.
//!
//! ```text
//! msg       = base64url( signature(64) || enc(65) || ciphertext )
//! info      = "clavix-approve/v1 hpke" || sender signing key || recipient HPKE key
//! signature = Ed25519( "clavix-approve/v1 sig" || string(header) || string(enc) || string(ciphertext) )
//! ```
//!
//! The same layout is implemented in `web/lib/channel.js`.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::{DhP256HkdfSha256, Kem as KemTrait};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use serde_json::Value;

use crate::proto::write_string;
use crate::relay::{b64u, random, unb64u};

type Kem = DhP256HkdfSha256;
type KemPrivate = <Kem as KemTrait>::PrivateKey;
type KemPublic = <Kem as KemTrait>::PublicKey;
type Encapped = <Kem as KemTrait>::EncappedKey;

const LABEL: &str = "clavix-approve/v1";
const SIG_LENGTH: usize = 64;
/// An uncompressed P-256 point.
pub const KEM_KEY_LENGTH: usize = 65;
pub const SIG_KEY_LENGTH: usize = 32;

/// Our long-term keys.
pub struct Identity {
    kem_private: KemPrivate,
    kem_public: Vec<u8>,
    sig: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let (kem_private, kem_public) = Kem::gen_keypair();
        Self {
            kem_private,
            kem_public: kem_public.to_bytes().to_vec(),
            sig: SigningKey::from_bytes(&random::<32>()),
        }
    }

    /// Rebuild from what [`Identity::secrets`] returned.
    pub fn from_secrets(kem_private: &[u8], sig_seed: &[u8]) -> Result<Self, String> {
        let kem_private =
            KemPrivate::from_bytes(kem_private).map_err(|_| "invalid HPKE private key")?;
        let seed: [u8; 32] = sig_seed.try_into().map_err(|_| "invalid signing key")?;
        Ok(Self {
            kem_public: Kem::sk_to_pk(&kem_private).to_bytes().to_vec(),
            kem_private,
            sig: SigningKey::from_bytes(&seed),
        })
    }

    /// (HPKE private key, signing seed): to be stored privately.
    pub fn secrets(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.kem_private.to_bytes().to_vec(),
            self.sig.to_bytes().to_vec(),
        )
    }

    pub fn kem_public(&self) -> &[u8] {
        &self.kem_public
    }

    pub fn sig_public(&self) -> [u8; SIG_KEY_LENGTH] {
        self.sig.verifying_key().to_bytes()
    }
}

/// The other side's public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    kem_public: Vec<u8>,
    sig_public: VerifyingKey,
}

impl Peer {
    pub fn new(kem_public: &[u8], sig_public: &[u8]) -> Result<Self, String> {
        KemPublic::from_bytes(kem_public).map_err(|_| "invalid peer HPKE key")?;
        let sig: [u8; SIG_KEY_LENGTH] = sig_public
            .try_into()
            .map_err(|_| "invalid peer signing key")?;
        Ok(Self {
            kem_public: kem_public.to_vec(),
            sig_public: VerifyingKey::from_bytes(&sig).map_err(|_| "invalid peer signing key")?,
        })
    }

    pub fn kem_public(&self) -> &[u8] {
        &self.kem_public
    }

    pub fn sig_public(&self) -> [u8; SIG_KEY_LENGTH] {
        self.sig_public.to_bytes()
    }
}

fn header(kind: &str, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    write_string(&mut out, LABEL.as_bytes());
    write_string(&mut out, kind.as_bytes());
    for field in fields {
        write_string(&mut out, field.as_bytes());
    }
    out
}

pub fn request_header(ch: &str, signer: &str, id: &str, exp: u64) -> Vec<u8> {
    header("request", &[ch, signer, id, &exp.to_string()])
}

pub fn response_header(ch: &str, signer: &str, id: &str) -> Vec<u8> {
    header("response", &[ch, signer, id])
}

pub fn pair_header(ch: &str, signer: &str) -> Vec<u8> {
    header("pair", &[ch, signer])
}

fn hpke_info(sender_sig: &[u8], recipient_kem: &[u8]) -> Vec<u8> {
    [
        format!("{LABEL} hpke").as_bytes(),
        sender_sig,
        recipient_kem,
    ]
    .concat()
}

fn signed_bytes(header: &[u8], enc: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut out = format!("{LABEL} sig").into_bytes();
    write_string(&mut out, header);
    write_string(&mut out, enc);
    write_string(&mut out, ct);
    out
}

/// Seal `value` for `to`, bound to `header`.
pub fn seal(me: &Identity, to: &Peer, header: &[u8], value: &Value) -> Result<String, String> {
    let recipient = KemPublic::from_bytes(&to.kem_public).map_err(|_| "invalid peer HPKE key")?;
    let info = hpke_info(&me.sig_public(), &to.kem_public);
    let (enc, ct) = hpke::single_shot_seal::<AesGcm128, HkdfSha256, Kem>(
        &OpModeS::Base,
        &recipient,
        &info,
        value.to_string().as_bytes(),
        header,
    )
    .map_err(|_| "encryption failed")?;
    let enc = enc.to_bytes();
    let signature = me.sig.sign(&signed_bytes(header, &enc, &ct));
    Ok(b64u(
        &[&signature.to_bytes()[..], &enc[..], &ct[..]].concat(),
    ))
}

fn open_bytes(
    me: &Identity,
    from: &VerifyingKey,
    header: &[u8],
    raw: &[u8],
) -> Result<Value, &'static str> {
    if raw.len() < SIG_LENGTH + KEM_KEY_LENGTH + 16 {
        return Err("message too short");
    }
    let (sig, rest) = raw.split_at(SIG_LENGTH);
    let (enc, ct) = rest.split_at(KEM_KEY_LENGTH);
    let signature = Signature::from_slice(sig).map_err(|_| "bad signature")?;
    from.verify_strict(&signed_bytes(header, enc, ct), &signature)
        .map_err(|_| "bad signature")?;
    let encapped = Encapped::from_bytes(enc).map_err(|_| "bad encapsulated key")?;
    let plain = hpke::single_shot_open::<AesGcm128, HkdfSha256, Kem>(
        &OpModeR::Base,
        &me.kem_private,
        &encapped,
        &hpke_info(from.as_bytes(), &me.kem_public),
        ct,
        header,
    )
    .map_err(|_| "decryption failed")?;
    match serde_json::from_slice(&plain) {
        Ok(value @ Value::Object(_)) => Ok(value),
        _ => Err("not a message"),
    }
}

/// Open a message from the known peer `from`; fails unless it is
/// authentic, meant for us and bound to `header`.
pub fn open(me: &Identity, from: &Peer, header: &[u8], msg: &str) -> Result<Value, &'static str> {
    let raw = unb64u(msg).ok_or("not base64url")?;
    open_bytes(me, &from.sig_public, header, &raw)
}

/// Pairing only: the sender is not known yet, so its signing key travels
/// in front of the message. Returns the content and that key, which the
/// caller must then authenticate by other means (the pairing secret).
pub fn open_introduction(
    me: &Identity,
    header: &[u8],
    msg: &str,
) -> Result<(Value, [u8; SIG_KEY_LENGTH]), &'static str> {
    let raw = unb64u(msg).ok_or("not base64url")?;
    if raw.len() < SIG_KEY_LENGTH {
        return Err("message too short");
    }
    let (key, rest) = raw.split_at(SIG_KEY_LENGTH);
    let key: [u8; SIG_KEY_LENGTH] = key.try_into().map_err(|_| "message too short")?;
    let sender = VerifyingKey::from_bytes(&key).map_err(|_| "invalid sender key")?;
    Ok((open_bytes(me, &sender, header, rest)?, key))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn peer_of(id: &Identity) -> Peer {
        Peer::new(id.kem_public(), &id.sig_public()).unwrap()
    }

    /// The HPKE suite is the one the JavaScript side implements by hand:
    /// both must decrypt the RFC's own vector.
    #[test]
    fn hpke_suite_decrypts_rfc9180_vector_a3() {
        let v: Value =
            serde_json::from_str(include_str!("../../testdata/hpke-rfc9180-a3.json")).unwrap();
        let field = |name: &str| unhex(v[name].as_str().unwrap());
        let sk = KemPrivate::from_bytes(&field("skRm")).unwrap();
        let enc = Encapped::from_bytes(&field("enc")).unwrap();
        let pt = hpke::single_shot_open::<AesGcm128, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            &field("info"),
            &field("ct"),
            &field("aad"),
        )
        .unwrap();
        assert_eq!(pt, field("pt"));
        assert_eq!(Kem::sk_to_pk(&sk).to_bytes().to_vec(), field("pkRm"));
    }

    #[test]
    fn a_sealed_message_opens_for_its_recipient_only() {
        let (agent, phone, other) = (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        );
        let header = request_header("ch", "signer", "id", 1_800_000_000);
        let value = json!({ "t": "sign", "n": 1 });
        let msg = seal(&agent, &peer_of(&phone), &header, &value).unwrap();

        assert_eq!(open(&phone, &peer_of(&agent), &header, &msg), Ok(value));
        // Another recipient, another claimed sender, another header.
        assert!(open(&other, &peer_of(&agent), &header, &msg).is_err());
        assert_eq!(
            open(&phone, &peer_of(&other), &header, &msg),
            Err("bad signature")
        );
        let later = request_header("ch", "signer", "id", 1_800_000_999);
        assert_eq!(
            open(&phone, &peer_of(&agent), &later, &msg),
            Err("bad signature")
        );
        assert!(open(
            &phone,
            &peer_of(&agent),
            &response_header("ch", "signer", "id"),
            &msg
        )
        .is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let (agent, phone) = (Identity::generate(), Identity::generate());
        let header = pair_header("ch", "signer");
        let msg = seal(&agent, &peer_of(&phone), &header, &json!({ "a": 1 })).unwrap();
        let raw = unb64u(&msg).unwrap();
        for at in [0, SIG_LENGTH, SIG_LENGTH + KEM_KEY_LENGTH, raw.len() - 1] {
            let mut bad = raw.clone();
            bad[at] ^= 1;
            assert!(open(&phone, &peer_of(&agent), &header, &b64u(&bad)).is_err());
        }
        assert!(open(&phone, &peer_of(&agent), &header, &b64u(&raw[..100])).is_err());
        assert!(open(&phone, &peer_of(&agent), &header, "%%%").is_err());
    }

    #[test]
    fn only_json_objects_are_messages() {
        let (agent, phone) = (Identity::generate(), Identity::generate());
        let header = pair_header("ch", "signer");
        let msg = seal(&agent, &peer_of(&phone), &header, &json!([1, 2])).unwrap();
        assert_eq!(
            open(&phone, &peer_of(&agent), &header, &msg),
            Err("not a message")
        );
    }

    #[test]
    fn an_introduction_carries_its_sender_key() {
        let (agent, phone) = (Identity::generate(), Identity::generate());
        let header = pair_header("ch", "signer");
        let sealed = seal(&phone, &peer_of(&agent), &header, &json!({ "t": "pair" })).unwrap();
        let intro = b64u(&[&phone.sig_public()[..], &unb64u(&sealed).unwrap()].concat());
        let (value, sender) = open_introduction(&agent, &header, &intro).unwrap();
        assert_eq!(value, json!({ "t": "pair" }));
        assert_eq!(sender, phone.sig_public());
        // A key swapped in front does not open someone else's message.
        let forged = b64u(&[&agent.sig_public()[..], &unb64u(&sealed).unwrap()].concat());
        assert!(open_introduction(&agent, &header, &forged).is_err());
    }

    #[test]
    fn an_identity_survives_storage() {
        let id = Identity::generate();
        let (kem, sig) = id.secrets();
        let again = Identity::from_secrets(&kem, &sig).unwrap();
        assert_eq!(again.kem_public(), id.kem_public());
        assert_eq!(again.sig_public(), id.sig_public());
        assert!(Identity::from_secrets(&[0; 32], &sig).is_err());
        assert!(Identity::from_secrets(&kem, &[1; 31]).is_err());
        assert!(Peer::new(&[4; 65], &id.sig_public()).is_err());
        assert!(Peer::new(id.kem_public(), &[0; 5]).is_err());
    }
}
