//! Encodings shared by every message: base64url, hex, SSH strings.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Base64url without padding, as every field on the wire.
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// Lowercase hex, as ids in URLs.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `N` bytes from the operating system's generator.
pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

/// An SSH `string`: a big-endian u32 length, then the bytes.
pub fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&u32::to_be_bytes(s.len() as u32));
    buf.extend_from_slice(s);
}

/// What the relay stores of a bearer token.
pub fn token_auth(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings_roundtrip() {
        assert_eq!(unhex(&hex(&[0, 0xab, 0xff])), Some(vec![0, 0xab, 0xff]));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unb64u(&b64u(b"\xff\xfe")), Some(b"\xff\xfe".to_vec()));
        let mut s = Vec::new();
        write_string(&mut s, b"ab");
        assert_eq!(s, [0, 0, 0, 2, b'a', b'b']);
    }
}
