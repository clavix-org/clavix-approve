//! What the agent keeps on disk: where the relay is, how to authenticate
//! to it, and which signer it is paired with. No private SSH key, ever.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const FILE: &str = "state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Base URL of the relay.
    pub relay: String,
    /// Channel id (32 hex digits): one pairing.
    pub ch: String,
    /// Bearer token of the agent on that channel.
    pub agent_token: String,
    /// Name of this machine as shown on the approval screen.
    pub label: String,
    /// The agent's own channel keys (base64url): HPKE private key and
    /// Ed25519 signing seed. They authenticate this agent to the signer;
    /// they cannot sign an SSH login.
    pub kem_private: String,
    pub sig_private: String,
    pub signer: Signer,
}

/// The paired device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signer {
    /// Signer id on the channel (16 hex digits).
    pub id: String,
    /// Its SSH public key, as an `authorized_keys` line.
    pub public_key: String,
    /// Its channel keys (base64url): HPKE public key and Ed25519 key.
    pub kem_public: String,
    pub sig_public: String,
}

/// `$CLAVIX_AGENT_DIR`, else `$XDG_CONFIG_HOME/clavix-agent`, else
/// `~/.config/clavix-agent`.
pub fn default_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CLAVIX_AGENT_DIR") {
        return Some(dir.into());
    }
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("clavix-agent"))
}

pub fn load(dir: &Path) -> std::io::Result<State> {
    let raw = std::fs::read(dir.join(FILE))?;
    serde_json::from_slice(&raw)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Write the state, readable by the current user only, replacing any
/// previous one atomically.
pub fn save(dir: &Path, state: &State) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!("{FILE}.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?)?;
    file.sync_all()?;
    std::fs::rename(tmp, dir.join(FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrips_and_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested").join("clavix-agent");
        let state = State {
            relay: "https://relay.example".into(),
            ch: "ab".repeat(16),
            agent_token: "token".into(),
            label: "build-box".into(),
            kem_private: "a2Vt".into(),
            sig_private: "c2ln".into(),
            signer: Signer {
                id: "cd".repeat(8),
                public_key: "ecdsa-sha2-nistp256 AAAA phone".into(),
                kem_public: "a2Vt".into(),
                sig_public: "c2ln".into(),
            },
        };
        save(&dir, &state).unwrap();
        assert_eq!(load(&dir).unwrap(), state);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join(FILE)), 0o600);
        assert_eq!(mode(&dir), 0o700);
        // Saving again replaces the file.
        save(&dir, &state).unwrap();
        assert!(!dir.join(format!("{FILE}.tmp")).exists());
    }

    #[test]
    fn a_missing_or_broken_state_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path()).is_err());
        std::fs::write(tmp.path().join(FILE), b"{").unwrap();
        assert!(load(tmp.path()).is_err());
    }
}
