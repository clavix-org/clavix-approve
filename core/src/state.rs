//! What the agent keeps on disk: where the relay is, how to authenticate
//! to it, and which devices it is paired with. No private SSH key, ever.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bytes::{hex, random};

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
    /// The paired devices, in the order their keys are offered to `ssh`:
    /// the first is tried first.
    pub signers: Vec<Signer>,
}

/// As written before several devices could be paired: a single `signer`.
#[derive(Deserialize)]
struct OnDisk {
    relay: String,
    ch: String,
    agent_token: String,
    label: String,
    kem_private: String,
    sig_private: String,
    #[serde(default)]
    signers: Vec<Signer>,
    #[serde(default)]
    signer: Option<Signer>,
}

/// A paired device.
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

/// Read the state. On Unix, a state file that other users can read or
/// write is refused (`PermissionDenied`), as OpenSSH does for a private
/// key: its secrets may already be exposed, and a file others can write
/// could name another relay or other keys.
pub fn load(dir: &Path) -> std::io::Result<State> {
    let path = dir.join(FILE);
    let mut file = std::fs::File::open(&path)?;
    check_private(&path, &file)?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut raw)?;
    let invalid = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
    let disk: OnDisk = serde_json::from_slice(&raw).map_err(|e| invalid(e.to_string()))?;
    let mut signers = disk.signers;
    if signers.is_empty() {
        signers.extend(disk.signer);
    }
    if signers.is_empty() {
        return Err(invalid("no paired device".into()));
    }
    Ok(State {
        relay: disk.relay,
        ch: disk.ch,
        agent_token: disk.agent_token,
        label: disk.label,
        kem_private: disk.kem_private,
        sig_private: disk.sig_private,
        signers,
    })
}

/// Refuse a state file that is not private to its owner (Unix only:
/// elsewhere the profile's ACLs apply).
#[cfg(unix)]
fn check_private(path: &Path, file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible by other users (mode {mode:03o}); it holds secrets: \
                 restrict it with `chmod 600` (and pair again if others may have read it)",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path, _file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

/// Write the state, readable by the current user only, replacing any
/// previous one atomically: a fresh temporary file with a random name is
/// created next to it (never an existing file or link), synced, then
/// renamed over it. On Unix the directory is (re)set to `0700` and the
/// file created `0600`.
pub fn save(dir: &Path, state: &State) -> std::io::Result<()> {
    create_private_dir(dir)?;
    let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    let tmp = dir.join(format!(".{FILE}.{}.tmp", hex(&random::<8>())));
    let mut options = std::fs::OpenOptions::new();
    // `create_new` is O_CREAT|O_EXCL: it fails on any existing file,
    // symbolic links included.
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    let written = file
        .write_all(&body)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            std::fs::rename(&tmp, dir.join(FILE))
        });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    sync_dir(dir);
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    // An existing directory (restored backup, copied dotfiles) keeps its
    // bits otherwise.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Make the rename durable. Best effort.
#[cfg(unix)]
fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) {}

/// Forget the pairing: delete the state file. Not an error when there is
/// none.
pub fn remove(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        State {
            relay: "https://relay.example".into(),
            ch: "ab".repeat(16),
            agent_token: "token".into(),
            label: "build-box".into(),
            kem_private: "a2Vt".into(),
            sig_private: "c2ln".into(),
            signers: vec![signer("cd"), signer("ef")],
        }
    }

    /// The names in `dir`.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn state_roundtrips_and_leaves_no_temporary_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested").join("clavix-agent");
        let state = sample();
        save(&dir, &state).unwrap();
        assert_eq!(load(&dir).unwrap(), state);
        // Saving again replaces the file.
        let mut other = state.clone();
        other.label = "other-box".into();
        save(&dir, &other).unwrap();
        assert_eq!(load(&dir).unwrap(), other);
        assert_eq!(entries(&dir), vec![FILE.to_string()]);
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn set_mode(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_is_private_even_in_an_existing_open_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("clavix-agent");
        std::fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o755);
        save(&dir, &sample()).unwrap();
        assert_eq!(mode(&dir.join(FILE)), 0o600);
        assert_eq!(mode(&dir), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_state_others_can_read_or_write_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        save(tmp.path(), &sample()).unwrap();
        let path = tmp.path().join(FILE);
        for open in [0o640, 0o604, 0o620, 0o602] {
            set_mode(&path, open);
            let e = load(tmp.path()).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{open:o}");
            assert!(e.to_string().contains("chmod 600"), "{e}");
        }
        // Saving again writes a private file, which loads.
        save(tmp.path(), &sample()).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(load(tmp.path()).unwrap(), sample());
    }

    #[cfg(unix)]
    #[test]
    fn a_leftover_temporary_file_or_link_is_never_written_through() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("clavix-agent");
        std::fs::create_dir(&dir).unwrap();
        // The fixed name used before: a link planted there is left alone.
        let target = tmp.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, dir.join(format!("{FILE}.tmp"))).unwrap();
        save(&dir, &sample()).unwrap();
        assert!(!target.exists());
        assert_eq!(load(&dir).unwrap(), sample());
    }

    fn signer(id: &str) -> Signer {
        Signer {
            id: id.repeat(8),
            public_key: format!("ecdsa-sha2-nistp256 AAAA{id} phone"),
            kem_public: "a2Vt".into(),
            sig_public: "c2ln".into(),
        }
    }

    #[test]
    fn a_state_from_before_several_devices_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let old = serde_json::json!({
            "relay": "https://relay.example", "ch": "ab".repeat(16), "agent_token": "t",
            "label": "box", "kem_private": "k", "sig_private": "s",
            "signer": { "id": "cd".repeat(8), "public_key": "ecdsa-sha2-nistp256 AAAAcd phone",
                        "kem_public": "a2Vt", "sig_public": "c2ln" },
        });
        std::fs::write(tmp.path().join(FILE), old.to_string()).unwrap();
        #[cfg(unix)]
        set_mode(&tmp.path().join(FILE), 0o600);
        let state = load(tmp.path()).unwrap();
        assert_eq!(state.signers, vec![signer("cd")]);
        // Written back in the new form.
        save(tmp.path(), &state).unwrap();
        let raw = std::fs::read_to_string(tmp.path().join(FILE)).unwrap();
        assert!(raw.contains("\"signers\"") && !raw.contains("\"signer\""));
    }

    #[test]
    fn a_missing_or_broken_state_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(tmp.path()).is_err());
        std::fs::write(tmp.path().join(FILE), b"{").unwrap();
        assert!(load(tmp.path()).is_err());
    }

    #[test]
    fn remove_forgets_the_state_and_tolerates_its_absence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(FILE), b"{}").unwrap();
        remove(tmp.path()).unwrap();
        assert!(!tmp.path().join(FILE).exists());
        remove(tmp.path()).unwrap();
    }
}
