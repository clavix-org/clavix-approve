//! The [`Signer`] built on the relay: a thin adapter over the sign-mode
//! requester of `clavix-approve-core`, which sends every signature request
//! to the paired device through the relay and gets it back approved,
//! denied or not at all. The relay client itself, and its rules of conduct
//! towards the relay, are in `clavix-approve-core` too (re-exported here).
//! What stays here is agent-side: naming host keys from `known_hosts` and
//! the caller's command line, and the agent's wording of failures.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub use clavix_approve_core::bytes::{b64u, hex, random, token_auth, unb64u, unhex};
pub use clavix_approve_core::relay::{revoke, revoke_device, RelayClient, RelayError};
use clavix_approve_core::sign_requester::{
    self as core_sign, Caller, SessionBind, SignRequest, SignRequester,
};
pub use clavix_approve_core::sign_requester::{SignDevice as Device, DEFAULT_TIMEOUT};

use crate::channel;
use crate::proto::{CallerInfo, Identity, SignError, SignFuture, SignJob, Signer};

/// A sign-mode failure as the agent logs it: what the core reports, plus
/// what to do about it with this command line tool.
fn agent_error(e: core_sign::SignError) -> SignError {
    use core_sign::SignError as E;
    match e {
        E::Denied => SignError::Denied,
        E::Expired => SignError::Expired,
        E::Revoked => SignError::Backend(
            "the relay no longer knows this pairing (revoked from the device?); \
             run `clavix-agent pair` again"
                .into(),
        ),
        E::UnknownDevice(to) => SignError::Backend(format!(
            "device {to} is no longer paired (forgotten on the device?); \
             run `clavix-agent unpair --device {to}`"
        )),
        E::NotPickedUp { device, after } => SignError::Backend(format!(
            "device {device} did not pick the request up within {} s; \
             ssh may try the next device's key",
            after.as_secs()
        )),
        // Never retried: requests fail at once for a while, without
        // asking the relay again (a proxy in front bans on 4xx bursts).
        E::Relay(RelayError::SubscriptionRequired) => SignError::Backend(
            "abonnement requis : ouvrez Clavix Approve sur l'iPhone \
             (this relay serves subscribers only; requests fail at once for 30 s)"
                .into(),
        ),
        E::Relay(RelayError::MachineLimit) => SignError::Backend(
            "l'abonnement couvre déjà le nombre maximal de machines : \
             dissociez-en une (`clavix-agent unpair`) ou ouvrez Clavix Approve sur l'iPhone"
                .into(),
        ),
        e @ (E::Refused(_) | E::BackingOff | E::Busy | E::Relay(_) | E::Invalid(_)) => {
            SignError::Backend(e.to_string())
        }
    }
}

/// Names a host key, for display only. The caller is the process that
/// asked for the signature, when known; the flag says whether this host
/// is the only one in the request (no forwarded agent in between).
type HintFn = Arc<dyn Fn(&[u8], Option<&CallerInfo>, bool) -> Option<String> + Send + Sync>;

/// Sends each sign job to the device holding the requested key and waits
/// for its answer.
pub struct RelaySigner {
    requester: SignRequester,
    /// The offered keys, in order: computed once.
    identities: Vec<Identity>,
    hints: HintFn,
}

impl RelaySigner {
    /// `me` holds the agent's channel keys; `devices` the paired devices,
    /// in the order their keys are offered.
    pub fn new(
        client: RelayClient,
        ch: &str,
        token: &str,
        label: &str,
        me: channel::Identity,
        devices: Vec<Device>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let requester = SignRequester::new(client, ch, token, label, me, devices, timeout)
            .map_err(|e| e.to_string())?;
        let identities = requester
            .keys()
            .into_iter()
            .map(|k| Identity {
                key_blob: k.key_blob,
                comment: k.comment,
            })
            .collect();
        Ok(Self {
            requester,
            identities,
            hints: Arc::new(|_, _, _| None),
        })
    }

    /// Give up on a device that has not fetched a request after `pickup`
    /// (zero: never). Only with more than one device: alone, there is no
    /// other key to fall back on.
    pub fn with_pickup(mut self, pickup: Duration) -> Self {
        self.requester = self.requester.with_pickup(pickup);
        self
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

    /// The core's request for `job`, with the host-key names suggested.
    fn request(&self, job: SignJob) -> SignRequest {
        let mut hints = BTreeMap::new();
        let sole = job.hops.len() == 1;
        for hop in &job.hops {
            if let Some(name) = (self.hints)(&hop.key_blob, job.caller.as_ref(), sole) {
                hints.insert(hop.fingerprint.clone(), name);
            }
        }
        SignRequest {
            key: job.key_blob,
            data: job.data,
            flags: job.flags,
            binds: job
                .hops
                .into_iter()
                .map(|hop| SessionBind {
                    host_key: hop.key_blob,
                    session_id: hop.session_id,
                    signature: hop.signature,
                    forwarded: hop.forwarded,
                })
                .collect(),
            // A name that could not be read goes out as unknown (`null`).
            caller: job.caller.map(|c| Caller {
                pid: c.pid,
                name: c.name.unwrap_or_default(),
            }),
            hints,
        }
    }
}

impl Signer for RelaySigner {
    fn identities(&self) -> Vec<Identity> {
        self.identities.clone()
    }

    fn sign(&self, job: SignJob) -> SignFuture {
        let signature = self.requester.sign(&self.request(job));
        Box::pin(async move { signature.await.map_err(agent_error) })
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
    use crate::proto::HostHop;

    #[test]
    fn failures_keep_the_agents_wording() {
        use core_sign::SignError as E;
        let backend = |e: E| match agent_error(e) {
            SignError::Backend(reason) => reason,
            other => panic!("{other:?}"),
        };
        assert_eq!(agent_error(E::Denied), SignError::Denied);
        assert_eq!(agent_error(E::Expired), SignError::Expired);
        assert!(backend(E::Revoked).contains("no longer knows this pairing"));
        assert!(backend(E::Revoked).contains("`clavix-agent pair`"));
        assert!(backend(E::UnknownDevice("ab12".into()))
            .ends_with("run `clavix-agent unpair --device ab12`"));
        assert_eq!(
            backend(E::NotPickedUp {
                device: "ab12".into(),
                after: Duration::from_secs(3)
            }),
            "device ab12 did not pick the request up within 3 s; \
             ssh may try the next device's key"
        );
        assert_eq!(
            backend(E::Refused("unverified".into())),
            "the signer refused the request (unverified)"
        );
        assert_eq!(
            backend(E::BackingOff),
            "a request was just denied; backing off"
        );
        assert_eq!(backend(E::Busy), "too many requests already waiting");
        assert_eq!(
            backend(E::Relay(RelayError::Transport("x".into()))),
            RelayError::Transport("x".into()).to_string()
        );
        assert!(backend(E::Relay(RelayError::SubscriptionRequired))
            .starts_with("abonnement requis : ouvrez Clavix Approve sur l'iPhone"));
        assert!(backend(E::Relay(RelayError::MachineLimit)).contains("nombre maximal de machines"));
        assert_eq!(
            backend(E::Invalid("no paired device holds this key".into())),
            "no paired device holds this key"
        );
    }

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g phone";

    fn signer() -> RelaySigner {
        let phone = channel::Identity::generate();
        RelaySigner::new(
            RelayClient::new("http://127.0.0.1:9").unwrap(),
            &"ab".repeat(16),
            "token",
            "desk",
            channel::Identity::generate(),
            vec![Device {
                id: "01".into(),
                public_key: KEY.into(),
                peer: channel::Peer::new(phone.kem_public(), &phone.sig_public()).unwrap(),
            }],
            DEFAULT_TIMEOUT,
        )
        .unwrap()
    }

    fn hop(name: &str, forwarded: bool) -> HostHop {
        HostHop {
            key_blob: format!("{name}-key").into_bytes(),
            fingerprint: format!("SHA256:{name}"),
            forwarded,
            session_id: format!("{name}-sid").into_bytes(),
            signature: format!("{name}-sig").into_bytes(),
        }
    }

    #[test]
    fn a_job_becomes_the_cores_request() {
        let signer = signer();
        assert_eq!(signer.identities().len(), 1);
        assert_eq!(signer.identities()[0].comment, "phone");
        let signer = signer.with_hints(|key, caller, sole| {
            assert_eq!(caller.map(|c| c.pid), Some(42));
            (key == b"auth-key").then(|| format!("named, sole={sole}"))
        });
        let job = SignJob {
            key_blob: b"key".to_vec(),
            data: b"data".to_vec(),
            flags: 2,
            hops: vec![hop("jump", true), hop("auth", false)],
            caller: Some(CallerInfo {
                pid: 42,
                name: None,
            }),
        };
        let request = signer.request(job);
        assert_eq!(request.key, b"key");
        assert_eq!(request.data, b"data");
        assert_eq!(request.flags, 2);
        assert_eq!(request.binds.len(), 2);
        assert!(request.binds[0].forwarded && !request.binds[1].forwarded);
        assert_eq!(request.binds[1].host_key, b"auth-key");
        assert_eq!(request.binds[1].session_id, b"auth-sid");
        assert_eq!(request.binds[1].signature, b"auth-sig");
        assert_eq!(
            request.caller,
            Some(Caller {
                pid: 42,
                name: String::new()
            })
        );
        assert_eq!(
            request.hints,
            BTreeMap::from([("SHA256:auth".to_string(), "named, sole=false".to_string())])
        );
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
