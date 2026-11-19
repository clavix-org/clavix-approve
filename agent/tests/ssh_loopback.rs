//! End to end with the real OpenSSH programs: a scratch `sshd` on a
//! loopback port, the stock `ssh` client, and the agent in between with a
//! signer that stands in for the phone (it holds a P-256 key in memory).
//!
//! Skipped when `sshd` or `ssh` is not installed.

#![cfg(unix)]

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use clavix_agent::proto::{
    parse_userauth_request, Identity, SignError, SignFuture, SignJob, Signer,
};
use clavix_agent::unix::start_agent;
use rand::rngs::OsRng;
use signature::Signer as _;
use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

use common::{current_user, openssh_available, start_sshd};

/// Stands in for the phone: signs, or refuses, without asking anyone.
struct PhoneStandIn {
    key: PrivateKey,
    approve: bool,
    jobs: Mutex<Vec<SignJob>>,
}

impl PhoneStandIn {
    fn new(approve: bool) -> Arc<Self> {
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        Arc::new(Self {
            key,
            approve,
            jobs: Mutex::new(Vec::new()),
        })
    }
}

impl Signer for PhoneStandIn {
    fn identities(&self) -> Vec<Identity> {
        vec![Identity {
            key_blob: self.key.public_key().to_bytes().unwrap(),
            comment: "phone stand-in".into(),
        }]
    }

    fn sign(&self, job: SignJob) -> SignFuture {
        let answer = if self.approve {
            let signature = self.key.try_sign(&job.data).unwrap();
            Ok(Vec::<u8>::try_from(signature).unwrap())
        } else {
            Err(SignError::Denied)
        };
        self.jobs.lock().unwrap().push(job);
        Box::pin(async move { answer })
    }
}

/// The blocking client, off the runtime's worker threads.
async fn ssh(agent_socket: &Path, port: u16) -> (bool, String, String) {
    let socket = agent_socket.to_path_buf();
    tokio::task::spawn_blocking(move || common::ssh(&socket, port))
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn stock_ssh_logs_in_with_a_signature_from_the_signer() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let phone = PhoneStandIn::new(true);
    let sshd = start_sshd(dir.path(), &phone.key.public_key().to_openssh().unwrap());
    let agent = start_agent(dir.path().join("agent.sock"), phone.clone())
        .await
        .unwrap();

    let (ok, stdout, stderr) = ssh(&agent.socket_path, sshd.port).await;
    let sshd_log = std::fs::read_to_string(&sshd.log).unwrap_or_default();
    assert!(ok, "ssh failed:\n{stderr}\nsshd:\n{sshd_log}");
    assert_eq!(stdout.trim(), "signed-in");

    // Exactly one signature was asked for, and the signer was given what
    // it needs to check the destination by itself.
    let jobs = phone.jobs.lock().unwrap().clone();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert_eq!(job.hops.len(), 1);
    assert!(!job.hops[0].forwarded);
    assert_eq!(job.hops[0].key_blob, sshd.host_key_blob);
    assert!(!job.hops[0].signature.is_empty());
    let request = parse_userauth_request(&job.data).unwrap();
    assert_eq!(request.session_id, job.hops[0].session_id.as_slice());
    assert_eq!(request.user, current_user().as_bytes());
    assert_eq!(request.host_key, sshd.host_key_blob.as_slice());
    let caller = job.caller.as_ref().expect("caller identified on Linux");
    assert_eq!(caller.name.as_deref(), Some("ssh"));

    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denial_makes_ssh_fail() {
    if !openssh_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let phone = PhoneStandIn::new(false);
    let sshd = start_sshd(dir.path(), &phone.key.public_key().to_openssh().unwrap());
    let agent = start_agent(dir.path().join("agent.sock"), phone.clone())
        .await
        .unwrap();

    let (ok, _stdout, stderr) = ssh(&agent.socket_path, sshd.port).await;
    assert!(!ok, "ssh must not get in without a signature");
    assert!(
        stderr.contains("agent refused operation") || stderr.contains("Permission denied"),
        "unexpected ssh error:\n{stderr}"
    );
    assert_eq!(phone.jobs.lock().unwrap().len(), 1);

    agent.stop().await;
}
