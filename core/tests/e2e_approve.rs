//! Approve mode end to end, with real programs and no iPhone:
//!
//!   requester (this crate) → relay (Python) → fake phone (Node) → back
//!
//! The fake phone runs the modules of the approval page (`web/lib`), so
//! this checks that the Rust requester and the JavaScript signer agree on
//! every message of approve mode. Skipped when python3 or node is missing
//! (fails instead when `CLAVIX_REQUIRE_E2E` is set, as in CI).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use clavix_approve_core::bytes::write_string;
use clavix_approve_core::requester::{
    ApprovalRequest, ApproveChannel, ApproveOffer, Outcome, Requester, SessionBind,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;

const ENROLL_SECRET: &str = "test-enrolment-secret";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn available() -> bool {
    let has = |program: &str| Command::new(program).arg("--version").output().is_ok();
    let ok = has("python3") && has("node");
    if !ok {
        assert!(
            std::env::var_os("CLAVIX_REQUIRE_E2E").is_none(),
            "end-to-end test cannot run: python3 or node not installed"
        );
        eprintln!("skipped: python3 or node not installed");
    }
    ok
}

/// A child process killed when dropped.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A fake phone whose JSON events are read line by line.
struct Phone {
    _child: Kill,
    rx: Receiver<Value>,
}

impl Phone {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new("node")
            .arg(repo().join("tools/fake-phone.mjs"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if tx.send(v).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            _child: Kill(child),
            rx,
        }
    }

    /// The next event of the given kind, within 30 s.
    fn event(&self, kind: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let v = self
                .rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no {kind} event within 30 s"));
            if v["event"] == kind {
                return v;
            }
        }
    }
}

struct Bench {
    dir: tempfile::TempDir,
    _relay: Kill,
    relay_url: String,
}

impl Bench {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let relay = Kill(
            Command::new("python3")
                .arg(repo().join("relay/relay.py"))
                .env("RELAY_PORT", port.to_string())
                .env("RELAY_STATE_DIR", path("relay-state"))
                .env("RELAY_ENROLL_SECRET", ENROLL_SECRET)
                .env("RELAY_WEB_DIR", repo().join("web"))
                .env("RELAY_PUSH", "off")
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(path("relay.log")).unwrap())
                .stderr(std::fs::File::create(path("relay.err")).unwrap())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "relay did not start: {}",
                std::fs::read_to_string(path("relay.err")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            dir,
            _relay: relay,
            relay_url: format!("http://127.0.0.1:{port}"),
        }
    }

    fn state(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }

    /// Pair a fake phone with `offer`; both ends must show the same digits.
    async fn pair_phone(&self, offer: &ApproveOffer, state: &str) -> (String, String) {
        let pairing = Phone::spawn(&[
            "pair",
            "--relay",
            &self.relay_url,
            "--state",
            &self.state(state),
            "--code",
            offer.code(),
        ]);
        let paired = offer.wait(Duration::from_secs(30)).await.unwrap();
        let event = pairing.event("paired");
        assert_eq!(event["mode"], "approve");
        assert_eq!(event["fingerprint"], paired.digits.as_str());
        assert!(paired.device.approve_key.starts_with("ssh-ed25519 "));
        assert_eq!(paired.device.name(), "fake-phone");
        (
            paired.device.id.clone(),
            serde_json::to_string(&paired.device).unwrap(),
        )
    }

    fn run_phone(&self, state: &str, extra: &[&str]) -> Phone {
        let state = self.state(state);
        let mut args = vec!["run", "--state", &state];
        args.extend_from_slice(extra);
        let phone = Phone::spawn(&args);
        phone.event("ready");
        phone
    }
}

/// An SSH login as a client would ask an agent to sign it: the
/// requester's own key, for a session the server's host key signed.
fn login(user: &str) -> ApprovalRequest {
    let ssh_blob = |name: &[u8], key: &[u8]| {
        let mut b = Vec::new();
        write_string(&mut b, name);
        write_string(&mut b, key);
        b
    };
    let own = SigningKey::from_bytes(&rand_bytes());
    let host = SigningKey::from_bytes(&rand_bytes());
    let own_blob = ssh_blob(b"ssh-ed25519", own.verifying_key().as_bytes());
    let host_blob = ssh_blob(b"ssh-ed25519", host.verifying_key().as_bytes());
    let sid = rand_bytes().to_vec();

    let mut data = Vec::new();
    write_string(&mut data, &sid);
    data.push(50);
    write_string(&mut data, user.as_bytes());
    write_string(&mut data, b"ssh-connection");
    write_string(&mut data, b"publickey-hostbound-v00@openssh.com");
    data.push(1);
    write_string(&mut data, b"ssh-ed25519");
    write_string(&mut data, &own_blob);
    write_string(&mut data, &host_blob);

    let mut request = ApprovalRequest::new(own_blob, data);
    request.key_name = "vault key".into();
    request.binds = vec![SessionBind {
        signature: ssh_blob(b"ssh-ed25519", &host.sign(&sid).to_bytes()),
        host_key: host_blob,
        session_id: sid,
        forwarded: false,
    }];
    request
}

fn rand_bytes() -> [u8; 32] {
    clavix_approve_core::bytes::random::<32>()
}

#[tokio::test(flavor = "multi_thread")]
async fn approve_mode_end_to_end() {
    if !available() {
        return;
    }
    let bench = Bench::new();

    // Pairing: a new approve-mode channel, one phone.
    let offer = ApproveOffer::open(&bench.relay_url, ENROLL_SECRET, "desk")
        .await
        .unwrap();
    // The link opens the app, with the relay in the query: never a page.
    assert_eq!(
        offer.link(),
        format!(
            "clavix-approve://pair?relay={}#{}",
            bench.relay_url,
            offer.code()
        )
    );
    assert!(offer.code().starts_with("cva2-"));
    let (first, device) = bench.pair_phone(&offer, "phone1.json").await;
    let mut channel: ApproveChannel = offer.into_channel(serde_json::from_str(&device).unwrap());
    assert_eq!(channel.label, "desk");

    // Approved: the proof verified, the phone saw the requester's key.
    let requester = Requester::new(&channel).unwrap();
    {
        let phone = bench.run_phone("phone1.json", &["--once"]);
        let (_withdraw, outcome) = requester.request_approval(&login("deploy"));
        assert_eq!(
            outcome.await.unwrap(),
            Outcome::Approved {
                device: first.clone()
            }
        );
        let seen = phone.event("approved");
        assert_eq!(seen["user"], "deploy");
        assert_eq!(seen["keyName"], "vault key");
        assert_eq!(seen["keyType"], "ssh-ed25519");
        assert_eq!(seen["state"], "accepted");
    }

    // Denied by the user.
    {
        let phone = bench.run_phone("phone1.json", &["--once", "--deny"]);
        let (_withdraw, outcome) = requester.request_approval(&login("deploy"));
        assert_eq!(
            outcome.await.unwrap(),
            Outcome::Denied {
                device: first.clone(),
                reason: "user".into()
            }
        );
        phone.event("denied");
    }

    // Withdrawn by the caller's own id while the phone takes its time (the
    // local dialog answered first): the late answer is refused.
    {
        let phone = bench.run_phone("phone1.json", &["--once", "--delay", "3"]);
        let mut request = login("deploy");
        request.id = "local-0001".into();
        request.agent = Some("desk (Clavix)".into());
        let (_withdraw, outcome) = requester.request_approval(&request);
        let waiter = tokio::spawn(outcome);
        tokio::time::sleep(Duration::from_secs(1)).await;
        requester.withdraw("local-0001");
        assert_eq!(waiter.await.unwrap().unwrap(), Outcome::Withdrawn);
        let late = phone.event("approved");
        assert_eq!(late["agent"], "desk (Clavix)");
        assert_ne!(late["state"], "accepted");
    }

    // Nobody answers: expired.
    {
        let mut request = login("deploy");
        request.ttl = Duration::from_secs(3);
        let (_withdraw, outcome) = requester.request_approval(&request);
        assert_eq!(outcome.await.unwrap(), Outcome::Expired);
    }

    // A second device; a refusal from either is final.
    let more = ApproveOffer::add_device(&channel).await.unwrap();
    let (second, device) = bench.pair_phone(&more, "phone2.json").await;
    channel.devices.push(serde_json::from_str(&device).unwrap());
    assert_ne!(first, second);
    let both = Requester::new(&channel).unwrap();
    {
        let slow = bench.run_phone("phone1.json", &["--once", "--delay", "3"]);
        let refusing = bench.run_phone("phone2.json", &["--once", "--deny"]);
        let (_withdraw, outcome) = both.request_approval(&login("deploy"));
        assert_eq!(
            outcome.await.unwrap(),
            Outcome::Denied {
                device: second.clone(),
                reason: "user".into()
            }
        );
        refusing.event("denied");
        // The other phone's request was withdrawn: its late approval is refused.
        assert_ne!(slow.event("approved")["state"], "accepted");
    }

    // Forget the second device: the first one alone approves again.
    assert!(channel.forget_device(&second).await.unwrap());
    assert_eq!(channel.devices.len(), 1);
    {
        let phone = bench.run_phone("phone1.json", &["--once"]);
        let (_withdraw, outcome) = Requester::new(&channel)
            .unwrap()
            .request_approval(&login("ops"));
        assert_eq!(
            outcome.await.unwrap(),
            Outcome::Approved {
                device: first.clone()
            }
        );
        assert_eq!(phone.event("approved")["user"], "ops");
    }

    // Revoked: the relay forgets the channel.
    assert!(channel.revoke().await.unwrap());
    let (_withdraw, outcome) = Requester::new(&channel)
        .unwrap()
        .request_approval(&login("deploy"));
    assert_eq!(
        outcome.await,
        Err(clavix_approve_core::requester::Error::Revoked)
    );
}
