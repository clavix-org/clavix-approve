//! The whole chain with real programs and no iPhone:
//!
//!   ssh → clavix-agent → relay (Python) → fake phone (Node) → back → sshd
//!
//! The fake phone runs the modules of the approval page (`web/lib`), so
//! this also checks that the Rust and JavaScript sides agree on every
//! message. Skipped when OpenSSH, python3 or node is missing.

#![cfg(unix)]

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use common::{
    current_user, free_port, openssh_available, skip_unless, ssh, ssh_run, start_sshd,
    wait_for_port, Kill, SSH_OPTIONS,
};
use serde_json::Value;

const AGENT: &str = env!("CARGO_BIN_EXE_clavix-agent");
const ENROLL_SECRET: &str = "test-enrolment-secret";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn available() -> bool {
    let has = |program: &str| Command::new(program).arg("--version").output().is_ok();
    openssh_available()
        && skip_unless(
            has("python3") && has("node"),
            "python3 or node not installed",
        )
}

/// A child whose standard output is read line by line, with a timeout.
struct Lines {
    _child: Kill,
    rx: Receiver<String>,
}

impl Lines {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            _child: Kill(child),
            rx,
        }
    }

    /// The next line for which `pick` returns something.
    fn next<T>(&self, what: &str, pick: impl Fn(&str) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no {what} within 30 s"));
            if let Some(found) = pick(&line) {
                return found;
            }
        }
    }

    /// The next JSON event of the given kind (fake phone output).
    fn event(&self, kind: &str) -> Value {
        self.next(kind, |line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .filter(|v| v["event"] == kind)
        })
    }

    fn nothing_more(&self) -> bool {
        self.rx.try_recv().is_err()
    }
}

/// Everything around the agent, paired and ready.
struct Bench {
    dir: tempfile::TempDir,
    relay: Option<Kill>,
    relay_url: String,
    sshd: common::Sshd,
    /// The `authorized_keys` line both sides agreed on.
    public_key: String,
}

impl Bench {
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);

        // The relay, push disabled.
        let port = free_port();
        let relay_log = path("relay.log");
        let relay = Command::new("python3")
            .arg(repo().join("relay/relay.py"))
            .env("RELAY_PORT", port.to_string())
            .env("RELAY_STATE_DIR", path("relay-state"))
            .env("RELAY_ENROLL_SECRET", ENROLL_SECRET)
            .env("RELAY_WEB_DIR", repo().join("web"))
            .env("RELAY_PUSH", "off")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&relay_log).unwrap())
            .stderr(std::fs::File::create(path("relay.err")).unwrap())
            .spawn()
            .unwrap();
        let relay = Kill(relay);
        wait_for_port(port, "relay", &path("relay.err"));
        let relay_url = format!("http://127.0.0.1:{port}");

        // Pairing: the agent shows a code, the phone enters it.
        let mut pair = Command::new(AGENT);
        pair.args([
            "pair",
            "--yes",
            "--relay",
            &relay_url,
            "--label",
            "test-bench",
        ])
        .env("CLAVIX_AGENT_DIR", path("agent-state"))
        .env("CLAVIX_ENROLL_SECRET", ENROLL_SECRET);
        let pairing = Lines::spawn(pair);
        let code = pairing.next("pairing code", |line| {
            line.trim()
                .starts_with("cva1-")
                .then(|| line.trim().to_string())
        });
        let phone = Command::new("node")
            .arg(repo().join("tools/fake-phone.mjs"))
            .args(["pair", "--relay", &relay_url, "--code", &code, "--state"])
            .arg(path("phone.json"))
            .output()
            .unwrap();
        assert!(
            phone.status.success(),
            "fake phone could not pair: {}",
            String::from_utf8_lossy(&phone.stderr)
        );
        let paired: Value = serde_json::from_slice(&phone.stdout).unwrap();
        assert_eq!(paired["agent"], "test-bench");
        let public_key = paired["publicKey"].as_str().unwrap().to_string();
        // Both ends derived the same verification digits from the keys.
        let digits = paired["fingerprint"].as_str().unwrap().to_string();
        assert_eq!(digits.len(), 7);
        pairing.next("verification digits from the agent", |line| {
            (line.trim() == digits).then_some(())
        });
        // The agent prints the very same line once it has the answer.
        pairing.next("public key from the agent", |line| {
            (line == public_key).then_some(())
        });

        let sshd = start_sshd(dir.path(), &public_key);
        Self {
            dir,
            relay: Some(relay),
            relay_url,
            sshd,
            public_key,
        }
    }

    fn agent(&self, timeout: &str) -> (Kill, PathBuf) {
        let socket = self.path("agent.sock");
        let _ = std::fs::remove_file(&socket);
        let child = Command::new(AGENT)
            .args(["run", "--timeout", timeout, "--socket"])
            .arg(&socket)
            .env("CLAVIX_AGENT_DIR", self.path("agent-state"))
            .stdin(Stdio::null())
            .stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.path("agent.log"))
                    .unwrap(),
            )
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "agent did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        (Kill(child), socket)
    }

    fn phone(&self, extra: &[&str]) -> Lines {
        let mut command = Command::new("node");
        command
            .arg(repo().join("tools/fake-phone.mjs"))
            .args(["run", "--state"])
            .arg(self.path("phone.json"))
            .args(extra);
        let phone = Lines::spawn(command);
        phone.event("ready");
        phone
    }

    fn agent_log(&self) -> String {
        std::fs::read_to_string(self.path("agent.log")).unwrap_or_default()
    }
}

#[test]
fn ssh_logs_in_through_the_relay_and_the_phone_sees_the_real_destination() {
    if !available() {
        return;
    }
    let bench = Bench::new();

    let pubkey = Command::new(AGENT)
        .arg("pubkey")
        .env("CLAVIX_AGENT_DIR", bench.path("agent-state"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&pubkey.stdout).trim(),
        bench.public_key
    );

    let (_agent, socket) = bench.agent("30");
    let phone = bench.phone(&[]);

    let (ok, stdout, stderr) = ssh(&socket, bench.sshd.port);
    assert!(ok, "ssh failed:\n{stderr}\nagent:\n{}", bench.agent_log());
    assert_eq!(stdout.trim(), "signed-in");

    // What the phone derived by itself from the request.
    let signed = phone.event("signed");
    assert_eq!(signed["state"], "accepted");
    assert_eq!(signed["user"], current_user());
    assert_eq!(signed["host"], bench.sshd.host_fingerprint);
    assert_eq!(signed["known"], false, "first contact with this host key");
    assert_eq!(signed["chain"].as_array().unwrap().len(), 1);
    assert_eq!(signed["caller"]["name"], "ssh");

    // Second login: one more approval, and the host is now pinned.
    let (ok, _, stderr) = ssh(&socket, bench.sshd.port);
    assert!(ok, "second ssh failed:\n{stderr}");
    assert_eq!(phone.event("signed")["known"], true);
    assert!(phone.nothing_more(), "one approval per signature, no more");

    // The agent's log has one line per request, with the time it took.
    let log = bench.agent_log();
    let signed: Vec<&str> = log.lines().filter(|l| l.contains("signed for")).collect();
    assert_eq!(signed.len(), 2, "agent log:\n{log}");
    assert!(signed[0].contains(&bench.sshd.host_fingerprint) && signed[0].ends_with(" s"));
}

/// `ssh -A` to a first server, and from there `ssh` to a second one with
/// the forwarded agent: the real OpenSSH programs produce the chain of
/// session bindings, and the phone must see both hops.
#[test]
fn a_forwarded_agent_shows_the_whole_chain_and_needs_its_own_approval() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let far_dir = bench.path("far");
    std::fs::create_dir(&far_dir).unwrap();
    let far = start_sshd(&far_dir, &bench.public_key);
    let (_agent, socket) = bench.agent("30");
    let phone = bench.phone(&[]);

    // What runs on the first server: a plain ssh to the second one, whose
    // only source of keys is the forwarded agent (SSH_AUTH_SOCK there).
    let onward = format!(
        "ssh {} -p {} 127.0.0.1 echo reached-the-far-host",
        SSH_OPTIONS.join(" "),
        far.port
    );
    let (ok, stdout, stderr) = ssh_run(&socket, bench.sshd.port, true, &onward);
    assert!(
        ok,
        "ssh -A failed:\n{stderr}\nagent:\n{}",
        bench.agent_log()
    );
    assert_eq!(stdout.trim(), "reached-the-far-host");

    // First approval: the jump host, directly.
    let first = phone.event("signed");
    assert_eq!(first["host"], bench.sshd.host_fingerprint);
    assert_eq!(first["chain"].as_array().unwrap().len(), 1);

    // Second approval: the far host, through the agent forwarded to the
    // jump host — both hops verified by the phone.
    let second = phone.event("signed");
    assert_eq!(second["host"], far.host_fingerprint);
    let chain = second["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2, "chain: {chain:?}");
    assert_eq!(chain[0]["host"], bench.sshd.host_fingerprint);
    assert_eq!(chain[0]["forwarded"], true);
    assert_eq!(chain[1]["host"], far.host_fingerprint);
    assert_eq!(chain[1]["forwarded"], false);
    assert!(phone.nothing_more(), "two logins, two approvals");
}

#[test]
fn a_denial_fails_the_login_and_silences_immediate_retries() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let (_agent, socket) = bench.agent("30");
    let phone = bench.phone(&["--deny"]);

    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(!ok, "a denied request must not log in");
    phone.event("denied");
    assert!(bench.agent_log().contains("denied by the signer"));

    // A tool retrying at once does not reach the phone again.
    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(!ok);
    assert!(bench.agent_log().contains("backing off"));
    assert!(phone.nothing_more());
}

#[test]
fn no_answer_expires_and_a_dead_relay_fails_fast() {
    if !available() {
        return;
    }
    let mut bench = Bench::new();
    let (_agent, socket) = bench.agent("10");

    // Nobody is there to approve.
    let started = Instant::now();
    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(!ok);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(9) && waited < Duration::from_secs(25),
        "expected the 10 s timeout, waited {waited:?}"
    );
    assert!(bench.agent_log().contains("no answer from signer"));

    // The relay is gone: the error is immediate and says so.
    bench.relay = None;
    let started = Instant::now();
    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(!ok);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(bench.agent_log().contains("relay unreachable"));
    let _ = &bench.relay_url;
}
