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
                .starts_with("cva2-")
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

impl Bench {
    /// `clavix-agent unpair` with these arguments: (success, stdout, stderr).
    fn unpair(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(AGENT)
            .arg("unpair")
            .args(args)
            .env("CLAVIX_AGENT_DIR", self.path("agent-state"))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn agent_state_exists(&self) -> bool {
        self.path("agent-state").join("state.json").exists()
    }
}

#[test]
fn unpair_from_the_agent_cuts_the_phone_off() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let phone = bench.phone(&[]);

    let (ok, out, err) = bench.unpair(&[]);
    assert!(ok, "unpair failed: {err}");
    assert!(out.contains("Pairing revoked on the relay."), "{out}");
    // It says which key still has to leave the servers.
    assert!(out.contains(&bench.public_key), "{out}");
    assert!(!bench.agent_state_exists());
    // The phone's long-poll ends: the relay no longer knows it.
    phone.event("revoked");

    // Nothing left to unpair.
    let (ok, _, err) = bench.unpair(&[]);
    assert!(!ok);
    assert!(err.contains("not paired yet"), "{err}");
}

#[test]
fn a_pairing_revoked_from_the_phone_fails_with_a_clear_message() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let revoked = Command::new("node")
        .arg(repo().join("tools/fake-phone.mjs"))
        .args(["revoke", "--state"])
        .arg(bench.path("phone.json"))
        .output()
        .unwrap();
    assert!(revoked.status.success());
    let event: Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert_eq!(event["deleted"], true);

    let (_agent, socket) = bench.agent("10");
    let started = Instant::now();
    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(!ok);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(
        bench.agent_log().contains("no longer knows this pairing"),
        "{}",
        bench.agent_log()
    );

    // The agent end then finds the channel already gone, and still cleans up.
    let (ok, out, err) = bench.unpair(&[]);
    assert!(ok, "{err}");
    assert!(out.contains("no longer knew this pairing"), "{out}");
    assert!(!bench.agent_state_exists());
}

#[test]
fn unpair_keeps_the_pairing_when_the_relay_is_unreachable() {
    if !available() {
        return;
    }
    let mut bench = Bench::new();
    bench.relay = None;

    let (ok, _, err) = bench.unpair(&[]);
    assert!(!ok);
    assert!(err.contains("nothing was changed"), "{err}");
    assert!(bench.agent_state_exists());

    let (ok, out, err) = bench.unpair(&["--local-only"]);
    assert!(ok, "{err}");
    assert!(out.contains(&bench.public_key), "{out}");
    assert!(!bench.agent_state_exists());
}

#[test]
fn pairing_again_revokes_the_previous_pairing() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let old_phone = bench.phone(&[]);

    // A new device pairs with the same agent.
    let mut pair = Command::new(AGENT);
    pair.args([
        "pair",
        "--yes",
        "--relay",
        &bench.relay_url,
        "--label",
        "test-bench",
    ])
    .env("CLAVIX_AGENT_DIR", bench.path("agent-state"))
    .env("CLAVIX_ENROLL_SECRET", ENROLL_SECRET);
    let pairing = Lines::spawn(pair);
    let code = pairing.next("pairing code", |line| {
        line.trim()
            .starts_with("cva2-")
            .then(|| line.trim().to_string())
    });
    let phone = Command::new("node")
        .arg(repo().join("tools/fake-phone.mjs"))
        .args([
            "pair",
            "--relay",
            &bench.relay_url,
            "--code",
            &code,
            "--state",
        ])
        .arg(bench.path("phone2.json"))
        .output()
        .unwrap();
    assert!(phone.status.success());
    pairing.next("revocation of the previous pairing", |line| {
        (line == "The previous pairing was revoked.").then_some(())
    });
    // The old device's key differs from the new one: remove it from servers.
    pairing.next("old key to remove", |line| {
        (line == bench.public_key).then_some(())
    });
    old_phone.event("revoked");
}

#[test]
fn refusing_the_digits_of_a_first_pairing_revokes_its_channel() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    // No --yes and no answer on standard input: the digits are refused.
    let mut pair = Command::new(AGENT);
    pair.args(["pair", "--relay", &bench.relay_url, "--label", "test-bench"])
        .env("CLAVIX_AGENT_DIR", bench.path("agent-state"))
        .env("CLAVIX_ENROLL_SECRET", ENROLL_SECRET);
    let pairing = Lines::spawn(pair);
    let code = pairing.next("pairing code", |line| {
        line.trim()
            .starts_with("cva2-")
            .then(|| line.trim().to_string())
    });
    let phone = Command::new("node")
        .arg(repo().join("tools/fake-phone.mjs"))
        .args([
            "pair",
            "--relay",
            &bench.relay_url,
            "--code",
            &code,
            "--state",
        ])
        .arg(bench.path("refused.json"))
        .output()
        .unwrap();
    // The device that was refused finds its channel gone on the relay:
    // while it waits for the agent's nonce, or right after.
    if phone.status.success() {
        let mut run = Command::new("node");
        run.arg(repo().join("tools/fake-phone.mjs"))
            .args(["run", "--state"])
            .arg(bench.path("refused.json"));
        Lines::spawn(run).event("revoked");
    } else {
        let err = String::from_utf8_lossy(&phone.stderr);
        assert!(err.contains("HTTP 401"), "{err}");
    }
    // The pairing in place is untouched.
    let (ok, out, _) = bench.cli(&["pubkey"]);
    assert!(ok);
    assert_eq!(out.trim(), bench.public_key);
}

#[test]
fn version_names_the_package_version() {
    let out = Command::new(AGENT).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("clavix-agent {}", env!("CARGO_PKG_VERSION"))
    );
}

// ---- several devices ------------------------------------------------------

impl Bench {
    /// `clavix-agent` with these arguments: (success, stdout, stderr).
    fn cli(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(AGENT)
            .args(args)
            .env("CLAVIX_AGENT_DIR", self.path("agent-state"))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Pair a second fake phone, keeping its state in `file`, and let the
    /// server accept its key too. Returns its public key.
    fn add_device(&self, file: &str) -> String {
        let mut pair = Command::new(AGENT);
        pair.args(["pair", "--add", "--yes"])
            .env("CLAVIX_AGENT_DIR", self.path("agent-state"));
        let pairing = Lines::spawn(pair);
        let code = pairing.next("pairing code", |line| {
            line.trim()
                .starts_with("cva2-")
                .then(|| line.trim().to_string())
        });
        let phone = Command::new("node")
            .arg(repo().join("tools/fake-phone.mjs"))
            .args([
                "pair",
                "--relay",
                &self.relay_url,
                "--code",
                &code,
                "--state",
            ])
            .arg(self.path(file))
            .output()
            .unwrap();
        assert!(
            phone.status.success(),
            "{}",
            String::from_utf8_lossy(&phone.stderr)
        );
        let paired: Value = serde_json::from_slice(&phone.stdout).unwrap();
        let key = paired["publicKey"].as_str().unwrap().to_string();
        pairing.next("the new key from the agent", |line| {
            (line == key).then_some(())
        });
        let authorized = self.dir.path().join("authorized_keys");
        let mut lines = std::fs::read_to_string(&authorized).unwrap();
        lines.push_str(&format!("{key}\n"));
        std::fs::write(&authorized, lines).unwrap();
        key
    }

    /// Device ids, in the order `devices` lists them.
    fn device_ids(&self) -> Vec<String> {
        let (ok, out, err) = self.cli(&["devices"]);
        assert!(ok, "{err}");
        out.lines()
            .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
            .collect()
    }

    fn agent_with(&self, args: &[&str]) -> (Kill, PathBuf) {
        let socket = self.path("agent.sock");
        let _ = std::fs::remove_file(&socket);
        let child = Command::new(AGENT)
            .arg("run")
            .args(args)
            .arg("--socket")
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

    fn phone_at(&self, file: &str, extra: &[&str]) -> Lines {
        let mut command = Command::new("node");
        command
            .arg(repo().join("tools/fake-phone.mjs"))
            .args(["run", "--state"])
            .arg(self.path(file))
            .args(extra);
        let phone = Lines::spawn(command);
        phone.event("ready");
        phone
    }
}

#[test]
fn a_second_device_takes_over_when_the_first_does_not_pick_up() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let second = bench.add_device("phone2.json");
    let ids = bench.device_ids();
    assert_eq!(ids.len(), 2);
    let (_, keys, _) = bench.cli(&["pubkey"]);
    assert_eq!(
        keys.lines().collect::<Vec<_>>(),
        vec![bench.public_key.as_str(), second.as_str()]
    );

    // The first device is off: only the second one answers.
    let (agent, socket) = bench.agent_with(&["--timeout", "30", "--pickup", "3"]);
    let phone = bench.phone_at("phone2.json", &[]);
    let started = Instant::now();
    let (ok, out, err) = ssh(&socket, bench.sshd.port);
    assert!(ok, "ssh failed: {err}\n{}", bench.agent_log());
    assert!(out.contains("signed-in"));
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "took {:?}",
        started.elapsed()
    );
    phone.event("signed");
    assert!(bench
        .agent_log()
        .contains("did not pick the request up within 3 s"));
    drop(agent);

    // Offered first, the second device signs at once.
    let (ok, out, _) = bench.cli(&["devices", "--first", &ids[1]]);
    assert!(ok && out.contains("now offered first"), "{out}");
    let (_, keys, _) = bench.cli(&["pubkey"]);
    assert_eq!(keys.lines().next(), Some(second.as_str()));
    let (_agent, socket) = bench.agent_with(&["--timeout", "30", "--pickup", "3"]);
    let started = Instant::now();
    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(ok);
    assert!(started.elapsed() < Duration::from_secs(3));
    phone.event("signed");
}

#[test]
fn a_denial_on_one_device_refuses_the_login_without_asking_the_other() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    bench.add_device("phone2.json");
    let (_agent, socket) = bench.agent_with(&["--timeout", "30", "--pickup", "3"]);
    let first = bench.phone_at("phone.json", &["--deny"]);
    let second = bench.phone_at("phone2.json", &[]);
    let (ok, _, _) = ssh(&socket, bench.sshd.port);
    assert!(!ok, "a refusal must refuse the login");
    first.event("denied");
    std::thread::sleep(Duration::from_millis(500));
    assert!(second.nothing_more(), "the other device must not be asked");
}

#[test]
fn one_device_can_be_unpaired_alone_from_either_end() {
    if !available() {
        return;
    }
    let bench = Bench::new();
    let second = bench.add_device("phone2.json");
    bench.add_device("phone3.json");
    let ids = bench.device_ids();

    // From the agent: the first device.
    let first = bench.phone_at("phone.json", &[]);
    let (ok, out, err) = bench.cli(&["unpair", "--device", &ids[0]]);
    assert!(ok, "{err}");
    assert!(out.contains("Device revoked on the relay."), "{out}");
    assert!(out.contains(&bench.public_key), "{out}");
    first.event("revoked");
    assert_eq!(bench.device_ids(), ids[1..].to_vec());

    // From a device: the third forgets itself; the channel stays.
    let revoked = Command::new("node")
        .arg(repo().join("tools/fake-phone.mjs"))
        .args(["revoke", "--state"])
        .arg(bench.path("phone3.json"))
        .output()
        .unwrap();
    let event: Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert_eq!(event["deleted"], true);

    // The second device still signs.
    let (_agent, socket) = bench.agent_with(&["--timeout", "30"]);
    let phone = bench.phone_at("phone2.json", &[]);
    let (ok, _, err) = ssh(&socket, bench.sshd.port);
    assert!(ok, "{err}\n{}", bench.agent_log());
    assert_eq!(phone.event("signed")["state"], "accepted");
    let _ = second;

    // The agent still lists the third until told: asking it fails clearly.
    let (ok, out, _) = bench.cli(&["unpair", "--device", &ids[2]]);
    assert!(ok);
    assert!(out.contains("no longer knew this device"), "{out}");
    assert_eq!(bench.device_ids(), vec![ids[1].clone()]);
}
