//! Shared by the integration tests: a scratch `sshd` on a loopback port
//! and the stock `ssh` client pointed at an agent socket.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

const SSHD: &str = "/usr/sbin/sshd";

/// A child process killed when dropped.
pub struct Kill(pub Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch sshd, killed when dropped.
pub struct Sshd {
    _child: Kill,
    pub port: u16,
    pub host_key_blob: Vec<u8>,
    /// `"SHA256:…"` of the host key.
    pub host_fingerprint: String,
    pub log: PathBuf,
}

pub fn write_private(path: &Path, content: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

/// A port nobody listens on right now.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn wait_for_port(port: u16, what: &str, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < deadline,
            "{what} did not start: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Start an sshd that accepts `authorized_key` for the current user.
pub fn start_sshd(dir: &Path, authorized_key: &str) -> Sshd {
    let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key_path = dir.join("host_key");
    write_private(
        &host_key_path,
        &host_key.to_openssh(LineEnding::LF).unwrap(),
    );
    let authorized = dir.join("authorized_keys");
    write_private(&authorized, &format!("{authorized_key}\n"));

    let port = free_port();
    let config = dir.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {}\n\
             PidFile none\n\
             AuthorizedKeysFile {}\n\
             StrictModes no\n\
             UsePAM no\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             MaxStartups 100\n",
            host_key_path.display(),
            authorized.display()
        ),
    )
    .unwrap();

    let log = dir.join("sshd.log");
    let child = Command::new(SSHD)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let sshd = Sshd {
        _child: Kill(child),
        port,
        host_key_blob: host_key.public_key().to_bytes().unwrap(),
        host_fingerprint: host_key.fingerprint(HashAlg::Sha256).to_string(),
        log,
    };
    wait_for_port(port, "sshd", &sshd.log);
    sshd
}

pub fn current_user() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Options that make the stock client use nothing but the agent, and
/// leave the user's own configuration and known hosts alone.
pub const SSH_OPTIONS: &[&str] = &[
    "-F",
    "none",
    "-o",
    "BatchMode=yes",
    "-o",
    "IdentityFile=none",
    "-o",
    "PreferredAuthentications=publickey",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "ConnectTimeout=10",
];

/// Run the stock client against the scratch server, with the agent as
/// its only source of keys. Returns (success, stdout, stderr).
pub fn ssh(agent_socket: &Path, port: u16) -> (bool, String, String) {
    ssh_run(agent_socket, port, false, "echo signed-in")
}

/// Same, running `remote_command` there, with the agent forwarded to the
/// server (`ssh -A`) when `forward_agent` is set.
pub fn ssh_run(
    agent_socket: &Path,
    port: u16,
    forward_agent: bool,
    remote_command: &str,
) -> (bool, String, String) {
    let mut command = Command::new("ssh");
    command
        .args(SSH_OPTIONS)
        .args(["-p", &port.to_string()])
        .arg("-o")
        .arg(format!("IdentityAgent={}", agent_socket.display()));
    if forward_agent {
        command.arg("-A");
    }
    let out = command
        .args(["127.0.0.1", remote_command])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

pub fn openssh_available() -> bool {
    let ok = Path::new(SSHD).exists() && Command::new("ssh").arg("-V").output().is_ok();
    skip_unless(ok, "sshd or ssh not installed")
}

/// Report a skipped test — or fail, where skipping would hide a broken
/// set-up (`CLAVIX_REQUIRE_E2E` is set in CI).
pub fn skip_unless(available: bool, why: &str) -> bool {
    if !available {
        assert!(
            std::env::var_os("CLAVIX_REQUIRE_E2E").is_none(),
            "end-to-end test cannot run: {why}"
        );
        eprintln!("skipped: {why}");
    }
    available
}
