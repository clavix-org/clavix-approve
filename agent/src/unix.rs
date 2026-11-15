//! Unix-socket transport (`SSH_AUTH_SOCK`): how connections arrive and
//! how the caller is identified. Derived from the `unix` module of the
//! Clavix desktop agent (GPL-3.0-or-later).

use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::proto::{serve, CallerInfo, Signer};

pub struct AgentHandle {
    pub socket_path: PathBuf,
    task: JoinHandle<()>,
}

impl AgentHandle {
    /// Stop accepting connections and remove the socket. Connections
    /// already being served end when their client disconnects.
    pub async fn stop(self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// The command line of a process, for guessing which host it is
/// connecting to (see `relay::host_candidates`). Linux-only via `/proc`;
/// empty when it cannot be read. Like the process name, it is whatever
/// the process chose to show.
pub fn process_args(pid: u32) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|raw| {
                raw.split(|b| *b == 0)
                    .map(|arg| String::from_utf8_lossy(arg).into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Read the peer's credentials off an accepted connection.
///
/// Returns `None` rather than failing the connection: an unidentifiable
/// caller must still be able to request a signature (the user then sees
/// "unknown", which is itself useful information).
fn peer_caller(stream: &UnixStream) -> Option<CallerInfo> {
    let cred = stream.peer_cred().ok()?;
    // `pid()` is `Option` because not every Unix exposes it.
    let pid = cred.pid()?;
    if pid <= 0 {
        return None;
    }
    let pid = pid as u32;
    Some(CallerInfo {
        pid,
        name: process_name(pid),
    })
}

/// Resolve a pid to a process name. Linux-only via `/proc`; other Unixes
/// get `None` and the approval screen falls back to the bare pid.
fn process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        // `comm` is attacker-controlled text heading for a screen.
        crate::proto::sanitize_process_label(comm.trim())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Listen on `socket_path` and serve every connection with `signer`.
/// The socket is only reachable by the current user.
pub async fn start_agent(
    socket_path: PathBuf,
    signer: Arc<dyn Signer>,
) -> std::io::Result<AgentHandle> {
    // Remove any stale socket file.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let path_for_task = socket_path.clone();
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let signer = signer.clone();
                    // Resolve the peer at accept time: the pid is only
                    // guaranteed meaningful while the connection is
                    // open, and the process may exit mid-request.
                    let caller = peer_caller(&stream);
                    tokio::spawn(async move {
                        if let Err(e) = serve(stream, signer.as_ref(), caller).await {
                            eprintln!("[clavix-agent] connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!(
                        "[clavix-agent] accept failed on {}: {e}",
                        path_for_task.display()
                    );
                    break;
                }
            }
        }
    });

    Ok(AgentHandle { socket_path, task })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Both ends of the connection live in this test process, so the
    /// credentials the agent reads must resolve to our own pid — which
    /// makes the expected value exactly known rather than "some pid".
    #[tokio::test]
    async fn peer_caller_resolves_the_connecting_process() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let connect = tokio::spawn({
            let sock = sock.clone();
            async move { UnixStream::connect(&sock).await.unwrap() }
        });
        let (server_side, _) = listener.accept().await.unwrap();
        let _client = connect.await.unwrap();

        let caller = peer_caller(&server_side).expect("peer credentials available on Linux");
        assert_eq!(caller.pid, std::process::id());
        // The name comes from /proc/<pid>/comm — the test binary's own.
        let name = caller.name.expect("comm readable for a live process");
        assert!(!name.is_empty());
        assert!(!name.contains('\n'), "name must be a single line: {name:?}");
    }

    /// A pid that cannot exist yields no name rather than a bogus one.
    #[test]
    fn process_name_is_none_for_an_unknown_pid() {
        assert_eq!(process_name(u32::MAX), None);
    }

    #[tokio::test]
    async fn the_socket_is_private_and_removed_on_stop() {
        use std::os::unix::fs::PermissionsExt;

        struct NoKeys;
        impl Signer for NoKeys {
            fn identities(&self) -> Vec<crate::proto::Identity> {
                Vec::new()
            }
            fn sign(&self, _job: crate::proto::SignJob) -> crate::proto::SignFuture {
                Box::pin(async { Err(crate::proto::SignError::Denied) })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        let handle = start_agent(sock.clone(), Arc::new(NoKeys)).await.unwrap();
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        handle.stop().await;
        assert!(!sock.exists());
    }
}
