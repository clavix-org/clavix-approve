//! Platform-neutral core: framing, message handlers, session binding and
//! the signer backend interface.
//!
//! Derived from the `proto` module of the Clavix desktop agent
//! (`src-tauri/src/ssh_agent.rs`, GPL-3.0-or-later). What changed:
//!
//! - there is no key store: identities and signatures come from a
//!   [`Signer`] backend, which replaces the boolean confirmation callback;
//! - a session binding keeps the host's raw signature, so the device that
//!   signs can verify the binding itself instead of trusting this machine;
//! - a signature is only requested for a public-key user-auth request on a
//!   connection bound to that very session — nothing else is forwarded.

use std::future::Future;
use std::pin::Pin;

use signature::Verifier;
use ssh_key::{HashAlg, PublicKey, Signature};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Agent protocol message types (draft-miller-ssh-agent).
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// OpenSSH >= 8.9 binds each agent connection to the SSH session it
/// serves (PROTOCOL.agent, "session-bind@openssh.com").
pub const EXT_SESSION_BIND: &[u8] = b"session-bind@openssh.com";
/// Same cap as OpenSSH's `AGENT_MAX_SESSION_IDS`: a forwarding chain
/// deeper than this is not a real use case, only a memory sink.
pub const MAX_SESSION_BINDS: usize = 16;
/// `SSH_MSG_USERAUTH_REQUEST` (RFC 4252), the byte that follows the
/// session identifier in the data a client asks us to sign for
/// public-key authentication.
const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// The only user-auth method this agent signs for (OpenSSH >= 8.9). Plain
/// `publickey` does not name the server in the signed bytes: anyone
/// holding a host key the user trusts could bind a session it opened with
/// another server and pass a login there off as a login to itself.
pub const METHOD_HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
const METHOD_PLAIN: &[u8] = b"publickey";

// Cap any single agent request to 256 KB — real traffic is orders smaller.
pub const MAX_MESSAGE: usize = 256 * 1024;

/// Best-effort identity of the process on the other end of an agent
/// connection, shown on the approval screen so the user can tell a
/// `git push` they just ran from a signature they never asked for.
///
/// This is INDICATIVE, NOT A SECURITY BOUNDARY. The OS vouches for the
/// pid at connect time, but pids are recycled and process names are
/// unauthenticated labels the process itself can change. The approving
/// device must label it as unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerInfo {
    pub pid: u32,
    /// Process name, when it can be read.
    pub name: Option<String>,
}

/// One `session-bind@openssh.com` binding: a server host key whose
/// signature over the session identifier we verified, so we know the
/// SSH client really holds a session with that host.
///
/// The host key IS authenticated — but a host key is not a host name.
/// Naming it is the approving device's job, from its own pinned list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHop {
    /// SSH wire-format public host key.
    pub key_blob: Vec<u8>,
    /// `"SHA256:…"` fingerprint of the host key.
    pub fingerprint: String,
    /// `true` when this hop carries a forwarded agent (`ssh -A`),
    /// `false` when the binding is for authenticating to that host.
    pub forwarded: bool,
    /// Exchange hash of the bound session.
    pub session_id: Vec<u8>,
    /// The host key's signature over `session_id`, SSH wire format. Kept
    /// so the signer can repeat our verification rather than believe it.
    pub signature: Vec<u8>,
}

/// Per-connection agent state. `session-bind` is scoped to the
/// connection it arrives on.
#[derive(Debug, Default)]
pub struct ConnState {
    pub hops: Vec<HostHop>,
}

impl ConnState {
    /// The last binding, if it was for authentication. OpenSSH treats
    /// such a connection as spent for further binds, and expects any
    /// user-auth signature on it to be for that very session.
    fn bound_for_auth(&self) -> Option<&HostHop> {
        self.hops.last().filter(|h| !h.forwarded)
    }
}

/// A public key the agent offers to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// SSH wire-format public key blob (what clients compare against).
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// Everything the signer needs to decide and to sign.
#[derive(Debug, Clone)]
pub struct SignJob {
    /// Which identity must sign.
    pub key_blob: Vec<u8>,
    /// The exact bytes to sign: a public-key user-auth request.
    pub data: Vec<u8>,
    /// Flags of the agent sign request (only meaningful for RSA keys).
    pub flags: u32,
    /// Session bindings of the requesting connection, outermost first:
    /// `[host1 (forwarded), host2 (auth)]` means "authenticate to host2
    /// from host1, through the agent forwarded to host1". Never empty,
    /// and the last one is always the authentication binding.
    pub hops: Vec<HostHop>,
    pub caller: Option<CallerInfo>,
}

/// Why no signature came back. Clients only ever see
/// `SSH_AGENT_FAILURE`; the distinction is for the agent's own log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The user said no.
    Denied,
    /// Nobody answered in time.
    Expired,
    /// The signer could not be reached or answered nonsense.
    Backend(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => f.write_str("denied by the signer"),
            Self::Expired => f.write_str("no answer from signer"),
            Self::Backend(reason) => write!(f, "signer unavailable: {reason}"),
        }
    }
}

pub type SignFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, SignError>> + Send>>;

/// Where signatures come from. The agent itself cannot sign anything.
pub trait Signer: Send + Sync {
    /// Public keys to offer. Cheap and local: called for every request.
    fn identities(&self) -> Vec<Identity>;

    /// Obtain the SSH wire-format signature (`string algorithm, string
    /// blob`) of `job.data` under `job.key_blob`. May take as long as a
    /// human needs; the implementation owns the timeout.
    fn sign(&self, job: SignJob) -> SignFuture;
}

/// A parsed host-bound public-key user-auth request (RFC 4252 §7 with
/// OpenSSH's `publickey-hostbound-v00@openssh.com`) — the only thing this
/// agent will ask a signer to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAuthRequest<'a> {
    pub session_id: &'a [u8],
    pub user: &'a [u8],
    pub service: &'a [u8],
    pub algorithm: &'a [u8],
    /// The client key the request authenticates with.
    pub key_blob: &'a [u8],
    /// Server host key the client authenticates to.
    pub host_key: &'a [u8],
}

/// Reduce an OS-supplied process label (Linux `/proc/<pid>/comm`) to a
/// short, printable, single-line string: it is headed for an approval
/// screen and the process itself controls parts of it.
pub fn sanitize_process_label(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(32)
        .collect::<String>()
        .trim()
        .to_string();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn log(message: &str) {
    eprintln!("[clavix-agent] {message}");
}

/// Run one agent message (type byte + body — what a socket would carry
/// after its length prefix) and return the response *without* framing.
pub async fn process_message(
    msg: &[u8],
    signer: &dyn Signer,
    caller: Option<&CallerInfo>,
    conn: &mut ConnState,
) -> Vec<u8> {
    let Some((&msg_type, body)) = msg.split_first() else {
        return vec![SSH_AGENT_FAILURE];
    };
    match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => handle_list(signer),
        SSH_AGENTC_SIGN_REQUEST => handle_sign(signer, body, caller, conn).await,
        SSH_AGENTC_EXTENSION => handle_extension(body, conn),
        _ => vec![SSH_AGENT_FAILURE],
    }
}

/// `SSH_AGENTC_EXTENSION`. Only `session-bind@openssh.com` is
/// understood; anything else gets the generic failure, which is what
/// PROTOCOL.agent prescribes for an unsupported extension.
fn handle_extension(body: &[u8], conn: &mut ConnState) -> Vec<u8> {
    let mut reader = SshReader::new(body);
    match reader.read_string() {
        Ok(EXT_SESSION_BIND) => match session_bind(&mut reader, conn) {
            Some(()) => vec![SSH_AGENT_SUCCESS],
            None => vec![SSH_AGENT_FAILURE],
        },
        _ => vec![SSH_AGENT_FAILURE],
    }
}

/// Parse, verify and record one session binding:
///
/// ```text
/// string  hostkey
/// string  session identifier
/// string  signature (by hostkey, over the session identifier)
/// bool    is_forwarding
/// ```
///
/// The rules mirror OpenSSH's `process_ext_session_bind`, so a client
/// sees the same answers as from `ssh-agent`. `None` means "refuse".
fn session_bind(reader: &mut SshReader<'_>, conn: &mut ConnState) -> Option<()> {
    let key_blob = reader.read_string().ok()?;
    let session_id = reader.read_string().ok()?;
    let sig_blob = reader.read_string().ok()?;
    let forwarded = match reader.read_u8().ok()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    if !reader.is_empty() {
        return None;
    }

    // The signature is what turns "the client says it talks to this
    // host" into "the client holds a session that this host key
    // signed". Without it a binding would be an unverified label.
    let host_key = PublicKey::from_bytes(key_blob).ok()?;
    let signature = Signature::try_from(sig_blob).ok()?;
    // Fully qualified: `PublicKey` also has an inherent `verify` for
    // SSHSIG (namespace + message), which is not this.
    Verifier::verify(&host_key, session_id, &signature).ok()?;

    // Re-binding a session already seen is fine (OpenSSH re-sends the
    // forwarding bind on every forwarded channel) as long as it names
    // the same host key; a different key for the same session is a lie.
    if let Some(existing) = conn.hops.iter().find(|h| h.session_id == session_id) {
        return (existing.key_blob == key_blob).then_some(());
    }
    // A connection bound for authentication is spent: nothing may be
    // chained after it.
    if conn.bound_for_auth().is_some() || conn.hops.len() >= MAX_SESSION_BINDS {
        return None;
    }
    conn.hops.push(HostHop {
        key_blob: key_blob.to_vec(),
        fingerprint: host_key.fingerprint(HashAlg::Sha256).to_string(),
        forwarded,
        session_id: session_id.to_vec(),
        signature: sig_blob.to_vec(),
    });
    Some(())
}

/// The user-auth method named by `data`, if it starts like a user-auth
/// request. Only used to explain a refusal.
fn userauth_method(data: &[u8]) -> Option<&[u8]> {
    let mut r = SshReader::new(data);
    r.read_string().ok()?;
    if r.read_u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    r.read_string().ok()?;
    r.read_string().ok()?;
    r.read_string().ok()
}

/// Parse `data` as a host-bound public-key user-auth request. `None` for
/// anything else (plain `publickey`, git's `SSHSIG`, arbitrary data) and
/// for trailing bytes.
pub fn parse_userauth_request(data: &[u8]) -> Option<UserAuthRequest<'_>> {
    let mut r = SshReader::new(data);
    let session_id = r.read_string().ok()?;
    if r.read_u8().ok()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = r.read_string().ok()?;
    let service = r.read_string().ok()?;
    if r.read_string().ok()? != METHOD_HOSTBOUND {
        return None;
    }
    if r.read_u8().ok()? != 1 {
        return None;
    }
    let algorithm = r.read_string().ok()?;
    let key_blob = r.read_string().ok()?;
    let host_key = r.read_string().ok()?;
    r.is_empty().then_some(UserAuthRequest {
        session_id,
        user,
        service,
        algorithm,
        key_blob,
        host_key,
    })
}

/// Serve one connection: read length-prefixed requests until the peer
/// disconnects, answering each with a length-prefixed response.
pub async fn serve<S>(
    mut stream: S,
    signer: &dyn Signer,
    caller: Option<CallerInfo>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = ConnState::default();
    loop {
        let len = match stream.read_u32().await {
            Ok(n) => n as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if len == 0 || len > MAX_MESSAGE {
            return Ok(());
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let response = process_message(&buf, signer, caller.as_ref(), &mut conn).await;

        let len_bytes = u32::to_be_bytes(response.len() as u32);
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

fn handle_list(signer: &dyn Signer) -> Vec<u8> {
    let identities = signer.identities();
    let mut out = Vec::with_capacity(64);
    out.push(SSH_AGENT_IDENTITIES_ANSWER);
    out.extend_from_slice(&u32::to_be_bytes(identities.len() as u32));
    for id in &identities {
        write_string(&mut out, &id.key_blob);
        write_string(&mut out, id.comment.as_bytes());
    }
    out
}

/// Does `sig_blob` verify as a signature of `data` under `key_blob`?
fn signature_is_valid(key_blob: &[u8], data: &[u8], sig_blob: &[u8]) -> bool {
    let Ok(key) = PublicKey::from_bytes(key_blob) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig_blob) else {
        return false;
    };
    Verifier::verify(&key, data, &signature).is_ok()
}

async fn handle_sign(
    signer: &dyn Signer,
    payload: &[u8],
    caller: Option<&CallerInfo>,
    conn: &ConnState,
) -> Vec<u8> {
    let failure = vec![SSH_AGENT_FAILURE];
    let mut reader = SshReader::new(payload);
    let Ok(key_blob) = reader.read_string() else {
        return failure;
    };
    let Ok(data) = reader.read_string() else {
        return failure;
    };
    let flags = reader.read_u32().unwrap_or(0);

    if !signer.identities().iter().any(|i| i.key_blob == key_blob) {
        return failure;
    }

    // Refuse early what the signer would refuse anyway, without waking
    // anyone up: the request must be a host-bound user-auth request for
    // the session this connection is bound to and for that session's host
    // key, made with the key we are asked to sign with. A hostile server
    // holding a forwarded agent cannot then relay another session's
    // challenge through a connection whose binding the user is looking
    // at: even if it binds that session with its own key, the request
    // names the other server's key. The signer repeats every one of these
    // checks: this machine may lie.
    let Some(bound) = conn.bound_for_auth() else {
        log("sign request refused: connection has no session binding for authentication");
        return failure;
    };
    let Some(request) = parse_userauth_request(data) else {
        if userauth_method(data) == Some(METHOD_PLAIN) {
            log(
                "sign request refused: plain \"publickey\" login, which does not name the server; \
                 client and server must be OpenSSH 8.9 or later (publickey-hostbound-v00@openssh.com)",
            );
        } else {
            log("sign request refused: not a host-bound public-key user-auth request");
        }
        return failure;
    };
    if request.session_id != bound.session_id.as_slice()
        || request.key_blob != key_blob
        || request.host_key != bound.key_blob.as_slice()
    {
        log("sign request refused: it does not match the bound session and host key");
        return failure;
    }

    let job = SignJob {
        key_blob: key_blob.to_vec(),
        data: data.to_vec(),
        flags,
        hops: conn.hops.clone(),
        caller: caller.cloned(),
    };
    // One log line per request, whatever its outcome: the host key
    // fingerprint (which this machine knows anyway) and how long the
    // signer took — the figure that matters against the expiry.
    let started = std::time::Instant::now();
    let answer = signer.sign(job).await;
    let waited = started.elapsed().as_secs_f32();
    let sig_blob = match answer {
        Ok(sig) => sig,
        Err(e) => {
            log(&format!(
                "no signature for {} after {waited:.1} s: {e}",
                bound.fingerprint
            ));
            return failure;
        }
    };
    // A wrong signature would only fail later, at the server, with a
    // less useful message — and a signer returning one is worth knowing.
    if !signature_is_valid(key_blob, data, &sig_blob) {
        log(&format!(
            "signer returned a signature that does not verify for {} after {waited:.1} s; dropped",
            bound.fingerprint
        ));
        return failure;
    }
    log(&format!(
        "signed for {} after {waited:.1} s",
        bound.fingerprint
    ));

    let mut out = Vec::with_capacity(sig_blob.len() + 5);
    out.push(SSH_AGENT_SIGN_RESPONSE);
    write_string(&mut out, &sig_blob);
    out
}

pub fn write_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.extend_from_slice(&u32::to_be_bytes(s.len() as u32));
    buf.extend_from_slice(s);
}

pub struct SshReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u32(&mut self) -> std::io::Result<u32> {
        let end = self
            .pos
            .checked_add(4)
            .filter(|&end| end <= self.buf.len())
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        let n = u32::from_be_bytes(self.buf[self.pos..end].try_into().unwrap());
        self.pos = end;
        Ok(n)
    }

    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    /// `true` once every byte has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn read_string(&mut self) -> std::io::Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.buf.len())
            .ok_or(std::io::ErrorKind::UnexpectedEof)?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    /// An Ed25519 key pair in SSH wire format: plays the server host key
    /// and the remote signer, the two roles the agent does not have.
    struct TestKey(SigningKey);

    impl TestKey {
        fn new(seed: u8) -> Self {
            Self(SigningKey::from_bytes(&[seed; 32]))
        }
        fn blob(&self) -> Vec<u8> {
            let mut b = Vec::new();
            write_string(&mut b, b"ssh-ed25519");
            write_string(&mut b, self.0.verifying_key().as_bytes());
            b
        }
        fn sign(&self, data: &[u8]) -> Vec<u8> {
            let mut b = Vec::new();
            write_string(&mut b, b"ssh-ed25519");
            write_string(&mut b, &self.0.sign(data).to_bytes());
            b
        }
    }

    /// What the fake signer does with a job.
    enum Behaviour {
        Sign,
        Deny,
        /// Answer with a signature made by another key.
        SignWithWrongKey,
    }

    struct FakeSigner {
        key: TestKey,
        behaviour: Behaviour,
        jobs: Mutex<Vec<SignJob>>,
    }

    impl FakeSigner {
        fn new(behaviour: Behaviour) -> Self {
            Self {
                key: TestKey::new(9),
                behaviour,
                jobs: Mutex::new(Vec::new()),
            }
        }
        fn asked(&self) -> usize {
            self.jobs.lock().unwrap().len()
        }
    }

    impl Signer for FakeSigner {
        fn identities(&self) -> Vec<Identity> {
            vec![Identity {
                key_blob: self.key.blob(),
                comment: "phone".into(),
            }]
        }
        fn sign(&self, job: SignJob) -> SignFuture {
            let answer = match self.behaviour {
                Behaviour::Sign => Ok(self.key.sign(&job.data)),
                Behaviour::Deny => Err(SignError::Denied),
                Behaviour::SignWithWrongKey => Ok(TestKey::new(10).sign(&job.data)),
            };
            self.jobs.lock().unwrap().push(job);
            Box::pin(async move { answer })
        }
    }

    fn run(msg: &[u8], signer: &FakeSigner, conn: &mut ConnState) -> Vec<u8> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(process_message(msg, signer, None, conn))
    }

    fn bind_msg(host_blob: &[u8], sid: &[u8], sig: &[u8], forwarded: bool) -> Vec<u8> {
        let mut m = vec![SSH_AGENTC_EXTENSION];
        write_string(&mut m, EXT_SESSION_BIND);
        write_string(&mut m, host_blob);
        write_string(&mut m, sid);
        write_string(&mut m, sig);
        m.push(forwarded as u8);
        m
    }

    fn bind(conn: &mut ConnState, host: &TestKey, sid: &[u8], forwarded: bool) -> Vec<u8> {
        let msg = bind_msg(&host.blob(), sid, &host.sign(sid), forwarded);
        run(&msg, &FakeSigner::new(Behaviour::Sign), conn)
    }

    fn userauth(sid: &[u8], client_key: &[u8], hostbound: Option<&[u8]>) -> Vec<u8> {
        let mut d = Vec::new();
        write_string(&mut d, sid);
        d.push(SSH_MSG_USERAUTH_REQUEST);
        write_string(&mut d, b"git");
        write_string(&mut d, b"ssh-connection");
        match hostbound {
            Some(_) => write_string(&mut d, b"publickey-hostbound-v00@openssh.com"),
            None => write_string(&mut d, b"publickey"),
        }
        d.push(1);
        write_string(&mut d, b"ssh-ed25519");
        write_string(&mut d, client_key);
        if let Some(hk) = hostbound {
            write_string(&mut d, hk);
        }
        d
    }

    fn sign_msg(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = vec![SSH_AGENTC_SIGN_REQUEST];
        write_string(&mut m, key_blob);
        write_string(&mut m, data);
        m.extend_from_slice(&u32::to_be_bytes(0));
        m
    }

    // ---- framing ---------------------------------------------------------

    #[test]
    fn write_string_prepends_big_endian_length() {
        let mut out = Vec::new();
        write_string(&mut out, b"hello");
        assert_eq!(out, [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn ssh_reader_roundtrip_matches_write_string() {
        let mut buf = Vec::new();
        write_string(&mut buf, b"first");
        write_string(&mut buf, b"");
        buf.extend_from_slice(&u32::to_be_bytes(7));
        let mut r = SshReader::new(&buf);
        assert_eq!(r.read_string().unwrap(), b"first");
        assert_eq!(r.read_string().unwrap(), b"");
        assert_eq!(r.read_u32().unwrap(), 7);
        assert!(r.is_empty());
    }

    #[test]
    fn ssh_reader_rejects_truncated_input() {
        // Announces 10 bytes, carries 2.
        assert!(SshReader::new(&[0, 0, 0, 10, 1, 2]).read_string().is_err());
        // A length that would overflow the position must not panic.
        assert!(SshReader::new(&[0xff, 0xff, 0xff, 0xff])
            .read_string()
            .is_err());
        assert!(SshReader::new(&[0, 0, 1]).read_u32().is_err());
    }

    #[test]
    fn unknown_message_types_and_extensions_fail() {
        let signer = FakeSigner::new(Behaviour::Sign);
        let mut conn = ConnState::default();
        assert_eq!(run(&[], &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
        assert_eq!(run(&[200], &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
        let mut m = vec![SSH_AGENTC_EXTENSION];
        write_string(&mut m, b"query");
        assert_eq!(run(&m, &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
    }

    #[test]
    fn identities_come_from_the_signer() {
        let signer = FakeSigner::new(Behaviour::Sign);
        let out = run(
            &[SSH_AGENTC_REQUEST_IDENTITIES],
            &signer,
            &mut ConnState::default(),
        );
        let mut expected = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1];
        write_string(&mut expected, &signer.key.blob());
        write_string(&mut expected, b"phone");
        assert_eq!(out, expected);
    }

    // ---- session-bind@openssh.com ----------------------------------------

    #[test]
    fn session_bind_records_a_verified_binding_with_its_signature() {
        let host = TestKey::new(7);
        let mut conn = ConnState::default();
        assert_eq!(
            bind(&mut conn, &host, b"sid-1", false),
            vec![SSH_AGENT_SUCCESS]
        );
        assert_eq!(conn.hops.len(), 1);
        let hop = &conn.hops[0];
        assert_eq!(hop.key_blob, host.blob());
        assert_eq!(hop.session_id, b"sid-1");
        assert_eq!(hop.signature, host.sign(b"sid-1"));
        assert!(!hop.forwarded);
        assert!(hop.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn session_bind_rejects_a_signature_from_another_key() {
        let (host, impostor) = (TestKey::new(7), TestKey::new(8));
        let signer = FakeSigner::new(Behaviour::Sign);
        let mut conn = ConnState::default();
        let msg = bind_msg(&host.blob(), b"sid-1", &impostor.sign(b"sid-1"), false);
        assert_eq!(run(&msg, &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
        // Signed by the right key but over another session id.
        let msg = bind_msg(&host.blob(), b"sid-1", &host.sign(b"sid-2"), false);
        assert_eq!(run(&msg, &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
        assert!(conn.hops.is_empty());
    }

    #[test]
    fn session_bind_rejects_malformed_bodies() {
        let host = TestKey::new(7);
        let signer = FakeSigner::new(Behaviour::Sign);
        let mut conn = ConnState::default();
        let mut msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
        msg.push(0); // trailing garbage
        assert_eq!(run(&msg, &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
        let mut msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
        *msg.last_mut().unwrap() = 2; // not a boolean
        assert_eq!(run(&msg, &signer, &mut conn), vec![SSH_AGENT_FAILURE]);
        let msg = bind_msg(&host.blob(), b"sid", &host.sign(b"sid"), false);
        assert_eq!(
            run(&msg[..msg.len() - 1], &signer, &mut conn),
            vec![SSH_AGENT_FAILURE]
        );
        assert!(conn.hops.is_empty());
    }

    #[test]
    fn forwarding_chain_is_recorded_outermost_first() {
        let (jump, dest) = (TestKey::new(1), TestKey::new(2));
        let mut conn = ConnState::default();
        assert_eq!(
            bind(&mut conn, &jump, b"sid-jump", true),
            vec![SSH_AGENT_SUCCESS]
        );
        // OpenSSH re-sends the forwarding bind per channel: idempotent.
        assert_eq!(
            bind(&mut conn, &jump, b"sid-jump", true),
            vec![SSH_AGENT_SUCCESS]
        );
        assert_eq!(
            bind(&mut conn, &dest, b"sid-dest", false),
            vec![SSH_AGENT_SUCCESS]
        );
        let shape: Vec<_> = conn
            .hops
            .iter()
            .map(|h| (h.key_blob.clone(), h.forwarded))
            .collect();
        assert_eq!(shape, vec![(jump.blob(), true), (dest.blob(), false)]);
    }

    #[test]
    fn same_session_with_another_host_key_is_refused() {
        let (a, b) = (TestKey::new(1), TestKey::new(2));
        let mut conn = ConnState::default();
        assert_eq!(bind(&mut conn, &a, b"sid", true), vec![SSH_AGENT_SUCCESS]);
        assert_eq!(bind(&mut conn, &b, b"sid", true), vec![SSH_AGENT_FAILURE]);
        assert_eq!(conn.hops.len(), 1);
    }

    #[test]
    fn a_connection_bound_for_auth_accepts_no_further_binding() {
        let (a, b) = (TestKey::new(1), TestKey::new(2));
        let mut conn = ConnState::default();
        assert_eq!(
            bind(&mut conn, &a, b"sid-a", false),
            vec![SSH_AGENT_SUCCESS]
        );
        assert_eq!(bind(&mut conn, &b, b"sid-b", true), vec![SSH_AGENT_FAILURE]);
        assert_eq!(conn.hops.len(), 1);
    }

    #[test]
    fn binding_count_is_capped() {
        let host = TestKey::new(3);
        let mut conn = ConnState::default();
        for i in 0..MAX_SESSION_BINDS {
            let sid = format!("sid-{i}");
            assert_eq!(
                bind(&mut conn, &host, sid.as_bytes(), true),
                vec![SSH_AGENT_SUCCESS]
            );
        }
        assert_eq!(
            bind(&mut conn, &host, b"one-too-many", true),
            vec![SSH_AGENT_FAILURE]
        );
    }

    #[test]
    fn parse_userauth_request_accepts_only_host_bound_requests() {
        let hb = userauth(b"s", b"k", Some(b"hk"));
        let parsed = parse_userauth_request(&hb).unwrap();
        assert_eq!(parsed.session_id, b"s");
        assert_eq!(parsed.user, b"git");
        assert_eq!(parsed.service, b"ssh-connection");
        assert_eq!(parsed.algorithm, b"ssh-ed25519");
        assert_eq!(parsed.key_blob, b"k");
        assert_eq!(parsed.host_key, b"hk");

        // Plain `publickey` does not name the server: refused.
        let plain = userauth(b"s", b"k", None);
        assert_eq!(parse_userauth_request(&plain), None);
        assert_eq!(userauth_method(&plain), Some(METHOD_PLAIN));

        let mut trailing = userauth(b"s", b"k", Some(b"hk"));
        trailing.push(0);
        assert_eq!(parse_userauth_request(&trailing), None);
        assert_eq!(parse_userauth_request(b"SSHSIG"), None);
        assert_eq!(parse_userauth_request(&[]), None);
    }

    // ---- signing ---------------------------------------------------------

    #[test]
    fn a_bound_userauth_request_is_signed_by_the_signer() {
        let host = TestKey::new(4);
        let signer = FakeSigner::new(Behaviour::Sign);
        let key = signer.key.blob();
        let mut conn = ConnState::default();
        bind(&mut conn, &host, b"sid-ok", false);

        let data = userauth(b"sid-ok", &key, Some(&host.blob()));
        let out = run(&sign_msg(&key, &data), &signer, &mut conn);

        let mut expected = vec![SSH_AGENT_SIGN_RESPONSE];
        write_string(&mut expected, &signer.key.sign(&data));
        assert_eq!(out, expected);

        // The signer received what it needs to re-verify the destination.
        let jobs = signer.jobs.lock().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].key_blob, key);
        assert_eq!(jobs[0].data, data);
        assert_eq!(jobs[0].hops, conn.hops);
    }

    #[test]
    fn the_whole_forwarding_chain_reaches_the_signer() {
        let (jump, dest) = (TestKey::new(1), TestKey::new(2));
        let signer = FakeSigner::new(Behaviour::Sign);
        let key = signer.key.blob();
        let mut conn = ConnState::default();
        bind(&mut conn, &jump, b"sid-j", true);
        bind(&mut conn, &dest, b"sid-d", false);

        let data = userauth(b"sid-d", &key, Some(&dest.blob()));
        let out = run(&sign_msg(&key, &data), &signer, &mut conn);
        assert_eq!(out[0], SSH_AGENT_SIGN_RESPONSE);
        let jobs = signer.jobs.lock().unwrap();
        assert_eq!(jobs[0].hops.len(), 2);
        assert!(jobs[0].hops[0].forwarded && !jobs[0].hops[1].forwarded);
    }

    #[test]
    fn requests_the_signer_would_refuse_never_reach_it() {
        let host = TestKey::new(4);
        let signer = FakeSigner::new(Behaviour::Sign);
        let key = signer.key.blob();
        let fail = vec![SSH_AGENT_FAILURE];

        // No binding at all (old client).
        let mut unbound = ConnState::default();
        let data = userauth(b"sid-ok", &key, Some(&host.blob()));
        assert_eq!(run(&sign_msg(&key, &data), &signer, &mut unbound), fail);

        // Only a forwarding binding: the session to sign for is unknown.
        let mut forwarded = ConnState::default();
        bind(&mut forwarded, &host, b"sid-fwd", true);
        let data = userauth(b"sid-fwd", &key, Some(&host.blob()));
        assert_eq!(run(&sign_msg(&key, &data), &signer, &mut forwarded), fail);

        let mut conn = ConnState::default();
        bind(&mut conn, &host, b"sid-ok", false);
        // Another session's challenge relayed through this connection.
        let data = userauth(b"sid-other", &key, Some(&host.blob()));
        assert_eq!(run(&sign_msg(&key, &data), &signer, &mut conn), fail);
        // A plain `publickey` login for the bound session: its bytes do
        // not name the server, so the binding proves nothing about it.
        let data = userauth(b"sid-ok", &key, None);
        assert_eq!(run(&sign_msg(&key, &data), &signer, &mut conn), fail);
        // Host-bound request naming another host key.
        let data = userauth(b"sid-ok", &key, Some(&TestKey::new(5).blob()));
        assert_eq!(run(&sign_msg(&key, &data), &signer, &mut conn), fail);
        // A request made with another client key than the one asked for.
        let data = userauth(b"sid-ok", &TestKey::new(6).blob(), Some(&host.blob()));
        assert_eq!(run(&sign_msg(&key, &data), &signer, &mut conn), fail);
        // Not a user-auth request (git commit signing).
        assert_eq!(
            run(&sign_msg(&key, b"SSHSIG\0\0\0\x01"), &signer, &mut conn),
            fail
        );
        // A key the signer does not offer.
        let other = TestKey::new(6).blob();
        let data = userauth(b"sid-ok", &other, Some(&host.blob()));
        assert_eq!(run(&sign_msg(&other, &data), &signer, &mut conn), fail);

        assert_eq!(signer.asked(), 0);
    }

    #[test]
    fn a_denial_becomes_an_agent_failure() {
        let host = TestKey::new(4);
        let signer = FakeSigner::new(Behaviour::Deny);
        let key = signer.key.blob();
        let mut conn = ConnState::default();
        bind(&mut conn, &host, b"sid-ok", false);
        let data = userauth(b"sid-ok", &key, Some(&host.blob()));
        assert_eq!(
            run(&sign_msg(&key, &data), &signer, &mut conn),
            vec![SSH_AGENT_FAILURE]
        );
        assert_eq!(signer.asked(), 1);
    }

    #[test]
    fn a_signature_that_does_not_verify_is_dropped() {
        let host = TestKey::new(4);
        let signer = FakeSigner::new(Behaviour::SignWithWrongKey);
        let key = signer.key.blob();
        let mut conn = ConnState::default();
        bind(&mut conn, &host, b"sid-ok", false);
        let data = userauth(b"sid-ok", &key, Some(&host.blob()));
        assert_eq!(
            run(&sign_msg(&key, &data), &signer, &mut conn),
            vec![SSH_AGENT_FAILURE]
        );
        assert_eq!(signer.asked(), 1);
    }

    /// testdata/hostbound.json, shared with web/test and the iOS tests:
    /// the agent passes on exactly the requests the signers accept, and
    /// refuses the others before anyone is asked.
    #[test]
    fn hostbound_vectors() {
        use base64::Engine as _;
        let unb64u = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(v.as_str().unwrap())
                .unwrap()
        };
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/hostbound.json")).unwrap();
        let key = unb64u(&v["key"]);

        struct VectorSigner {
            key: Vec<u8>,
            asked: Mutex<usize>,
        }
        impl Signer for VectorSigner {
            fn identities(&self) -> Vec<Identity> {
                vec![Identity {
                    key_blob: self.key.clone(),
                    comment: "phone".into(),
                }]
            }
            fn sign(&self, _job: SignJob) -> SignFuture {
                *self.asked.lock().unwrap() += 1;
                Box::pin(async { Err(SignError::Denied) })
            }
        }

        for case in v["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let signer = VectorSigner {
                key: key.clone(),
                asked: Mutex::new(0),
            };
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut conn = ConnState::default();
            for b in case["binds"].as_array().unwrap() {
                let msg = bind_msg(
                    &unb64u(&b["hostkey"]),
                    &unb64u(&b["sid"]),
                    &unb64u(&b["sig"]),
                    b["fwd"].as_bool().unwrap(),
                );
                let out = rt.block_on(process_message(&msg, &signer, None, &mut conn));
                assert_eq!(out, vec![SSH_AGENT_SUCCESS], "{name}: bind");
            }
            let data = unb64u(&case["data"]);
            let out = rt.block_on(process_message(
                &sign_msg(&key, &data),
                &signer,
                None,
                &mut conn,
            ));
            assert_eq!(out, vec![SSH_AGENT_FAILURE], "{name}");
            let ok = case["ok"].as_bool().unwrap();
            assert_eq!(*signer.asked.lock().unwrap(), usize::from(ok), "{name}");
            if ok {
                let dest = conn.bound_for_auth().unwrap();
                assert_eq!(
                    dest.fingerprint,
                    case["destination"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn process_labels_are_reduced_to_one_short_printable_line() {
        assert_eq!(sanitize_process_label("ssh\n"), Some("ssh".into()));
        assert_eq!(sanitize_process_label("a\x1b[31mb"), Some("a[31mb".into()));
        assert_eq!(sanitize_process_label(&"x".repeat(100)).unwrap().len(), 32);
        assert_eq!(sanitize_process_label(" \t\n"), None);
    }
}
