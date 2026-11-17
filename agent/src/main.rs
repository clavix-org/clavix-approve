//! Command line of the key-less agent.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clavix_agent::channel::{Identity, Peer};
use clavix_agent::pairing::{pairing_url, terminal_qr, Offer, PAIRING_WINDOW};
use clavix_agent::relay::{
    b64u, host_candidates, known_host_name, revoke, ssh_destination, unb64u, RelayClient,
    RelaySigner, DEFAULT_TIMEOUT,
};
use clavix_agent::state::{self, State};
use clavix_agent::unix::{process_args, start_agent};

const USAGE: &str = "\
clavix-agent — SSH agent without a key; signatures are approved on a paired device

Usage:
  clavix-agent pair --relay URL [--label NAME] [--yes]
      Pair with a device. Needs the relay's enrolment secret in the
      CLAVIX_ENROLL_SECRET environment variable. Prints a code to enter on
      the device, then verification digits to compare with the device's
      (--yes: do not ask), then the SSH public key to install on servers.
      A previous pairing is revoked once the new one is confirmed.
  clavix-agent run [--socket PATH] [--timeout SECONDS]
      Serve the agent protocol. Point SSH_AUTH_SOCK (or IdentityAgent) at
      the socket. Default timeout: 90 seconds per request.
  clavix-agent pubkey
      Print the paired device's SSH public key.
  clavix-agent unpair [--local-only]
      Revoke the pairing on the relay, then forget it here. The device can
      then no longer sign through this agent; its key still has to be
      removed from the servers' authorized_keys. --local-only: forget it
      here even when the relay cannot be reached.

State lives in $CLAVIX_AGENT_DIR, else $XDG_CONFIG_HOME/clavix-agent, else
~/.config/clavix-agent.";

/// `--name value` pairs; anything else is an error.
fn options(
    args: &[String],
    allowed: &[&str],
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut out = std::collections::HashMap::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let name = arg.strip_prefix("--").filter(|n| allowed.contains(n));
        let (Some(name), Some(value)) = (name, it.next()) else {
            return Err(format!("unexpected argument: {arg}"));
        };
        out.insert(name.to_string(), value.clone());
    }
    Ok(out)
}

fn state_dir() -> Result<PathBuf, String> {
    state::default_dir()
        .ok_or_else(|| "cannot locate a configuration directory (HOME is not set)".into())
}

fn load_state() -> Result<State, String> {
    let dir = state_dir()?;
    state::load(&dir).map_err(|e| {
        format!(
            "not paired yet ({}: {e}); run `clavix-agent pair`",
            dir.display()
        )
    })
}

fn default_label() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "agent".into())
}

fn default_socket() -> Result<PathBuf, String> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|d| !d.is_empty())
        .ok_or("XDG_RUNTIME_DIR is not set; pass --socket PATH")?;
    Ok(PathBuf::from(runtime).join("clavix-agent.sock"))
}

async fn pair(args: &[String]) -> Result<(), String> {
    // `--yes` skips the comparison of the verification digits.
    let yes = args.iter().any(|a| a == "--yes");
    let args: Vec<String> = args.iter().filter(|a| *a != "--yes").cloned().collect();
    let opts = options(&args, &["relay", "label"])?;
    let relay = opts.get("relay").ok_or("pair needs --relay URL")?;
    let label = opts.get("label").cloned().unwrap_or_else(default_label);
    let enroll = std::env::var("CLAVIX_ENROLL_SECRET")
        .map_err(|_| "set CLAVIX_ENROLL_SECRET to the relay's enrolment secret")?;
    let dir = state_dir()?;
    let client = RelayClient::new(relay)?;

    let offer = Offer::new();
    offer.open(&client, &enroll, &label).await?;
    println!(
        "Pairing code (valid 15 minutes, works once):\n\n    {}\n",
        offer.code
    );
    // The same code as a QR code, when the phone is not the screen this
    // is displayed on: its camera opens the approval page with the code.
    if let Some(qr) = terminal_qr(&pairing_url(relay, &offer.code)) {
        println!("Or scan this with the phone's camera, then follow the page:\n\n{qr}");
    }
    println!("Enter the code in the approval app. Waiting…");

    let paired = offer.wait_for_signer(&client, PAIRING_WINDOW).await?;
    println!(
        "A device answered. Verification digits:\n\n    {}\n",
        paired.fingerprint
    );
    if !yes && !confirmed("Does the device show the same digits? [y/N] ") {
        return Err("pairing abandoned; nothing was saved".into());
    }
    let (kem_private, sig_private) = offer.identity.secrets();
    let state = State {
        relay: relay.trim_end_matches('/').to_string(),
        ch: offer.ch.clone(),
        agent_token: offer.agent_token.clone(),
        label,
        kem_private: b64u(&kem_private),
        sig_private: b64u(&sig_private),
        signer: paired.signer,
    };
    // Read before it is replaced: the pairing this one supersedes.
    let previous = state::load(&dir).ok().filter(|old| old.ch != state.ch);
    state::save(&dir, &state).map_err(|e| format!("cannot save {}: {e}", dir.display()))?;
    println!(
        "Paired. Public key to install in authorized_keys:\n\n{}\n",
        state.signer.public_key
    );
    if let Some(old) = previous {
        revoke_previous(&old, &state.signer.public_key).await;
    }
    Ok(())
}

/// Best effort: a failure here leaves a dead channel on the old relay,
/// not a security problem, so it is reported and the pairing stands.
async fn revoke_previous(old: &State, new_key: &str) {
    let outcome = match RelayClient::new(&old.relay) {
        Ok(client) => revoke(&client, &old.ch, &old.agent_token)
            .await
            .map_err(|e| e.to_string()),
        Err(e) => Err(e),
    };
    match outcome {
        Ok(_) => println!("The previous pairing was revoked."),
        Err(e) => eprintln!("clavix-agent: could not revoke the previous pairing: {e}"),
    }
    // Same device paired again: same key, still in use.
    if same_key(&old.signer.public_key, new_key) {
        return;
    }
    {
        println!(
            "If the previous device's key is no longer needed, remove it from the servers:\n\n{}\n",
            old.signer.public_key
        );
    }
}

/// Two `authorized_keys` lines for the same key, whatever their comments.
fn same_key(a: &str, b: &str) -> bool {
    fn key(line: &str) -> Vec<&str> {
        line.split_whitespace().take(2).collect()
    }
    key(a) == key(b)
}

async fn unpair(args: &[String]) -> Result<(), String> {
    let local_only = match args {
        [] => false,
        [flag] if flag == "--local-only" => true,
        [other, ..] => return Err(format!("unexpected argument: {other}")),
    };
    let dir = state_dir()?;
    let state = load_state()?;
    if local_only {
        println!(
            "Not contacting the relay: the pairing stays there until revoked from the device."
        );
    } else {
        let client = RelayClient::new(&state.relay)?;
        match revoke(&client, &state.ch, &state.agent_token).await {
            Ok(true) => println!("Pairing revoked on the relay."),
            Ok(false) => println!("The relay no longer knew this pairing."),
            Err(e) => {
                return Err(format!(
                    "{e}; nothing was changed. Try again, or pass --local-only to forget \
                     the pairing here anyway"
                ))
            }
        }
    }
    state::remove(&dir)
        .map_err(|e| format!("cannot remove the state in {}: {e}", dir.display()))?;
    println!(
        "Pairing forgotten. The device's key still opens the servers it was installed on; \
         remove this line from their authorized_keys:\n\n{}\n",
        state.signer.public_key
    );
    Ok(())
}

/// Ask on the terminal; anything but "y" or "yes" is a no.
fn confirmed(question: &str) -> bool {
    use std::io::Write;
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).is_ok()
        && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// The channel keys recorded at pairing.
fn channel_keys(state: &State) -> Result<(Identity, Peer), String> {
    let field = |text: &str| unb64u(text).ok_or("the saved state is damaged; pair again");
    let me = Identity::from_secrets(&field(&state.kem_private)?, &field(&state.sig_private)?)?;
    let peer = Peer::new(
        &field(&state.signer.kem_public)?,
        &field(&state.signer.sig_public)?,
    )?;
    Ok((me, peer))
}

async fn run(args: &[String]) -> Result<(), String> {
    let opts = options(args, &["socket", "timeout"])?;
    let state = load_state()?;
    let socket = match opts.get("socket") {
        Some(path) => PathBuf::from(path),
        None => default_socket()?,
    };
    let timeout = match opts.get("timeout") {
        Some(s) => Duration::from_secs(
            s.parse::<u64>()
                .ok()
                .filter(|n| (10..=300).contains(n))
                .ok_or("--timeout must be between 10 and 300 seconds")?,
        ),
        None => DEFAULT_TIMEOUT,
    };

    let (me, peer) = channel_keys(&state)?;
    let known_hosts = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".ssh/known_hosts"));
    let signer = RelaySigner::new(
        RelayClient::new(&state.relay)?,
        &state.ch,
        &state.agent_token,
        &state.signer.id,
        &state.signer.public_key,
        &state.label,
        me,
        peer,
        timeout,
    )?
    // Read at each request: the file changes as the user accepts hosts.
    // Hashed entries are named from what the calling `ssh` was asked to
    // reach, when that hashes to the entry. Failing that (an alias from
    // ~/.ssh/config, a HostKeyAlias, another known_hosts file…), the
    // destination typed on the `ssh` command line, when it can only be
    // this host. Either way the device shows the name as unverified.
    .with_hints(move |key_blob, caller, sole_hop| {
        let args = caller.map(|c| process_args(c.pid)).unwrap_or_default();
        let content = known_hosts
            .as_ref()
            .and_then(|path| std::fs::read_to_string(path).ok());
        if let Some(name) = content
            .as_deref()
            .and_then(|c| known_host_name(c, key_blob, &host_candidates(&args)))
        {
            return Some(name);
        }
        let typed = if sole_hop {
            ssh_destination(&args)
        } else {
            None
        };
        if typed.is_none() {
            let why = if caller.is_none() {
                "caller unknown"
            } else if args.is_empty() {
                "caller's command line unreadable"
            } else if !sole_hop {
                "not in known_hosts, and reached through a forwarded agent"
            } else {
                "not in known_hosts, and the caller is not a plain ssh command"
            };
            eprintln!("[clavix-agent] no name suggested for a host key: {why}");
        }
        typed
    });

    let agent = start_agent(socket.clone(), Arc::new(signer))
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", socket.display()))?;
    eprintln!("[clavix-agent] listening on {}", socket.display());

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    agent.stop().await;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("pair") => pair(&args[1..]).await,
        Some("run") => run(&args[1..]).await,
        Some("pubkey") => load_state().map(|s| println!("{}", s.signer.public_key)),
        Some("unpair") => unpair(&args[1..]).await,
        Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("clavix-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
