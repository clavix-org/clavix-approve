//! `clavix-agent` — an SSH agent that holds no private key.
//!
//! It speaks the standard agent protocol (draft-miller-ssh-agent) on a
//! Unix socket and hands every signature request to a [`proto::Signer`]
//! backend, which is expected to obtain the signature from a device the
//! user approves on. See `DESIGN.md` at the repository root.
//!
//! `proto` is the protocol core; `unix` knows how connections arrive and
//! how the caller is identified; `relay` is the signer backend that
//! reaches the paired device; `pairing` and `state` set that up.

pub mod channel;
pub mod pairing;
pub mod proto;
pub mod relay;
pub mod state;
pub mod unix;
