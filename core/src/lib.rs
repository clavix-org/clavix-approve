//! `clavix-approve-core` — the Clavix Approve protocol, shared by the
//! key-less agent (`clavix-agent`, sign mode) and Clavix desktop (approve
//! mode, and sign mode while its vault is locked). See `PROTOCOL.md` at the
//! repository root.
//!
//! - [`channel`]: the end-to-end sealed channel (HPKE + Ed25519);
//! - [`pairing`]: one-time pairing with a device, in either mode;
//! - [`relay`]: HTTP access to the relay;
//! - [`requester`]: approve mode, the requester's side (what Clavix
//!   desktop uses: pair phones, ask them to approve, verify the proof);
//! - [`sign_requester`]: sign mode, the requester's side (what the agent
//!   uses, and Clavix desktop while its vault is locked: have the device
//!   holding the key sign);
//! - [`state`]: the agent's state file;
//! - [`bytes`]: base64url, hex and SSH string encodings.
//!
//! No private SSH key is ever handled here.

pub mod bytes;
pub mod channel;
pub mod pairing;
pub mod relay;
pub mod requester;
pub mod sign_requester;
pub mod state;
