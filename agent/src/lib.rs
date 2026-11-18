//! `clavix-agent` — an SSH agent that holds no private key.
//!
//! It speaks the standard agent protocol (draft-miller-ssh-agent) on a
//! Unix socket and hands every signature request to a [`proto::Signer`]
//! backend, which is expected to obtain the signature from a device the
//! user approves on. See `DESIGN.md` at the repository root.
//!
//! `proto` is the protocol core; `unix` knows how connections arrive and
//! how the caller is identified; `relay` is the signer backend that
//! reaches the paired device. The channel, the pairing, the relay client
//! and the state file come from `clavix-approve-core`, shared with Clavix
//! desktop.

pub use clavix_approve_core::{channel, state};

pub mod proto;
pub mod relay;
pub mod unix;

/// Pairing with a device (from `clavix-approve-core`), and the terminal
/// QR code of its link.
pub mod pairing {
    pub use clavix_approve_core::pairing::*;

    /// A QR code drawn with half-block characters, for a terminal. Drawn
    /// for a dark background (the usual case): the light modules are the
    /// inked ones.
    pub fn terminal_qr(text: &str) -> Option<String> {
        use qrcode::render::unicode::Dense1x2;
        let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
        Some(
            code.render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .quiet_zone(true)
                .build(),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_qr_code_fits_a_terminal() {
            let offer = Offer::new();
            let qr = terminal_qr(&pairing_url("https://approve.example", &offer.code)).unwrap();
            let lines: Vec<&str> = qr.lines().collect();
            // Small enough for an 80-column terminal, and rectangular.
            assert!(
                lines.len() >= 15 && lines.len() <= 30,
                "{} lines",
                lines.len()
            );
            let width = lines[0].chars().count();
            assert!(width <= 60 && lines.iter().all(|l| l.chars().count() == width));
        }
    }
}
