//! `piggy card init` (piggy#194) — the real-card driver for full-setup
//! provisioning. Selects a blank card, opens one PIN session, and runs the
//! binding-agnostic [`engine`] against it through the [`SessionCard`] adapter,
//! with the operator interaction routed to either the tty (default) or a
//! JSON-RPC frontend (RFC 0006 §6).
//!
//! The adapter holds `&mut PinSession` in this function's local scope, so the
//! single `begin_pin_session()` persists across every engine card-op (admin
//! auth and PIN verify are session state) without a self-referential struct.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::Path;

use openssl::rand::rand_bytes;

use piggy_piv::{PinSession, PivAlgorithm, PivContext, PivError, PivToken};

use crate::card::engine::{self, ProvisionCard, ProvisionConfig, ProvisionOutcome};
use crate::card::frontend::jsonrpc::JsonRpcFrontend;
use crate::card::frontend::tty::TtyFrontend;
use crate::card::protocol::Frontend;

/// Which interaction binding to use (RFC 0006 §6). `tty` is the interim default;
/// see piggy#197 for the eventual GUI-auto-launch default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FrontendKind {
    /// In-process terminal / askpass (default).
    Tty,
    /// JSON-RPC over an `AF_UNIX` socket (`--socket`); an external program
    /// (e.g. a charmbracelet TUI) drives the interactions.
    Jsonrpc,
}

/// Adapter wiring the engine's [`ProvisionCard`] seam to a live
/// [`PinSession`]. Each method delegates to the session; `serial` is captured
/// before the session opens (it lives on the token, which the session borrows).
struct SessionCard<'a, 'b> {
    session: &'a mut PinSession<'b>,
    serial: Option<u32>,
}

impl ProvisionCard for SessionCard<'_, '_> {
    fn serial(&self) -> Option<u32> {
        self.serial
    }
    fn authenticate_admin(&mut self, key: &[u8]) -> Result<(), PivError> {
        self.session
            .authenticate_admin(key, piggy_piv::apdu::alg::TDEA_3KEY)
    }
    fn verify_pin(&mut self, pin: &str) -> Result<(), PivError> {
        self.session.verify_pin(pin)
    }
    fn write_chuid(&mut self, guid: &[u8; 16]) -> Result<(), PivError> {
        self.session.write_chuid(guid)
    }
    fn generate_key(&mut self, slot: u8, alg: PivAlgorithm) -> Result<Vec<u8>, PivError> {
        // Card-default PIN/touch policy (no AA/AB tags), like pivy `piv_generate`.
        self.session.generate_key(slot, alg.to_byte(), None, None)
    }
    fn sign_prehash(&mut self, slot: u8, digest: &[u8]) -> Result<Vec<u8>, PivError> {
        self.session.sign_prehash(slot, digest)
    }
    fn put_cert(&mut self, slot: u8, cert_der: &[u8]) -> Result<(), PivError> {
        self.session.put_cert(slot, cert_der)
    }
    fn change_pin(&mut self, old: &str, new: &str) -> Result<(), PivError> {
        self.session.change_pin(old, new)
    }
    fn change_puk(&mut self, old: &str, new: &str) -> Result<(), PivError> {
        self.session.change_puk(old, new)
    }
    fn set_management_key_3des(&mut self, key: &[u8]) -> Result<(), PivError> {
        self.session.set_management_key_3des(key)
    }
}

/// Select the blank card to provision: by `--serial` if given, else the sole
/// uninitialized card. Errors clearly on none / ambiguity.
fn select_blank(tokens: Vec<PivToken>, serial: Option<u32>) -> Result<PivToken, String> {
    let mut blanks: Vec<PivToken> = tokens.into_iter().filter(|t| !t.is_initialized()).collect();
    match serial {
        Some(want) => blanks
            .into_iter()
            .find(|t| t.yk_serial() == Some(want))
            .ok_or_else(|| format!("no uninitialized PIV card with serial {want}")),
        None => match blanks.len() {
            0 => Err(
                "no uninitialized (factory-blank) PIV card found; insert one to provision".into(),
            ),
            1 => Ok(blanks.remove(0)),
            n => Err(format!(
                "{n} uninitialized cards present; choose one with --serial <N>"
            )),
        },
    }
}

/// Build the interaction frontend. For JSON-RPC the socket is connected here —
/// before any card operation — so `--frontend jsonrpc` without a usable channel
/// fails fast (RFC 0006 §6).
fn build_frontend(kind: FrontendKind, socket: Option<&Path>) -> Result<Box<dyn Frontend>, String> {
    match kind {
        FrontendKind::Tty => Ok(Box::new(TtyFrontend::new())),
        FrontendKind::Jsonrpc => {
            let path = socket.ok_or("--frontend jsonrpc requires --socket <PATH>")?;
            let stream = UnixStream::connect(path)
                .map_err(|e| format!("connect frontend socket {}: {e}", path.display()))?;
            let reader = BufReader::new(
                stream
                    .try_clone()
                    .map_err(|e| format!("clone socket handle: {e}"))?,
            );
            Ok(Box::new(JsonRpcFrontend::new(reader, stream, "card-init")))
        }
    }
}

fn run_inner(
    serial: Option<u32>,
    frontend: FrontendKind,
    socket: Option<&Path>,
) -> Result<ProvisionOutcome, String> {
    // Build the frontend first: a jsonrpc channel that can't be opened must
    // fail before we touch any card (RFC 0006 §6).
    let mut frontend = build_frontend(frontend, socket)?;

    let ctx = PivContext::new().map_err(|e| format!("PC/SC: {e}"))?;
    let tokens = ctx
        .enumerate_tokens_including_uninitialized()
        .map_err(|e| format!("enumerate cards: {e}"))?;
    let mut token = select_blank(tokens, serial)?;
    let card_serial = token.yk_serial();

    let mut session = token
        .begin_pin_session()
        .map_err(|e| format!("open card session: {e}"))?;
    let mut card = SessionCard {
        session: &mut session,
        serial: card_serial,
    };

    let mut guid = [0u8; 16];
    rand_bytes(&mut guid).map_err(|e| format!("generate GUID: {e}"))?;
    let cfg = ProvisionConfig { guid };

    engine::run(&mut card, frontend.as_mut(), &cfg).map_err(|e| e.to_string())
}

/// `piggy card init` entry point. Returns a process exit code.
pub fn run(serial: Option<u32>, frontend: FrontendKind, socket: Option<&Path>) -> i32 {
    match run_inner(serial, frontend, socket) {
        Ok(outcome) => {
            // stdout: the provisioned GUID (machine-readable; papi re-lists by
            // serial and ignores this, but a human/script can capture it).
            println!("{}", outcome.guid);
            if let Some(key) = &outcome.generated_mgmt_key {
                // The random mgmt key, displayed once. Never logged or sent over
                // a notification (RFC 0006 security); printed to stderr so it is
                // not mistaken for the GUID on stdout.
                eprintln!(
                    "New management key (record this — it is NOT recoverable): {}",
                    key.as_str()
                );
            }
            0
        }
        Err(e) => {
            eprintln!("piggy card init: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_frontend_without_socket_fails_fast() {
        // RFC 0006 §6: no usable channel → error before any card op. This
        // returns before touching PC/SC, so it is card-free.
        // `Box<dyn Frontend>` isn't Debug, so map the Ok away before unwrap_err.
        let err = build_frontend(FrontendKind::Jsonrpc, None)
            .map(|_| ())
            .unwrap_err();
        assert!(err.contains("--socket"), "got {err}");
    }
}
