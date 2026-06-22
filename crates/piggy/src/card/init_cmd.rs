//! `piggy card init` (piggy#194) — the real-card driver for full-setup
//! provisioning. Selects a blank card, opens one PIN session, and runs the
//! binding-agnostic [`engine`] against it through the [`SessionCard`] adapter,
//! with the operator interaction routed to either the tty (default) or a
//! JSON-RPC frontend (RFC 0006 §6).
//!
//! The adapter holds `&mut PinSession` in this function's local scope, so the
//! single `begin_pin_session()` persists across every engine card-op (admin
//! auth and PIN verify are session state) without a self-referential struct.

use std::path::Path;

use openssl::rand::rand_bytes;

use piggy_piv::{PinSession, PivAlgorithm, PivContext, PivError, PivToken};

use crate::card::engine::{self, ProvisionCard, ProvisionConfig, ProvisionError, ProvisionOutcome};
use crate::card::frontend::select::{FrontendKind, build_frontend};
use crate::card::protocol::Frontend;

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
    fn sign_prehash(
        &mut self,
        slot: u8,
        alg: PivAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, PivError> {
        // The cert is signed before it is written, so the algorithm comes from
        // the engine (which just generated the key) rather than a cert read.
        self.session
            .sign_prehash_with_alg(slot, alg.to_byte(), digest)
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

/// Provision a blank card through an already-built frontend, returning the
/// structured [`ProvisionOutcome`] (or a [`ProvisionError`] preserving the
/// decline-vs-failure distinction). This is the binding-agnostic entry the
/// `piggy manage` `card.init` method (piggy#201) calls with a JSON-RPC
/// frontend bound to the live connection; the CLI ([`run`]) reaches it via
/// [`run_inner`] with a tty/socket frontend. Selecting the blank card, opening
/// the one PIN session, and minting the GUID happen here; the
/// [`SessionCard`] adapter then holds the live session for the engine.
pub fn provision_with_frontend(
    serial: Option<u32>,
    frontend: &mut dyn Frontend,
) -> Result<ProvisionOutcome, ProvisionError> {
    let ctx = PivContext::new().map_err(|e| ProvisionError::Setup(format!("PC/SC: {e}")))?;
    let tokens = ctx
        .enumerate_tokens_including_uninitialized()
        .map_err(|e| ProvisionError::Setup(format!("enumerate cards: {e}")))?;
    let mut token = select_blank(tokens, serial).map_err(ProvisionError::Setup)?;
    let card_serial = token.yk_serial();

    let mut session = token
        .begin_pin_session()
        .map_err(|e| ProvisionError::Setup(format!("open card session: {e}")))?;
    let mut card = SessionCard {
        session: &mut session,
        serial: card_serial,
    };

    let mut guid = [0u8; 16];
    rand_bytes(&mut guid).map_err(|e| ProvisionError::Setup(format!("generate GUID: {e}")))?;
    let cfg = ProvisionConfig { guid };

    engine::run(&mut card, frontend, &cfg)
}

fn run_inner(
    serial: Option<u32>,
    frontend: FrontendKind,
    socket: Option<&Path>,
) -> Result<ProvisionOutcome, String> {
    // Build the frontend first: a jsonrpc channel that can't be opened must
    // fail before we touch any card (RFC 0006 §6).
    let mut frontend = build_frontend(frontend, socket, "card init")?;
    provision_with_frontend(serial, frontend.as_mut()).map_err(|e| e.to_string())
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
