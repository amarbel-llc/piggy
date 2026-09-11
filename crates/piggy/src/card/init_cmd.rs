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

use piggy_ids::Classification;
use piggy_markl::Id;
use piggy_piv::{Guid, PinSession, PivAlgorithm, PivContext, PivError, PivToken};

use crate::card::engine::{
    self, Escrow, ProvisionCard, ProvisionConfig, ProvisionError, ProvisionOutcome,
};
use crate::card::frontend::select::{FrontendKind, build_frontend};
use crate::card::protocol::{Frontend, ProgressEvent};
use crate::card::seal::{
    KeyEscrow, SealMode, SealRequest, check_escrow_recipients, default_pass_name,
};

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

/// How the operator chose which card to provision. Exactly one of the
/// mutually-exclusive `--serial`/`--guid`/`--reader` selectors, or `Auto` (no
/// selector — the sole eligible card is used). A serial-less card (e.g. an
/// older YubiKey 4 whose serial isn't exposed over the PIV channel) can never
/// match `Serial`, so `--guid`/`--reader` exist to target it (piggy#256).
#[derive(Debug)]
pub enum CardSelector {
    /// Match the YubiKey factory serial (`--serial`).
    Serial(u32),
    /// Match the card CHUID GUID (`--guid`). Factory-blank cards all share the
    /// all-zeros GUID, so `--guid` cannot disambiguate two blank cards — use
    /// `--reader` for those.
    Guid(Guid),
    /// Match the PC/SC reader name (`--reader`).
    Reader(String),
    /// No selector: use the sole eligible card, erroring on none / ambiguity.
    Auto,
}

impl CardSelector {
    /// Build the selector from the mutually-exclusive flags shared by the CLI
    /// (`piggy card init`) and the JSON-RPC `card.init` method. At most one of
    /// `serial`/`guid`/`reader` may be set; `guid` is parsed from hex. The CLI
    /// also enforces exclusivity via clap, so the conflict arm is defense in
    /// depth for the JSON-RPC path.
    pub fn from_flags(
        serial: Option<u32>,
        guid: Option<String>,
        reader: Option<String>,
    ) -> Result<Self, String> {
        match (serial, guid, reader) {
            (None, None, None) => Ok(Self::Auto),
            (Some(s), None, None) => Ok(Self::Serial(s)),
            (None, Some(g), None) => Guid::from_hex(g.trim())
                .map(Self::Guid)
                .map_err(|e| format!("invalid --guid {g:?}: {e}")),
            (None, None, Some(r)) => Ok(Self::Reader(r)),
            _ => Err("provide at most one of --serial, --guid, --reader".to_string()),
        }
    }
}

/// The subset of a [`PivToken`]'s identity used to select a provision target.
/// Extracted so the pure selection logic ([`choose_card_index`]) is unit
/// testable without a live card.
struct CardMeta {
    serial: Option<u32>,
    guid: Guid,
    reader: String,
    initialized: bool,
}

impl CardMeta {
    fn from_token(t: &PivToken) -> Self {
        Self {
            serial: t.yk_serial(),
            guid: t.guid().clone(),
            reader: t.reader_name().to_string(),
            initialized: t.is_initialized(),
        }
    }
}

/// Resolve a filtered candidate set to a single index, or a clear error. Zero
/// matches and ambiguity both carry the candidate listing so the operator can
/// pick the right selector.
fn resolve_match(
    matching: Vec<usize>,
    what: &str,
    noun: &str,
    candidates: &str,
) -> Result<usize, String> {
    match matching.len() {
        0 => Err(format!(
            "no {noun} matching {what}. candidates: {candidates}"
        )),
        1 => Ok(matching[0]),
        n => Err(format!(
            "{n} {noun}s match {what}; disambiguate with --reader <NAME>. candidates: {candidates}"
        )),
    }
}

/// Pure card-selection decision over card metadata: filter to eligible cards
/// (uninitialized only, unless `allow_reprovision`) then apply the selector.
/// Returns the chosen index into `metas`. Kept free of any live-card type so it
/// is exhaustively unit tested.
fn choose_card_index(
    metas: &[CardMeta],
    selector: &CardSelector,
    allow_reprovision: bool,
) -> Result<usize, String> {
    let noun = if allow_reprovision {
        "PIV card"
    } else {
        "uninitialized (factory-blank) PIV card"
    };
    let eligible: Vec<usize> = (0..metas.len())
        .filter(|&i| allow_reprovision || !metas[i].initialized)
        .collect();
    let candidates = if eligible.is_empty() {
        "none present".to_string()
    } else {
        eligible
            .iter()
            .map(|&i| format!("guid={} reader={}", metas[i].guid.to_hex(), metas[i].reader))
            .collect::<Vec<_>>()
            .join("; ")
    };
    match selector {
        CardSelector::Auto => match eligible.len() {
            0 => Err(format!("no {noun} found; insert one to provision")),
            1 => Ok(eligible[0]),
            n => Err(format!(
                "{n} candidate cards present; choose one with --serial <N>, --guid <HEX>, or --reader <NAME>. candidates: {candidates}"
            )),
        },
        CardSelector::Serial(want) => resolve_match(
            eligible
                .iter()
                .copied()
                .filter(|&i| metas[i].serial == Some(*want))
                .collect(),
            &format!("serial {want}"),
            noun,
            &candidates,
        ),
        CardSelector::Guid(want) => resolve_match(
            eligible
                .iter()
                .copied()
                .filter(|&i| &metas[i].guid == want)
                .collect(),
            &format!("guid {}", want.to_hex()),
            noun,
            &candidates,
        ),
        CardSelector::Reader(want) => resolve_match(
            eligible
                .iter()
                .copied()
                .filter(|&i| &metas[i].reader == want)
                .collect(),
            &format!("reader {want:?}"),
            noun,
            &candidates,
        ),
    }
}

/// Select the card to provision per the [`CardSelector`], else the sole
/// eligible card. Errors clearly on none / ambiguity, listing candidates.
///
/// Without `allow_reprovision`, only an uninitialized (factory-blank) card is
/// eligible — the default `card init`. With `allow_reprovision` (piggy#204) an
/// already-initialized card-in-hand is eligible too, so `card init
/// --allow-reprovision` can re-provision it. A card whose credentials have been
/// rotated off the factory defaults still fails later at admin-auth (the
/// creds-lost path is out of scope — papi revocation), so accepting it here
/// only broadens *selection*, not the trust model.
fn select_card_for_provision(
    tokens: Vec<PivToken>,
    selector: &CardSelector,
    allow_reprovision: bool,
) -> Result<PivToken, String> {
    let metas: Vec<CardMeta> = tokens.iter().map(CardMeta::from_token).collect();
    let idx = choose_card_index(&metas, selector, allow_reprovision)?;
    Ok(tokens.into_iter().nth(idx).unwrap())
}

/// Provision a blank card through an already-built frontend, returning the
/// structured [`ProvisionOutcome`] (or a [`ProvisionError`] preserving the
/// decline-vs-failure distinction). This is the binding-agnostic entry the
/// `piggy manage` `card.init` method (piggy#201) calls with a JSON-RPC
/// frontend bound to the live connection; the CLI ([`run`]) reaches it via
/// [`run_inner`] with a tty/socket frontend. Selecting the blank card, opening
/// the one PIN session, and minting the GUID happen here; the
/// [`SessionCard`] adapter then holds the live session for the engine.
///
/// `seal` decides whether the generated management key is escrowed
/// (piggy#258). The escrow is prepared here, before the card is touched, so a
/// [`SealMode::Always`] whose target can't take the key fails without writing
/// anything.
pub fn provision_with_frontend(
    selector: CardSelector,
    allow_reprovision: bool,
    seal: SealRequest<'_>,
    frontend: &mut dyn Frontend,
) -> Result<ProvisionOutcome, ProvisionError> {
    let ctx = PivContext::new().map_err(|e| ProvisionError::Setup(format!("PC/SC: {e}")))?;
    let tokens = ctx
        .enumerate_tokens_including_uninitialized()
        .map_err(|e| ProvisionError::Setup(format!("enumerate cards: {e}")))?;
    let mut token = select_card_for_provision(tokens, &selector, allow_reprovision)
        .map_err(ProvisionError::Setup)?;
    let card_serial = token.yk_serial();
    // Reprovision iff the selected card is already initialized — so the engine's
    // confirm escalates (it is about to destroy real keys), even on a blank card
    // passed with --allow-reprovision (which is just a normal init).
    let reprovision = token.is_initialized();

    let mut guid = [0u8; 16];
    rand_bytes(&mut guid).map_err(|e| ProvisionError::Setup(format!("generate GUID: {e}")))?;

    let mut escrow = prepare_escrow(&seal, &hex::encode_upper(guid), frontend, || {
        if reprovision {
            current_9d_recipient(&token)
        } else {
            None
        }
    })?;

    let mut session = token
        .begin_pin_session()
        .map_err(|e| ProvisionError::Setup(format!("open card session: {e}")))?;
    let mut card = SessionCard {
        session: &mut session,
        serial: card_serial,
    };

    let cfg = ProvisionConfig { guid, reprovision };
    let escrow = escrow.as_mut().map(|sink| Escrow {
        sink: sink.as_mut(),
        ask: seal.mode == SealMode::Offer,
    });
    engine::run(&mut card, frontend, &cfg, escrow)
}

/// The markl-id of `token`'s current 9D key — the recipient a reprovision
/// destroys. `None` when the slot is empty or unreadable.
fn current_9d_recipient(token: &PivToken) -> Option<Id> {
    let slot = token.read_slot(0x9D).ok()?;
    match piggy_ids::classify_slot_9d(
        token.guid().clone(),
        token.reader_name().to_string(),
        token.yk_serial(),
        slot.algorithm(),
        slot.cert_der(),
    ) {
        Classification::Supported { id, .. } => Some(id),
        _ => None,
    }
}

/// Resolve and guard the escrow `seal` asks for. An `Always` seal that can't be
/// prepared is a setup error; an `Offer` that can't be prepared is dropped, and
/// the key is displayed as before. `destroyed_9d` yields the recipient a
/// reprovision destroys; it is only read once a store has produced recipients.
fn prepare_escrow(
    seal: &SealRequest<'_>,
    guid_hex: &str,
    fe: &mut dyn Frontend,
    destroyed_9d: impl FnOnce() -> Option<Id>,
) -> Result<Option<Box<dyn KeyEscrow>>, ProvisionError> {
    let (pass_name, required) = match &seal.mode {
        SealMode::Never => return Ok(None),
        SealMode::Offer => (default_pass_name(guid_hex), false),
        SealMode::Always(pass_name) => (
            pass_name
                .clone()
                .unwrap_or_else(|| default_pass_name(guid_hex)),
            true,
        ),
    };
    let prepared = seal.sealer.prepare(&pass_name).and_then(|escrow| {
        let warning = check_escrow_recipients(escrow.recipients(), destroyed_9d().as_ref())?;
        Ok((escrow, warning))
    });
    match prepared {
        Ok((escrow, warning)) => {
            if let Some(message) = warning {
                fe.progress(ProgressEvent {
                    step: "seal-warning".into(),
                    message,
                    current: None,
                    total: None,
                });
            }
            Ok(Some(escrow))
        }
        Err(_) if !required => Ok(None),
        Err(e) => Err(ProvisionError::Setup(format!(
            "cannot seal the management key to {pass_name}: {e}"
        ))),
    }
}

fn run_inner(
    serial: Option<u32>,
    guid: Option<String>,
    reader: Option<String>,
    allow_reprovision: bool,
    seal: SealRequest<'_>,
    frontend: FrontendKind,
    socket: Option<&Path>,
) -> Result<ProvisionOutcome, String> {
    // Resolve the card selector before touching any card (a bad --guid is a
    // usage error, not a card-op failure).
    let selector = CardSelector::from_flags(serial, guid, reader)?;
    // Build the frontend first: a jsonrpc channel that can't be opened must
    // fail before we touch any card (RFC 0006 §6).
    let mut frontend = build_frontend(frontend, socket, "card init")?;
    provision_with_frontend(selector, allow_reprovision, seal, frontend.as_mut())
        .map_err(|e| e.to_string())
}

/// `piggy card init` entry point. Returns a process exit code.
pub fn run(
    serial: Option<u32>,
    guid: Option<String>,
    reader: Option<String>,
    allow_reprovision: bool,
    seal: SealRequest<'_>,
    frontend: FrontendKind,
    socket: Option<&Path>,
) -> i32 {
    match run_inner(
        serial,
        guid,
        reader,
        allow_reprovision,
        seal,
        frontend,
        socket,
    ) {
        Ok(outcome) => {
            // stdout: the provisioned GUID (machine-readable; papi re-lists by
            // serial and ignores this, but a human/script can capture it).
            println!("{}", outcome.guid);
            if let Some(sealed) = &outcome.sealed_mgmt_key {
                eprintln!(
                    "Management key sealed to {} in the password store ({} recipient{}).",
                    sealed.pass_name,
                    sealed.recipients,
                    if sealed.recipients == 1 { "" } else { "s" }
                );
            }
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

    const BLANK: &str = "00000000000000000000000000000000";
    const GUID_A: &str = "0102030405060708090a0b0c0d0e0f10";
    const GUID_B: &str = "1112131415161718191a1b1c1d1e1f20";

    fn meta(serial: Option<u32>, guid_hex: &str, reader: &str, initialized: bool) -> CardMeta {
        CardMeta {
            serial,
            guid: Guid::from_hex(guid_hex).expect("valid guid hex"),
            reader: reader.to_string(),
            initialized,
        }
    }

    // --- CardSelector::from_flags ---

    #[test]
    fn from_flags_none_is_auto() {
        assert!(matches!(
            CardSelector::from_flags(None, None, None),
            Ok(CardSelector::Auto)
        ));
    }

    #[test]
    fn from_flags_serial() {
        assert!(matches!(
            CardSelector::from_flags(Some(42), None, None),
            Ok(CardSelector::Serial(42))
        ));
    }

    #[test]
    fn from_flags_guid_parses_hex() {
        match CardSelector::from_flags(None, Some(GUID_A.to_string()), None) {
            Ok(CardSelector::Guid(g)) => assert_eq!(g.to_hex(), GUID_A.to_uppercase()),
            other => panic!("expected Guid, got {other:?}"),
        }
    }

    #[test]
    fn from_flags_reader() {
        match CardSelector::from_flags(None, None, Some("R 01 00".to_string())) {
            Ok(CardSelector::Reader(r)) => assert_eq!(r, "R 01 00"),
            other => panic!("expected Reader, got {other:?}"),
        }
    }

    #[test]
    fn from_flags_conflict_errors() {
        let e = CardSelector::from_flags(Some(1), Some(GUID_A.to_string()), None).unwrap_err();
        assert!(e.contains("at most one"), "{e}");
    }

    #[test]
    fn from_flags_bad_guid_errors() {
        let e = CardSelector::from_flags(None, Some("nothex!!".to_string()), None).unwrap_err();
        assert!(e.contains("invalid --guid"), "{e}");
    }

    // --- choose_card_index ---

    #[test]
    fn auto_single_blank_ok() {
        let metas = vec![meta(None, BLANK, "Reader 00 00", false)];
        assert_eq!(
            choose_card_index(&metas, &CardSelector::Auto, false).unwrap(),
            0
        );
    }

    #[test]
    fn auto_none_errors() {
        let metas: Vec<CardMeta> = vec![];
        let e = choose_card_index(&metas, &CardSelector::Auto, false).unwrap_err();
        assert!(e.contains("no uninitialized"), "{e}");
    }

    #[test]
    fn auto_multiple_errors_with_hint() {
        let metas = vec![
            meta(None, BLANK, "R0 00 00", false),
            meta(None, BLANK, "R1 00 00", false),
        ];
        let e = choose_card_index(&metas, &CardSelector::Auto, false).unwrap_err();
        assert!(e.contains("candidate cards present"), "{e}");
        assert!(e.contains("--reader"), "{e}");
    }

    #[test]
    fn serial_matches() {
        let metas = vec![
            meta(Some(111), GUID_A, "R0", false),
            meta(Some(222), GUID_B, "R1", false),
        ];
        assert_eq!(
            choose_card_index(&metas, &CardSelector::Serial(222), false).unwrap(),
            1
        );
    }

    #[test]
    fn serial_miss_errors_lists_candidates() {
        let metas = vec![meta(Some(111), GUID_A, "R0", false)];
        let e = choose_card_index(&metas, &CardSelector::Serial(999), false).unwrap_err();
        assert!(e.contains("serial 999"), "{e}");
        assert!(e.contains("candidates:"), "{e}");
    }

    #[test]
    fn guid_matches_among_initialized() {
        let metas = vec![
            meta(None, GUID_A, "R0", true),
            meta(None, GUID_B, "R1", true),
        ];
        let sel = CardSelector::Guid(Guid::from_hex(GUID_B).unwrap());
        // allow_reprovision=true so initialized cards are eligible.
        assert_eq!(choose_card_index(&metas, &sel, true).unwrap(), 1);
    }

    #[test]
    fn reader_matches() {
        let metas = vec![
            meta(None, BLANK, "Yubico 00 00", false),
            meta(None, BLANK, "Yubico 01 00", false),
        ];
        let sel = CardSelector::Reader("Yubico 01 00".to_string());
        assert_eq!(choose_card_index(&metas, &sel, false).unwrap(), 1);
    }

    #[test]
    fn guid_ambiguous_blanks_errors() {
        // Two factory-blank cards share the all-zeros GUID — --guid can't pick.
        let metas = vec![
            meta(None, BLANK, "R0", false),
            meta(None, BLANK, "R1", false),
        ];
        let sel = CardSelector::Guid(Guid::from_hex(BLANK).unwrap());
        let e = choose_card_index(&metas, &sel, false).unwrap_err();
        assert!(e.contains("match"), "{e}");
        assert!(e.contains("--reader"), "{e}");
    }

    #[test]
    fn reprovision_filter_excludes_initialized_by_default() {
        let metas = vec![meta(Some(1), GUID_A, "R0", true)]; // initialized
        // Default (allow_reprovision=false): the initialized card is NOT eligible.
        let e = choose_card_index(&metas, &CardSelector::Serial(1), false).unwrap_err();
        assert!(e.contains("candidates: none present"), "{e}");
        // With allow_reprovision it becomes selectable.
        assert_eq!(
            choose_card_index(&metas, &CardSelector::Serial(1), true).unwrap(),
            0
        );
    }
}
