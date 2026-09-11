//! The provisioning engine (piggy#194): orchestrates `piggy card init`
//! full-setup against a card and a `&mut dyn Frontend`, binding-agnostic
//! (RFC 0006). It owns the *sequence* — admin-auth, write CHUID, generate the
//! 9D (key-management/ECDH) and 9A (PIV-auth) keys, build + card-sign + write
//! their self-signed certs, change the PIN, change the PUK, and rotate the
//! management key — issuing every human interaction through the frontend so the
//! same flow runs under the tty or a remote TUI.
//!
//! The card-write surface is the [`ProvisionCard`] trait, so the orchestration
//! is unit-testable against a mock card without hardware. The real
//! `PinSession`-backed implementation and the fibby end-to-end land with the
//! `piggy card init` command (Phase 4).
//!
//! Management-key policy: the engine rotates per whatever [`MgmtKeyChoice`] the
//! frontend returns (the mechanism). The tty default returns
//! [`MgmtKeyChoice::Random`]; the engine then generates the key and either
//! seals it into an [`Escrow`] (piggy#258) or returns it in
//! [`ProvisionOutcome::generated_mgmt_key`] for the command to display once —
//! the key never crosses a `progress`/`completed` notification (RFC 0006
//! security). An escrowed key is sealed *before* it is set on the card and
//! removed again if the card rejects it, so a key is never applied without its
//! escrow. PIN-protected on-card storage is piggy#198.

use openssl::rand::rand_bytes;
use zeroize::Zeroizing;

use piggy_piv::{PivAlgorithm, PivError};

use crate::card::protocol::{
    CardId, CompletedEvent, CompletedStatus, ConfirmRequest, Frontend, FrontendError,
    MgmtKeyChoice, MgmtKeyRequest, ProgressEvent, SecretKind, SecretRequest,
};
use crate::card::seal::KeyEscrow;

/// PIV factory-default application PIN (`123456`). A factory-blank card carries
/// this; full-setup verifies it (so the card can sign its own certs) and then
/// changes it to the operator's new PIN.
const DEFAULT_PIN: &str = "123456";

/// PIV factory-default PUK (`12345678`).
const DEFAULT_PUK: &str = "12345678";

/// The slots full-setup provisions: 9D (key management / ECDH — piggy's
/// decrypt recipient) and 9A (PIV authentication — the SSH-auth key).
const SLOT_KEY_MGMT: u8 = 0x9D;
const SLOT_PIV_AUTH: u8 = 0x9A;

/// The card-write surface the engine drives. A trait so the engine's
/// orchestration is unit-testable against a mock; the real implementation
/// (Phase 4) wraps a piggy-piv `PivToken`/`PinSession`, holding one open
/// session for the engine's lifetime so the admin-auth and PIN-verify state
/// persists across calls.
pub trait ProvisionCard {
    /// The card's YubiKey serial, for naming it in prompts (RFC 0006 §2.1).
    fn serial(&self) -> Option<u32>;
    /// Authenticate the management key (enables generate / put-data).
    fn authenticate_admin(&mut self, key: &[u8]) -> Result<(), PivError>;
    /// Verify the PIV PIN (enables the card to sign its self-signed certs).
    fn verify_pin(&mut self, pin: &str) -> Result<(), PivError>;
    /// Write the CHUID with the given 16-byte GUID (marks the card initialized).
    fn write_chuid(&mut self, guid: &[u8; 16]) -> Result<(), PivError>;
    /// Generate a key pair in `slot`; returns the uncompressed public point
    /// (`04 ‖ X ‖ Y`).
    fn generate_key(&mut self, slot: u8, alg: PivAlgorithm) -> Result<Vec<u8>, PivError>;
    /// Sign a prehash with `slot`'s key using the given algorithm; returns a
    /// DER ECDSA signature (used to self-sign the slot's cert). `alg` is passed
    /// explicitly because here the key exists but its cert does not yet — so
    /// the card layer cannot read the algorithm back from a cert.
    fn sign_prehash(
        &mut self,
        slot: u8,
        alg: PivAlgorithm,
        digest: &[u8],
    ) -> Result<Vec<u8>, PivError>;
    /// Write a slot's X.509 cert object.
    fn put_cert(&mut self, slot: u8, cert_der: &[u8]) -> Result<(), PivError>;
    /// Change the PIV PIN.
    fn change_pin(&mut self, old: &str, new: &str) -> Result<(), PivError>;
    /// Change the PUK.
    fn change_puk(&mut self, old: &str, new: &str) -> Result<(), PivError>;
    /// Rotate the 24-byte 3DES management key.
    fn set_management_key_3des(&mut self, key: &[u8]) -> Result<(), PivError>;
}

/// Engine configuration. Minimal for now; the CN convention
/// (`piv-key-mgmt@<guid8>` / `piv-auth@<guid8>`) is derived from the generated
/// GUID.
#[derive(Debug, Clone)]
pub struct ProvisionConfig {
    /// 16-byte GUID to write into the CHUID (random in production; pinned by
    /// tests for determinism).
    pub guid: [u8; 16],
    /// True when the selected card is already initialized and is being
    /// re-provisioned (piggy#204 `--allow-reprovision`). Only escalates the
    /// confirmation wording — the engine flow is identical (a blank card and a
    /// factory-cred reprovision both run admin-auth with the default key).
    pub reprovision: bool,
}

/// A management-key escrow the engine seals a generated key into (piggy#258).
pub struct Escrow<'a> {
    pub sink: &'a mut dyn KeyEscrow,
    /// Ask the operator through the frontend before sealing, rather than
    /// sealing unconditionally.
    pub ask: bool,
}

/// Where a generated management key was sealed instead of being displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedKey {
    pub pass_name: String,
    pub recipients: usize,
}

/// What a successful provision produced.
#[derive(Debug)]
pub struct ProvisionOutcome {
    /// The provisioned card's GUID, uppercase hex.
    pub guid: String,
    /// The newly-generated random management key (hex), present **only** when
    /// the frontend chose [`MgmtKeyChoice::Random`] and the key was not
    /// sealed. The caller displays it once; it is never logged or sent over a
    /// notification.
    pub generated_mgmt_key: Option<Zeroizing<String>>,
    /// Where the generated management key was sealed, when it was.
    pub sealed_mgmt_key: Option<SealedKey>,
}

/// Why a provision failed.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// A pre-engine setup failure (no/ambiguous blank card, PC/SC enumeration,
    /// opening the card session, RNG). Distinct from [`ProvisionError::Card`]
    /// (an on-card APDU failure during the run) so callers can render it
    /// plainly; not a declined interaction.
    #[error("{0}")]
    Setup(String),
    #[error("card error: {0}")]
    Card(#[from] PivError),
    #[error("frontend error: {0}")]
    Frontend(#[from] FrontendError),
    #[error("operator aborted: {0}")]
    Aborted(String),
    #[error("the two PIN entries did not match")]
    PinMismatch,
    #[error("the two PUK entries did not match")]
    PukMismatch,
    #[error("supplied management key is not valid 24-byte hex: {0}")]
    BadMgmtKey(String),
    /// Sealing the generated management key failed; the card's management key
    /// was left unrotated.
    #[error("sealing the management key failed (the card's management key was not rotated): {0}")]
    Seal(String),
}

/// The CN for a slot's self-signed cert: `<prefix>@<first-8-hex-of-guid>`.
fn slot_cn(prefix: &str, guid_hex: &str) -> String {
    let short: String = guid_hex.chars().take(8).collect();
    format!("{prefix}@{short}")
}

/// Provision a single slot: generate the key, build + card-sign + write its
/// self-signed cert. Factored out so the cert-signing closure's mutable borrow
/// of `card` is cleanly scoped.
fn provision_slot(card: &mut dyn ProvisionCard, slot: u8, cn: &str) -> Result<(), ProvisionError> {
    let point = card.generate_key(slot, PivAlgorithm::EcP256)?;
    let cert = piggy_piv::cert_builder::build_self_signed_cert(
        &point,
        PivAlgorithm::EcP256,
        cn,
        |digest| card.sign_prehash(slot, PivAlgorithm::EcP256, digest),
    )?;
    card.put_cert(slot, &cert)?;
    Ok(())
}

/// Run full-setup provisioning. On success the card has a fresh CHUID, 9D + 9A
/// keys with self-signed certs, a new PIN/PUK, and (per the frontend's choice)
/// a rotated management key. On any failure a `completed{status:error}`
/// notification is emitted before the error is returned.
pub fn run(
    card: &mut dyn ProvisionCard,
    fe: &mut dyn Frontend,
    cfg: &ProvisionConfig,
    escrow: Option<Escrow<'_>>,
) -> Result<ProvisionOutcome, ProvisionError> {
    let result = run_inner(card, fe, cfg, escrow);
    match &result {
        Ok(outcome) => {
            let mut summary = serde_json::json!({ "guid": outcome.guid });
            if let Some(sealed) = &outcome.sealed_mgmt_key {
                summary["sealed_management_key"] = sealed.pass_name.clone().into();
            }
            fe.completed(CompletedEvent {
                status: CompletedStatus::Ok,
                summary: Some(summary),
                error: None,
            })
        }
        Err(e) => fe.completed(CompletedEvent {
            status: CompletedStatus::Error,
            summary: None,
            error: Some(e.to_string()),
        }),
    }
    result
}

fn run_inner(
    card: &mut dyn ProvisionCard,
    fe: &mut dyn Frontend,
    cfg: &ProvisionConfig,
    escrow: Option<Escrow<'_>>,
) -> Result<ProvisionOutcome, ProvisionError> {
    let guid_hex = hex::encode_upper(cfg.guid);
    let card_id = CardId {
        guid: guid_hex.clone(),
        serial: card.serial(),
        cn: None,
    };

    // Confirm before touching the card — this overwrites slots 9A and 9D.
    // Reprovisioning an already-initialized card is more destructive (it
    // replaces keys/certs that are in use), so escalate the wording.
    let message = if cfg.reprovision {
        format!(
            "Card {} is ALREADY PROVISIONED — reprovisioning DESTROYS its existing 9A + 9D keys and overwrites their certs (and resets PIN/PUK/management key). Proceed?",
            card_id.short_label()
        )
    } else {
        format!(
            "Provision card {} — this generates new 9A + 9D keys and overwrites their certs. Proceed?",
            card_id.short_label()
        )
    };
    let proceed = fe.confirm(ConfirmRequest {
        message,
        default: Some(false),
    })?;
    if !proceed {
        return Err(ProvisionError::Aborted("declined at confirmation".into()));
    }

    let total = 6;
    let step = |fe: &mut dyn Frontend, n: u32, token: &str, msg: &str| {
        fe.progress(ProgressEvent {
            step: token.into(),
            message: msg.into(),
            current: Some(n),
            total: Some(total),
        });
    };

    // 1. Admin-auth with the factory mgmt key; verify the factory PIN so the
    //    card can sign its own certs.
    step(fe, 1, "admin-auth", "Authenticating management key");
    card.authenticate_admin(&piggy_piv::DEFAULT_ADMIN_KEY)?;
    card.verify_pin(DEFAULT_PIN)?;

    // 2. CHUID — marks the card initialized with a stable GUID.
    step(fe, 2, "write-chuid", "Writing CHUID");
    card.write_chuid(&cfg.guid)?;

    // 3. Slot 9D (key management / ECDH).
    step(fe, 3, "generate-9d", "Generating key-management key (9D)");
    provision_slot(card, SLOT_KEY_MGMT, &slot_cn("piv-key-mgmt", &guid_hex))?;

    // 4. Slot 9A (PIV authentication).
    step(fe, 4, "generate-9a", "Generating authentication key (9A)");
    provision_slot(card, SLOT_PIV_AUTH, &slot_cn("piv-auth", &guid_hex))?;

    // 5. Change PIN + PUK off their factory defaults.
    step(fe, 5, "change-secrets", "Setting new PIN and PUK");
    let new_pin = collect_new_secret(
        fe,
        &card_id,
        SecretKind::NewPin,
        SecretKind::ConfirmNewPin,
        "Choose a new PIN",
        ProvisionError::PinMismatch,
    )?;
    card.change_pin(DEFAULT_PIN, &new_pin)?;
    let new_puk = collect_new_secret(
        fe,
        &card_id,
        SecretKind::NewPuk,
        SecretKind::ConfirmNewPuk,
        "Choose a new PUK",
        ProvisionError::PukMismatch,
    )?;
    card.change_puk(DEFAULT_PUK, &new_puk)?;

    // 6. Rotate the management key per the frontend's choice.
    step(fe, 6, "rotate-mgmt-key", "Rotating management key");
    let (generated_mgmt_key, sealed_mgmt_key) = rotate_mgmt_key(card, fe, &card_id, escrow)?;

    Ok(ProvisionOutcome {
        guid: guid_hex,
        generated_mgmt_key,
        sealed_mgmt_key,
    })
}

/// Prompt for a new secret twice and require the entries to match.
fn collect_new_secret(
    fe: &mut dyn Frontend,
    card: &CardId,
    enter: SecretKind,
    confirm: SecretKind,
    prompt: &str,
    mismatch: ProvisionError,
) -> Result<Zeroizing<String>, ProvisionError> {
    let first = fe.request_secret(SecretRequest {
        kind: enter,
        prompt: prompt.into(),
        card: Some(card.clone()),
        slot: None,
        attempts_remaining: None,
        detail: None,
    })?;
    let second = fe.request_secret(SecretRequest {
        kind: confirm,
        prompt: "Re-enter to confirm".into(),
        card: Some(card.clone()),
        slot: None,
        attempts_remaining: None,
        detail: None,
    })?;
    if first.as_str() != second.as_str() {
        return Err(mismatch);
    }
    Ok(first)
}

/// Resolve the frontend's management-key choice into an applied rotation.
/// Returns the generated key (hex) for a `Random` key that was not sealed, or
/// where it was sealed. `Default`/`Hex` keys are never sealed: the operator
/// already knows them.
fn rotate_mgmt_key(
    card: &mut dyn ProvisionCard,
    fe: &mut dyn Frontend,
    card_id: &CardId,
    escrow: Option<Escrow<'_>>,
) -> Result<(Option<Zeroizing<String>>, Option<SealedKey>), ProvisionError> {
    let choice = fe.request_mgmt_key(MgmtKeyRequest {
        prompt: "Management key for the card".into(),
        card: card_id.clone(),
    })?;
    match choice {
        MgmtKeyChoice::Default => {
            note_unsealed(fe, escrow.as_ref());
            Ok((None, None))
        }
        MgmtKeyChoice::Hex { key } => {
            let bytes =
                hex::decode(key.trim()).map_err(|e| ProvisionError::BadMgmtKey(e.to_string()))?;
            if bytes.len() != 24 {
                return Err(ProvisionError::BadMgmtKey(format!(
                    "expected 24 bytes, got {}",
                    bytes.len()
                )));
            }
            card.set_management_key_3des(&bytes)?;
            note_unsealed(fe, escrow.as_ref());
            Ok((None, None))
        }
        MgmtKeyChoice::Random => {
            let mut key = Zeroizing::new([0u8; 24]);
            rand_bytes(&mut key[..])
                .map_err(|e| ProvisionError::BadMgmtKey(format!("rng: {e}")))?;
            let key_hex = Zeroizing::new(hex::encode_upper(&key[..]));
            // A failed or cancelled offer answer means "don't seal": by now the
            // card's keys and PIN/PUK are rewritten, so aborting here would
            // leave it half-provisioned with its key never shown.
            let sink = match escrow {
                Some(e) if !e.ask || offer_seal(fe, card_id, &*e.sink).unwrap_or(false) => {
                    Some(e.sink)
                }
                _ => None,
            };
            match sink {
                Some(sink) => seal_then_rotate(card, fe, sink, &key[..], &key_hex)
                    .map(|sealed| (None, Some(sealed))),
                None => {
                    card.set_management_key_3des(&key[..])?;
                    Ok((Some(key_hex), None))
                }
            }
        }
    }
}

/// Ask the operator whether to seal the new key into the store.
fn offer_seal(
    fe: &mut dyn Frontend,
    card_id: &CardId,
    sink: &dyn KeyEscrow,
) -> Result<bool, FrontendError> {
    let n = sink.recipients().len();
    fe.confirm(ConfirmRequest {
        message: format!(
            "Seal {}'s new management key into the password store at {} ({n} recipient{})? Otherwise it is shown once and is NOT recoverable.",
            card_id.short_label(),
            sink.pass_name(),
            if n == 1 { "" } else { "s" }
        ),
        default: Some(false),
    })
}

/// Tell the operator an explicitly requested seal did not happen: only a
/// piggy-generated key is escrowed.
fn note_unsealed(fe: &mut dyn Frontend, escrow: Option<&Escrow<'_>>) {
    if matches!(escrow, Some(e) if !e.ask) {
        fe.progress(ProgressEvent {
            step: "seal-skipped".into(),
            message: "Management key not sealed: only a generated (random) key is escrowed".into(),
            current: None,
            total: None,
        });
    }
}

/// Seal `key` into `sink`, then set it on the card. A card that rejects the key
/// rolls the seal back, so an escrow never outlives a failed rotation and a
/// rotation never happens without its escrow.
fn seal_then_rotate(
    card: &mut dyn ProvisionCard,
    fe: &mut dyn Frontend,
    sink: &mut dyn KeyEscrow,
    key: &[u8],
    key_hex: &str,
) -> Result<SealedKey, ProvisionError> {
    fe.progress(ProgressEvent {
        step: "seal-mgmt-key".into(),
        message: format!("Sealing management key to {}", sink.pass_name()),
        current: None,
        total: None,
    });
    sink.seal(key_hex).map_err(ProvisionError::Seal)?;
    if let Err(e) = card.set_management_key_3des(key) {
        sink.rollback();
        return Err(e.into());
    }
    sink.commit();
    Ok(SealedKey {
        pass_name: sink.pass_name().to_string(),
        recipients: sink.recipients().len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::protocol::{CardSelectRequest, CompletedEvent, ConfirmRequest, ProgressEvent};
    use std::collections::VecDeque;

    /// A mock card recording an ordered op log; returns dummy points/sigs (the
    /// cert builder embeds both verbatim, so no real crypto is needed).
    #[derive(Default)]
    struct MockCard {
        log: Vec<String>,
        last_mgmt_key: Option<Vec<u8>>,
        /// Fail the management-key rotation, as a card whose write errors.
        reject_mgmt_key: bool,
    }

    impl ProvisionCard for MockCard {
        fn serial(&self) -> Option<u32> {
            Some(15909078)
        }
        fn authenticate_admin(&mut self, _key: &[u8]) -> Result<(), PivError> {
            self.log.push("admin".into());
            Ok(())
        }
        fn verify_pin(&mut self, _pin: &str) -> Result<(), PivError> {
            self.log.push("verify_pin".into());
            Ok(())
        }
        fn write_chuid(&mut self, _guid: &[u8; 16]) -> Result<(), PivError> {
            self.log.push("chuid".into());
            Ok(())
        }
        fn generate_key(&mut self, slot: u8, _alg: PivAlgorithm) -> Result<Vec<u8>, PivError> {
            self.log.push(format!("generate:{slot:02x}"));
            // A 65-byte uncompressed-point-shaped blob (04 ‖ 64 zero bytes).
            let mut p = vec![0x04u8];
            p.extend_from_slice(&[0u8; 64]);
            Ok(p)
        }
        fn sign_prehash(
            &mut self,
            slot: u8,
            _alg: PivAlgorithm,
            _digest: &[u8],
        ) -> Result<Vec<u8>, PivError> {
            self.log.push(format!("sign:{slot:02x}"));
            // A minimal DER SEQUENCE { INTEGER 1, INTEGER 1 } — embedded verbatim.
            Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
        }
        fn put_cert(&mut self, slot: u8, _cert_der: &[u8]) -> Result<(), PivError> {
            self.log.push(format!("put_cert:{slot:02x}"));
            Ok(())
        }
        fn change_pin(&mut self, _old: &str, _new: &str) -> Result<(), PivError> {
            self.log.push("change_pin".into());
            Ok(())
        }
        fn change_puk(&mut self, _old: &str, _new: &str) -> Result<(), PivError> {
            self.log.push("change_puk".into());
            Ok(())
        }
        fn set_management_key_3des(&mut self, key: &[u8]) -> Result<(), PivError> {
            if self.reject_mgmt_key {
                return Err(PivError::SlotEmpty(0x9B));
            }
            self.log.push("set_mgmt_key".into());
            self.last_mgmt_key = Some(key.to_vec());
            Ok(())
        }
    }

    /// A scripted frontend: canned secrets (FIFO), confirm answers (FIFO, then
    /// the fixed `confirm` fallback) and a mgmt-key choice, recording progress
    /// step tokens + the completion status.
    struct ScriptedFrontend {
        secrets: VecDeque<String>,
        confirm: bool,
        answers: VecDeque<bool>,
        mgmt: MgmtKeyChoice,
        steps: Vec<String>,
        completed: Option<CompletedStatus>,
        confirm_message: Option<String>,
    }

    impl ScriptedFrontend {
        fn new(secrets: &[&str], confirm: bool, mgmt: MgmtKeyChoice) -> Self {
            Self {
                secrets: secrets.iter().map(|s| s.to_string()).collect(),
                confirm,
                answers: VecDeque::new(),
                mgmt,
                steps: Vec::new(),
                completed: None,
                confirm_message: None,
            }
        }

        fn answering(mut self, answers: &[bool]) -> Self {
            self.answers = answers.iter().copied().collect();
            self
        }
    }

    impl Frontend for ScriptedFrontend {
        fn request_secret(
            &mut self,
            _req: SecretRequest,
        ) -> Result<Zeroizing<String>, FrontendError> {
            self.secrets
                .pop_front()
                .map(Zeroizing::new)
                .ok_or_else(|| FrontendError::Declined("no scripted secret".into()))
        }
        fn request_mgmt_key(
            &mut self,
            _req: MgmtKeyRequest,
        ) -> Result<MgmtKeyChoice, FrontendError> {
            Ok(self.mgmt.clone())
        }
        fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError> {
            self.confirm_message = Some(req.message);
            Ok(self.answers.pop_front().unwrap_or(self.confirm))
        }
        fn select_card(&mut self, _req: CardSelectRequest) -> Result<String, FrontendError> {
            Err(FrontendError::Declined("not used".into()))
        }
        fn progress(&mut self, ev: ProgressEvent) {
            self.steps.push(ev.step);
        }
        fn completed(&mut self, ev: CompletedEvent) {
            self.completed = Some(ev.status);
        }
    }

    fn cfg() -> ProvisionConfig {
        ProvisionConfig {
            guid: [
                0x19, 0x17, 0x55, 0xCF, 0xF3, 0x9E, 0xFE, 0x52, 0x2C, 0x07, 0xA3, 0x83, 0x27, 0x5B,
                0xBE, 0xB1,
            ],
            reprovision: false,
        }
    }

    #[test]
    fn full_setup_drives_card_ops_in_order_and_returns_random_mgmt_key() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["999999", "999999", "12345678", "12345678"], // new PIN ×2, new PUK ×2
            true,
            MgmtKeyChoice::Random,
        );
        let outcome = run(&mut card, &mut fe, &cfg(), None).unwrap();

        assert_eq!(outcome.guid, "191755CFF39EFE522C07A383275BBEB1");
        // Random choice → the engine generated and returned a 24-byte (48 hex) key.
        let key = outcome.generated_mgmt_key.expect("random key returned");
        assert_eq!(key.len(), 48, "24 bytes hex-encoded");

        // The card ops fired in provisioning order.
        assert_eq!(
            card.log,
            vec![
                "admin",
                "verify_pin",
                "chuid",
                "generate:9d",
                "sign:9d",
                "put_cert:9d",
                "generate:9a",
                "sign:9a",
                "put_cert:9a",
                "change_pin",
                "change_puk",
                "set_mgmt_key",
            ]
        );
        // The rotated key matches what was returned to the caller.
        let applied = hex::encode_upper(card.last_mgmt_key.unwrap());
        assert_eq!(applied, *key);

        assert_eq!(fe.completed, Some(CompletedStatus::Ok));
        assert_eq!(
            fe.steps,
            vec![
                "admin-auth",
                "write-chuid",
                "generate-9d",
                "generate-9a",
                "change-secrets",
                "rotate-mgmt-key",
            ]
        );
    }

    #[test]
    fn declined_confirmation_aborts_before_touching_card() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(&[], false, MgmtKeyChoice::Default);
        let err = run(&mut card, &mut fe, &cfg(), None).unwrap_err();
        assert!(matches!(err, ProvisionError::Aborted(_)), "got {err:?}");
        assert!(card.log.is_empty(), "no card op fired: {:?}", card.log);
        assert_eq!(fe.completed, Some(CompletedStatus::Error));
    }

    #[test]
    fn mismatched_pin_entries_error_and_stop_after_pin_change_attempt() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["111111", "222222"], // new PIN ≠ confirm
            true,
            MgmtKeyChoice::Default,
        );
        let err = run(&mut card, &mut fe, &cfg(), None).unwrap_err();
        assert!(matches!(err, ProvisionError::PinMismatch), "got {err:?}");
        // Keys/certs were written, but the PIN was never changed.
        assert!(card.log.contains(&"put_cert:9a".to_string()));
        assert!(!card.log.contains(&"change_pin".to_string()));
        assert_eq!(fe.completed, Some(CompletedStatus::Error));
    }

    #[test]
    fn default_mgmt_choice_skips_rotation() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["999999", "999999", "12345678", "12345678"],
            true,
            MgmtKeyChoice::Default,
        );
        let outcome = run(&mut card, &mut fe, &cfg(), None).unwrap();
        assert!(outcome.generated_mgmt_key.is_none());
        assert!(
            !card.log.contains(&"set_mgmt_key".to_string()),
            "Default choice does not rotate: {:?}",
            card.log
        );
    }

    #[test]
    fn hex_mgmt_choice_rotates_to_supplied_key() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["999999", "999999", "12345678", "12345678"],
            true,
            MgmtKeyChoice::Hex {
                key: "0102030405060708".repeat(3), // 24 bytes
            },
        );
        let outcome = run(&mut card, &mut fe, &cfg(), None).unwrap();
        assert!(
            outcome.generated_mgmt_key.is_none(),
            "Hex is not 'generated'"
        );
        assert_eq!(card.last_mgmt_key.unwrap().len(), 24);
    }

    #[test]
    fn bad_hex_mgmt_key_is_rejected() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["999999", "999999", "12345678", "12345678"],
            true,
            MgmtKeyChoice::Hex {
                key: "abcd".into(), // 2 bytes, not 24
            },
        );
        let err = run(&mut card, &mut fe, &cfg(), None).unwrap_err();
        assert!(matches!(err, ProvisionError::BadMgmtKey(_)), "got {err:?}");
    }

    #[test]
    fn reprovision_escalates_the_confirm_wording() {
        // Default (fresh provision): standard wording, no destruction warning.
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["999999", "999999", "12345678", "12345678"],
            true,
            MgmtKeyChoice::Default,
        );
        run(&mut card, &mut fe, &cfg(), None).unwrap();
        let msg = fe.confirm_message.clone().unwrap();
        assert!(msg.contains("Provision card"), "default wording: {msg}");
        assert!(
            !msg.contains("ALREADY PROVISIONED"),
            "default wording: {msg}"
        );

        // Reprovision: escalated wording naming the destruction.
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &["999999", "999999", "12345678", "12345678"],
            true,
            MgmtKeyChoice::Default,
        );
        let reprov = ProvisionConfig {
            reprovision: true,
            ..cfg()
        };
        run(&mut card, &mut fe, &reprov, None).unwrap();
        let msg = fe.confirm_message.clone().unwrap();
        assert!(
            msg.contains("ALREADY PROVISIONED") && msg.contains("DESTROYS"),
            "reprovision wording: {msg}"
        );
    }

    #[test]
    fn slot_cn_uses_prefix_and_short_guid() {
        assert_eq!(
            slot_cn("piv-auth", "191755CFF39EFE522C07A383275BBEB1"),
            "piv-auth@191755CF"
        );
    }

    // --- piggy#258: management-key escrow ---

    #[derive(Default)]
    struct MockEscrow {
        sealed: Option<String>,
        rolled_back: bool,
        committed: bool,
        fail_seal: bool,
    }

    /// Two stand-in recipient ids (only their count reaches the engine).
    fn two_recipients() -> &'static [piggy_markl::Id] {
        static RECIPIENTS: std::sync::LazyLock<Vec<piggy_markl::Id>> =
            std::sync::LazyLock::new(|| {
                [0x02u8, 0x03]
                    .iter()
                    .map(|prefix| {
                        piggy_markl::Id::new(
                            Some(piggy_markl::PurposeId::PiggyRecipientV1),
                            piggy_markl::FormatId::PivyEcdhP256Pub,
                            vec![*prefix; 33],
                        )
                        .unwrap()
                    })
                    .collect()
            });
        &RECIPIENTS
    }

    impl KeyEscrow for MockEscrow {
        fn pass_name(&self) -> &str {
            "piv/TEST/management-key"
        }
        fn recipients(&self) -> &[piggy_markl::Id] {
            two_recipients()
        }
        fn seal(&mut self, key_hex: &str) -> Result<(), String> {
            if self.fail_seal {
                return Err("disk full".into());
            }
            self.sealed = Some(key_hex.to_string());
            Ok(())
        }
        fn rollback(&mut self) {
            self.rolled_back = true;
        }
        fn commit(&mut self) {
            self.committed = true;
        }
    }

    const NEW_SECRETS: [&str; 4] = ["999999", "999999", "12345678", "12345678"];

    fn seal_run(
        card: &mut MockCard,
        fe: &mut ScriptedFrontend,
        escrow: &mut MockEscrow,
        ask: bool,
    ) -> Result<ProvisionOutcome, ProvisionError> {
        run(card, fe, &cfg(), Some(Escrow { sink: escrow, ask }))
    }

    #[test]
    fn required_seal_escrows_the_applied_key_and_withholds_it() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(&NEW_SECRETS, true, MgmtKeyChoice::Random);
        let mut escrow = MockEscrow::default();
        let outcome = seal_run(&mut card, &mut fe, &mut escrow, false).unwrap();

        assert!(
            outcome.generated_mgmt_key.is_none(),
            "a sealed key is not displayed"
        );
        assert_eq!(
            outcome.sealed_mgmt_key,
            Some(SealedKey {
                pass_name: "piv/TEST/management-key".into(),
                recipients: 2,
            })
        );
        let applied = hex::encode_upper(card.last_mgmt_key.expect("rotated"));
        assert_eq!(escrow.sealed.as_deref(), Some(applied.as_str()));
        assert!(escrow.committed && !escrow.rolled_back);
        assert!(fe.steps.contains(&"seal-mgmt-key".to_string()));
    }

    #[test]
    fn failed_seal_leaves_the_management_key_unrotated() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(&NEW_SECRETS, true, MgmtKeyChoice::Random);
        let mut escrow = MockEscrow {
            fail_seal: true,
            ..Default::default()
        };
        let err = seal_run(&mut card, &mut fe, &mut escrow, false).unwrap_err();
        assert!(matches!(err, ProvisionError::Seal(_)), "got {err:?}");
        assert!(
            !card.log.contains(&"set_mgmt_key".to_string()),
            "the key is sealed before it is set: {:?}",
            card.log
        );
        assert!(!escrow.committed);
        assert_eq!(fe.completed, Some(CompletedStatus::Error));
    }

    #[test]
    fn card_rejecting_the_key_rolls_the_seal_back() {
        let mut card = MockCard {
            reject_mgmt_key: true,
            ..Default::default()
        };
        let mut fe = ScriptedFrontend::new(&NEW_SECRETS, true, MgmtKeyChoice::Random);
        let mut escrow = MockEscrow::default();
        let err = seal_run(&mut card, &mut fe, &mut escrow, false).unwrap_err();
        assert!(matches!(err, ProvisionError::Card(_)), "got {err:?}");
        assert!(escrow.sealed.is_some() && escrow.rolled_back && !escrow.committed);
    }

    #[test]
    fn accepted_seal_offer_escrows_the_key() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(&NEW_SECRETS, true, MgmtKeyChoice::Random);
        let mut escrow = MockEscrow::default();
        let outcome = seal_run(&mut card, &mut fe, &mut escrow, true).unwrap();
        assert!(outcome.sealed_mgmt_key.is_some());
        assert!(outcome.generated_mgmt_key.is_none());
        let offer = fe.confirm_message.unwrap();
        assert!(
            offer.contains("piv/TEST/management-key") && offer.contains("2 recipients"),
            "{offer}"
        );
    }

    #[test]
    fn declined_seal_offer_displays_the_key() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(&NEW_SECRETS, true, MgmtKeyChoice::Random)
            .answering(&[true, false]);
        let mut escrow = MockEscrow::default();
        let outcome = seal_run(&mut card, &mut fe, &mut escrow, true).unwrap();
        assert!(outcome.sealed_mgmt_key.is_none());
        assert!(outcome.generated_mgmt_key.is_some());
        assert!(escrow.sealed.is_none() && !escrow.committed);
    }

    #[test]
    fn operator_supplied_key_is_never_sealed() {
        let mut card = MockCard::default();
        let mut fe = ScriptedFrontend::new(
            &NEW_SECRETS,
            true,
            MgmtKeyChoice::Hex {
                key: "0102030405060708".repeat(3),
            },
        );
        let mut escrow = MockEscrow::default();
        let outcome = seal_run(&mut card, &mut fe, &mut escrow, false).unwrap();
        assert!(outcome.sealed_mgmt_key.is_none());
        assert!(escrow.sealed.is_none());
        assert!(
            fe.steps.contains(&"seal-skipped".to_string()),
            "{:?}",
            fe.steps
        );
    }

    /// Confirms the provision, then fails every later confirm as a cancelled
    /// prompt — i.e. the seal offer's answer never arrives.
    struct CancelsOffer(ScriptedFrontend);

    impl Frontend for CancelsOffer {
        fn request_secret(
            &mut self,
            req: SecretRequest,
        ) -> Result<Zeroizing<String>, FrontendError> {
            self.0.request_secret(req)
        }
        fn request_mgmt_key(
            &mut self,
            req: MgmtKeyRequest,
        ) -> Result<MgmtKeyChoice, FrontendError> {
            self.0.request_mgmt_key(req)
        }
        fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError> {
            if self.0.confirm_message.is_some() {
                return Err(FrontendError::Declined("prompt cancelled".into()));
            }
            self.0.confirm(req)
        }
        fn select_card(&mut self, req: CardSelectRequest) -> Result<String, FrontendError> {
            self.0.select_card(req)
        }
        fn progress(&mut self, ev: ProgressEvent) {
            self.0.progress(ev)
        }
        fn completed(&mut self, ev: CompletedEvent) {
            self.0.completed(ev)
        }
    }

    #[test]
    fn failed_seal_offer_answer_still_rotates_and_displays_the_key() {
        let mut card = MockCard::default();
        let mut fe = CancelsOffer(ScriptedFrontend::new(
            &NEW_SECRETS,
            true,
            MgmtKeyChoice::Random,
        ));
        let mut escrow = MockEscrow::default();
        let outcome = run(
            &mut card,
            &mut fe,
            &cfg(),
            Some(Escrow {
                sink: &mut escrow,
                ask: true,
            }),
        )
        .unwrap();
        assert!(
            outcome.generated_mgmt_key.is_some(),
            "the key is displayed, not lost"
        );
        assert!(outcome.sealed_mgmt_key.is_none());
        assert!(escrow.sealed.is_none());
        assert!(card.last_mgmt_key.is_some(), "the key was still rotated");
    }
}
