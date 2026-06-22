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
//! [`MgmtKeyChoice::Random`]; the engine then generates the key and returns it
//! in [`ProvisionOutcome::generated_mgmt_key`] for the command to display once
//! — the key never crosses a `progress`/`completed` notification (RFC 0006
//! security). PIN-protected storage — the eventual secure default — is
//! piggy#198.

use openssl::rand::rand_bytes;
use zeroize::Zeroizing;

use piggy_piv::{PivAlgorithm, PivError};

use crate::card::protocol::{
    CardId, CompletedEvent, CompletedStatus, ConfirmRequest, Frontend, FrontendError,
    MgmtKeyChoice, MgmtKeyRequest, ProgressEvent, SecretKind, SecretRequest,
};

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
    /// Sign a prehash with `slot`'s key; returns a DER ECDSA signature (used to
    /// self-sign the slot's cert).
    fn sign_prehash(&mut self, slot: u8, digest: &[u8]) -> Result<Vec<u8>, PivError>;
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
}

/// What a successful provision produced.
#[derive(Debug)]
pub struct ProvisionOutcome {
    /// The provisioned card's GUID, uppercase hex.
    pub guid: String,
    /// The newly-generated random management key (hex), present **only** when
    /// the frontend chose [`MgmtKeyChoice::Random`]. The caller displays it
    /// once; it is never logged or sent over a notification.
    pub generated_mgmt_key: Option<Zeroizing<String>>,
}

/// Why a provision failed.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
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
        |digest| card.sign_prehash(slot, digest),
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
) -> Result<ProvisionOutcome, ProvisionError> {
    let result = run_inner(card, fe, cfg);
    match &result {
        Ok(outcome) => fe.completed(CompletedEvent {
            status: CompletedStatus::Ok,
            summary: Some(serde_json::json!({ "guid": outcome.guid })),
            error: None,
        }),
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
) -> Result<ProvisionOutcome, ProvisionError> {
    let guid_hex = hex::encode_upper(cfg.guid);
    let card_id = CardId {
        guid: guid_hex.clone(),
        serial: card.serial(),
        cn: None,
    };

    // Confirm before touching the card — this overwrites slots 9A and 9D.
    let proceed = fe.confirm(ConfirmRequest {
        message: format!(
            "Provision card {} — this generates new 9A + 9D keys and overwrites their certs. Proceed?",
            card_id.short_label()
        ),
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
    let generated_mgmt_key = rotate_mgmt_key(card, fe, &card_id)?;

    Ok(ProvisionOutcome {
        guid: guid_hex,
        generated_mgmt_key,
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
    })?;
    let second = fe.request_secret(SecretRequest {
        kind: confirm,
        prompt: "Re-enter to confirm".into(),
        card: Some(card.clone()),
        slot: None,
        attempts_remaining: None,
    })?;
    if first.as_str() != second.as_str() {
        return Err(mismatch);
    }
    Ok(first)
}

/// Resolve the frontend's management-key choice into an applied rotation,
/// returning the generated key (hex) only for the `Random` case.
fn rotate_mgmt_key(
    card: &mut dyn ProvisionCard,
    fe: &mut dyn Frontend,
    card_id: &CardId,
) -> Result<Option<Zeroizing<String>>, ProvisionError> {
    let choice = fe.request_mgmt_key(MgmtKeyRequest {
        prompt: "Management key for the card".into(),
        card: card_id.clone(),
    })?;
    match choice {
        MgmtKeyChoice::Default => Ok(None),
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
            Ok(None)
        }
        MgmtKeyChoice::Random => {
            let mut key = [0u8; 24];
            rand_bytes(&mut key).map_err(|e| ProvisionError::BadMgmtKey(format!("rng: {e}")))?;
            card.set_management_key_3des(&key)?;
            Ok(Some(Zeroizing::new(hex::encode_upper(key))))
        }
    }
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
        fn sign_prehash(&mut self, slot: u8, _digest: &[u8]) -> Result<Vec<u8>, PivError> {
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
            self.log.push("set_mgmt_key".into());
            self.last_mgmt_key = Some(key.to_vec());
            Ok(())
        }
    }

    /// A scripted frontend: canned secrets (FIFO), a fixed confirm answer and
    /// mgmt-key choice, recording progress step tokens + the completion status.
    struct ScriptedFrontend {
        secrets: VecDeque<String>,
        confirm: bool,
        mgmt: MgmtKeyChoice,
        steps: Vec<String>,
        completed: Option<CompletedStatus>,
    }

    impl ScriptedFrontend {
        fn new(secrets: &[&str], confirm: bool, mgmt: MgmtKeyChoice) -> Self {
            Self {
                secrets: secrets.iter().map(|s| s.to_string()).collect(),
                confirm,
                mgmt,
                steps: Vec::new(),
                completed: None,
            }
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
        fn confirm(&mut self, _req: ConfirmRequest) -> Result<bool, FrontendError> {
            Ok(self.confirm)
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
        let outcome = run(&mut card, &mut fe, &cfg()).unwrap();

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
        let err = run(&mut card, &mut fe, &cfg()).unwrap_err();
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
        let err = run(&mut card, &mut fe, &cfg()).unwrap_err();
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
        let outcome = run(&mut card, &mut fe, &cfg()).unwrap();
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
        let outcome = run(&mut card, &mut fe, &cfg()).unwrap();
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
        let err = run(&mut card, &mut fe, &cfg()).unwrap_err();
        assert!(matches!(err, ProvisionError::BadMgmtKey(_)), "got {err:?}");
    }

    #[test]
    fn slot_cn_uses_prefix_and_short_guid() {
        assert_eq!(
            slot_cn("piv-auth", "191755CFF39EFE522C07A383275BBEB1"),
            "piv-auth@191755CF"
        );
    }
}
