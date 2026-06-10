//! End-to-end integration test for the direct-PCSC card unlock path
//! (`CardEcdhOracle`) against a live fib-backed PIV card.
//!
//! Issue #31. Mirrors the shape of `unlock_ebox_agent_integration.rs`
//! but skips the `piggy agent` spawn — the card oracle talks straight to
//! pcscd via `PCSCLITE_CSOCK_NAME` and reads the PIN from `SSH_ASKPASS`.
//!
//! Gating: the test no-ops unless `PCSCLITE_CSOCK_NAME` and `PIGGY_BIN`
//! are both set. The `test-rust-card-unlock` just recipe brings up fib,
//! generates a P-256 key in slot 9D, points `SSH_ASKPASS` at the
//! refusing test askpass, and exports `PIGGY_TEST_FIB_PIN=123456` so the
//! askpass returns the fib PIN non-interactively.

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint, PointConversionForm};
use piggy::card_oracle::{CardEcdhOracle, askpass_pin_supplier};
use piggy_box::ebox::{Ebox, EboxType};
use piggy_box::piv_box::EcCurve;
use piggy_box::template::{DEFAULT_SLOT, EboxConfigType, EboxTemplate, EboxTplConfig, EboxTplPart};
use piggy_box::unlock::unlock_ebox;
use piggy_piv::{PivAlgorithm, PivContext};
use ssh_key::public::{EcdsaPublicKey, KeyData};

#[test]
fn unlock_ebox_against_real_card() {
    // ---- Gating ----
    // Two modes enable this test; otherwise it no-ops:
    //  - fib mode: `PCSCLITE_CSOCK_NAME` points at the fib socket.
    //  - hardware mode: `PIGGY_TEST_CARD_GUID` pins the test to ONE specific
    //    real card, so it never touches a co-resident prod card.
    // `PIGGY_TEST_FIB_PIN` supplies the card PIN (via the test askpass) in
    // both modes. This is the only Rust `PinSession` user reachable as an
    // in-process test (the agent/box CLIs exec into C pivy-*; piggy#56).
    let pcscd_sock = std::env::var("PCSCLITE_CSOCK_NAME").unwrap_or_default();
    let want_guid = std::env::var("PIGGY_TEST_CARD_GUID").unwrap_or_default();
    if pcscd_sock.is_empty() && want_guid.is_empty() {
        eprintln!(
            "neither PCSCLITE_CSOCK_NAME nor PIGGY_TEST_CARD_GUID set — skipping \
             (fib: `just test-rust-card-unlock`; hardware: the card-unlock-hw recipe)"
        );
        return;
    }
    if !pcscd_sock.is_empty() {
        eprintln!("using pcscd socket: {pcscd_sock}");
    }
    if !want_guid.is_empty() {
        eprintln!("pinned to card GUID: {want_guid}");
    }

    // ---- Read card's 9D pubkey via piggy-piv ----
    //
    // We do a fresh enumerate/read here (rather than reusing what
    // CardEcdhOracle does internally) so the template we seal against
    // names the exact GUID + pubkey the card will present at unlock
    // time. Scoping the read in a block ensures the `PivContext` and
    // its `pcsc::Card` are dropped before the card oracle later opens
    // its own context — avoids any reader-locking contention.
    let (card_guid, card_sec1_uncompressed) = {
        let ctx = PivContext::new().expect("PivContext");
        let tokens = ctx.enumerate_tokens().expect("enumerate_tokens");
        // In hardware mode pin to the requested GUID so a co-resident prod
        // card is never selected; in fib mode take the only token present.
        let token = if want_guid.is_empty() {
            tokens
                .first()
                .expect("at least one PIV token available via PCSCLITE_CSOCK_NAME")
        } else {
            tokens
                .iter()
                .find(|t| t.guid().to_hex().eq_ignore_ascii_case(&want_guid))
                .unwrap_or_else(|| panic!("no PIV token with GUID {want_guid} present"))
        };
        let slot_9d = token.read_slot(0x9D).expect("read 9D slot");
        assert_eq!(
            slot_9d.algorithm(),
            PivAlgorithm::EcP256,
            "test assumes 9D was generated with eccp256"
        );
        let guid = token.guid().clone();
        let pubkey = match slot_9d.public_key().key_data() {
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
            other => panic!("expected NistP256, got {other:?}"),
        };
        assert_eq!(pubkey.len(), 65, "P-256 uncompressed point is 65 bytes");
        (guid, pubkey)
    };

    // Compress for the template (matches `piggy box tpl create`).
    let card_sec1_compressed = compress_ec_point(EcCurve::NistP256, &card_sec1_uncompressed);

    // ---- Build a minimal single-part Primary template ----
    let tpl = EboxTemplate {
        version: 1,
        configs: vec![EboxTplConfig {
            config_type: EboxConfigType::Primary,
            n: 1,
            parts: vec![EboxTplPart {
                guid: Some(card_guid.clone()),
                slot: DEFAULT_SLOT,
                name: Some("piggy-test:unlock-card-integration".into()),
                pubkey: card_sec1_compressed,
                pubkey_curve: EcCurve::NistP256,
                cak: None,
            }],
        }],
    };

    // ---- Seal a random key under the card's pubkey ----
    let plaintext_key: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(13).wrapping_add(5))
        .collect();
    let sealed = Ebox::create(&tpl, &plaintext_key, EboxType::Stream).expect("Ebox::create");

    // ---- Wire round-trip (bytes → bytes → Ebox) ----
    let wire = sealed.to_bytes().expect("serialize ebox");
    let mut ebox = Ebox::from_bytes(&wire).expect("deserialize ebox");
    assert!(!ebox.is_unlocked(), "deserialized ebox must start locked");

    // ---- Unlock via the card ----
    //
    // The recipe wires SSH_ASKPASS to the refusing test askpass (plus
    // SSH_ASKPASS_REQUIRE=force per the harness safety net) and sets
    // PIGGY_TEST_FIB_PIN so the askpass non-interactively returns the
    // fib PIN. Under force, an unset SSH_ASKPASS surfaces as a clear
    // error ("no PIN source") rather than a GUI dialog or a tty
    // fallback (#166).
    let mut oracle = CardEcdhOracle::new(askpass_pin_supplier()).expect("build CardEcdhOracle");
    unlock_ebox(&mut ebox, None, Some(&mut oracle)).expect("unlock_ebox via card");

    assert!(
        ebox.is_unlocked(),
        "ebox must be unlocked after card round-trip"
    );
    let recovered = ebox.key().expect("key materializes");
    assert_eq!(
        recovered, plaintext_key,
        "recovered key must match the sealed plaintext"
    );

    eprintln!("unlock_ebox round-trip OK: recovered sealed key via direct PCSC card path");
}

/// Compress a SEC1 uncompressed EC point (65 bytes for P-256) to the
/// compressed form (33 bytes) using openssl — the same encoding
/// template and piv_box expect for `recipient_pubkey`.
fn compress_ec_point(curve: EcCurve, uncompressed: &[u8]) -> Vec<u8> {
    let group = EcGroup::from_curve_name(curve.nid()).expect("EcGroup");
    let mut ctx = BigNumContext::new().expect("BigNumContext");
    let p = EcPoint::from_bytes(&group, uncompressed, &mut ctx).expect("EcPoint::from_bytes");
    let out = p
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .expect("point to_bytes");
    assert_eq!(out.len(), 33, "compressed P-256 point is 33 bytes");
    out
}
