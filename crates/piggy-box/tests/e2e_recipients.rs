//! End-to-end tracer-bullet for piggy 2.x's Rust-native encrypt path
//! (#73 phase 3).
//!
//! Exercises the full flow:
//!
//!   piggy_markl::Id (PiggyRecipientV1@PivyEcdhP256Pub)
//!     → piggy_box::recipients::template_from_recipients
//!     → guid-less EboxTemplate
//!     → EboxStream::new (seals key against recipients)
//!     → encrypt_chunk → wire bytes
//!     → EboxStream::from_bytes (parses guid-less wire format)
//!     → unlock_ebox via LocalEcdhOracle (recovers key by ECDH)
//!     → decrypt_chunk → original plaintext
//!
//! The decrypt side uses piggy-box's own `LocalEcdhOracle` (matching
//! the unit-test pattern in `unlock.rs::tests`) rather than shelling
//! out to the C `pivy-box stream decrypt`. That stronger compat
//! claim is a follow-up in this same phase — what this test
//! establishes is:
//!
//! 1. The recipients shim produces a wire-format ebox without a
//!    guid tag (proves vendored-pivy parser patches in #70 are
//!    matched by the Rust-side serializer).
//! 2. The wire-format round-trips through to_bytes / from_bytes.
//! 3. The ECDH unlock path handles the no-guidslot case cleanly
//!    (because the oracle is keyed on pubkey, not GUID).
//! 4. After unlock, encrypt_chunk / decrypt_chunk recover the
//!    original plaintext.

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::nid::Nid;
use piggy_box::oracle::{EcdhOracle, OracleError};
use piggy_box::piv_box::EcCurve;
use piggy_box::recipients::template_from_recipients;
use piggy_box::stream::EboxStream;
use piggy_box::unlock::unlock_ebox;
use piggy_markl::{FormatId, Id as MarklId, PurposeId};

/// Minimal local oracle: a private scalar that knows how to ECDH
/// against any P-256 partner pubkey. Mirrors the test-only oracle
/// in `unlock.rs::tests` but exposed via this integration test.
struct LocalEcdhOracle {
    priv_key: EcKey<openssl::pkey::Private>,
    curve: EcCurve,
}

impl EcdhOracle for LocalEcdhOracle {
    fn ecdh(
        &mut self,
        _self_blob: &[u8],
        partner_blob: &[u8],
    ) -> std::result::Result<Vec<u8>, OracleError> {
        let point = piggy_box::agent_ext::extract_point_from_sshkey_blob(partner_blob)?;

        let group = EcGroup::from_curve_name(self.curve.nid())
            .map_err(|e| OracleError::Other(e.to_string()))?;
        let mut ctx = BigNumContext::new().map_err(|e| OracleError::Other(e.to_string()))?;
        let ec_point = openssl::ec::EcPoint::from_bytes(&group, &point, &mut ctx)
            .map_err(|e| OracleError::InvalidPubkey(e.to_string()))?;
        let peer_pub = EcKey::from_public_key(&group, &ec_point)
            .map_err(|e| OracleError::Other(e.to_string()))?;

        let pkey_priv = openssl::pkey::PKey::from_ec_key(self.priv_key.clone())
            .map_err(|e| OracleError::Other(e.to_string()))?;
        let pkey_pub = openssl::pkey::PKey::from_ec_key(peer_pub)
            .map_err(|e| OracleError::Other(e.to_string()))?;

        let mut d = openssl::derive::Deriver::new(&pkey_priv)
            .map_err(|e| OracleError::Other(e.to_string()))?;
        d.set_peer(&pkey_pub)
            .map_err(|e| OracleError::Other(e.to_string()))?;
        d.derive_to_vec()
            .map_err(|e| OracleError::Other(e.to_string()))
    }
}

fn fresh_p256_keypair() -> (EcKey<openssl::pkey::Private>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let priv_key = EcKey::generate(&group).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let pubkey = priv_key
        .public_key()
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .unwrap();
    (priv_key, pubkey)
}

#[test]
fn rust_encrypt_then_rust_decrypt_round_trips_through_guid_less_wire_format() {
    let plaintext = b"Phase 3 tracer-bullet: encrypt via markl recipient, decrypt via local oracle.";

    // ---- Encrypt side ----
    let (priv_key, pubkey_bytes) = fresh_p256_keypair();
    let recipient_id = MarklId::new(
        Some(PurposeId::PiggyRecipientV1),
        FormatId::PivyEcdhP256Pub,
        pubkey_bytes,
    )
    .expect("constructing the markl recipient ID");

    let tpl = template_from_recipients(&[recipient_id]).expect("template_from_recipients");

    // Sanity-check guid-less template — the load-bearing claim of this test.
    assert_eq!(tpl.configs.len(), 1);
    assert_eq!(tpl.configs[0].parts.len(), 1);
    assert!(
        tpl.configs[0].parts[0].guid.is_none(),
        "recipients shim must produce guid-less template parts"
    );

    let stream = EboxStream::new(&tpl).expect("EboxStream::new");
    let header_bytes = stream.to_bytes().expect("EboxStream::to_bytes");

    // Verify the serialized header parses cleanly back without losing
    // the guid-less property.
    let parsed_header = EboxStream::from_bytes(&header_bytes).expect("EboxStream::from_bytes");
    assert!(
        parsed_header.ebox.configs[0].parts[0].guid.is_none(),
        "wire round-trip must preserve guid-less encoding"
    );

    let chunk_bytes = stream.encrypt_chunk(0, plaintext).expect("encrypt_chunk");

    // ---- Decrypt side: parse header → unlock via local oracle → decrypt chunk ----
    let mut received = EboxStream::from_bytes(&header_bytes).expect("decoder side from_bytes");
    assert!(
        received.ebox.key().is_none(),
        "freshly-parsed stream must not carry a key"
    );

    let mut oracle = LocalEcdhOracle {
        priv_key,
        curve: EcCurve::NistP256,
    };
    unlock_ebox(&mut received.ebox, Some(&mut oracle), None).expect("unlock_ebox");
    assert!(
        received.ebox.is_unlocked(),
        "ebox must be unlocked after oracle returns the shared secret"
    );

    let (seqnr, recovered) = received.decrypt_chunk(Some(0), &chunk_bytes).expect("decrypt_chunk");
    assert_eq!(seqnr, 0);
    assert_eq!(recovered, plaintext);
}

#[test]
fn rust_encrypt_against_multiple_recipients_lets_any_decrypt() {
    let plaintext = b"any one recipient should be able to decrypt";

    let (priv_a, pub_a) = fresh_p256_keypair();
    let (_priv_b, pub_b) = fresh_p256_keypair();
    let (_priv_c, pub_c) = fresh_p256_keypair();

    let id = |bytes: Vec<u8>| -> MarklId {
        MarklId::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            bytes,
        )
        .unwrap()
    };

    let tpl = template_from_recipients(&[id(pub_a), id(pub_b), id(pub_c)]).unwrap();
    assert_eq!(tpl.configs[0].parts.len(), 3);
    for part in &tpl.configs[0].parts {
        assert!(part.guid.is_none(), "every recipient is guid-less");
    }

    let stream = EboxStream::new(&tpl).unwrap();
    let header_bytes = stream.to_bytes().unwrap();
    let chunk_bytes = stream.encrypt_chunk(0, plaintext).unwrap();

    // Decrypt with recipient A only — proves any-of-N unlock.
    let mut received = EboxStream::from_bytes(&header_bytes).unwrap();
    let mut oracle = LocalEcdhOracle {
        priv_key: priv_a,
        curve: EcCurve::NistP256,
    };
    unlock_ebox(&mut received.ebox, Some(&mut oracle), None).expect("unlock with priv_a");

    let (_, recovered) = received.decrypt_chunk(Some(0), &chunk_bytes).unwrap();
    assert_eq!(recovered, plaintext);
}
