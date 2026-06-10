//! Unit tests for `piggy_ids::classify_slot_9d`, `classify_slot`, and
//! `classify_ssh_slot`. No PIV context needed — we feed synthetic
//! algorithm values and cert bytes.

use piggy_ids::{
    Classification, ClassifyInput, classify_slot, classify_slot_9d, classify_ssh_slot,
};
use piggy_piv::{Guid, PinPolicy, PivAlgorithm, TouchPolicy};

fn fake_guid() -> Guid {
    Guid::from_hex("00112233445566778899aabbccddeeff").expect("valid hex")
}

#[test]
fn rsa_in_9d_is_unsupported() {
    let guid = fake_guid();
    let cert: &[u8] = &[]; // irrelevant when algorithm rejects the slot
    match classify_slot_9d(
        guid,
        "Yubico YubiKey 00 00".into(),
        Some(12_345_678),
        PivAlgorithm::Rsa2048,
        cert,
    ) {
        Classification::Unsupported {
            reason,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            ..
        } => {
            assert!(
                reason.starts_with("slot 9D is"),
                "reason missing expected prefix 'slot 9D is': {reason}"
            );
            assert!(
                reason.contains("Rsa2048"),
                "reason missing algorithm name 'Rsa2048': {reason}"
            );
            assert_eq!(reader, "Yubico YubiKey 00 00");
            assert_eq!(serial, Some(12_345_678));
            assert_eq!(slot_id, 0x9D);
            // Empty cert can't carry a CN.
            assert_eq!(cn, None);
            // classify_slot_9d wrapper passes None for both policies.
            assert_eq!(pin_policy, None);
            assert_eq!(touch_policy, None);
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn malformed_cert_in_9d_is_unsupported() {
    let guid = fake_guid();
    let cert: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF]; // not a valid X.509 cert
    match classify_slot_9d(guid, "fake-reader".into(), None, PivAlgorithm::EcP256, cert) {
        Classification::Unsupported {
            reason,
            reader,
            serial,
            slot_id,
            cn,
            pin_policy,
            touch_policy,
            ..
        } => {
            assert!(
                reason.starts_with("pubkey decode failed:"),
                "reason missing expected prefix 'pubkey decode failed:': {reason}"
            );
            assert!(
                reason.contains("decode"),
                "reason missing inner 'decode' substring: {reason}"
            );
            assert_eq!(reader, "fake-reader");
            assert_eq!(serial, None);
            assert_eq!(slot_id, 0x9D);
            // Malformed cert can't be parsed for a CN either.
            assert_eq!(cn, None);
            assert_eq!(pin_policy, None);
            assert_eq!(touch_policy, None);
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn rsa_in_retired_slot_reason_names_that_slot() {
    let guid = fake_guid();
    let cert: &[u8] = &[];
    match classify_slot(ClassifyInput {
        slot_id: 0x82,
        guid,
        reader: "Yubico YubiKey 00 00".into(),
        serial: None,
        algo: PivAlgorithm::Rsa2048,
        cert_der: cert,
        // No policy info plumbed in.
        pin_policy: None,
        touch_policy: None,
    }) {
        Classification::Unsupported {
            reason,
            slot_id,
            pin_policy,
            touch_policy,
            ..
        } => {
            assert!(
                reason.starts_with("slot 82 is"),
                "reason missing expected prefix 'slot 82 is': {reason}"
            );
            assert_eq!(slot_id, 0x82);
            assert_eq!(pin_policy, None);
            assert_eq!(touch_policy, None);
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn classify_ssh_slot_rejects_non_9a_9c_9e() {
    // SSH slot classifier should refuse recipient slots — those go
    // through classify_slot.
    let cert: &[u8] = &[];
    let result = classify_ssh_slot(ClassifyInput {
        slot_id: 0x9D,
        guid: fake_guid(),
        reader: "reader".into(),
        serial: None,
        algo: PivAlgorithm::EcP256,
        cert_der: cert,
        pin_policy: None,
        touch_policy: None,
    });
    match result {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.contains("9A/9C/9E"),
                "expected slot-set reason, got: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn classify_ssh_slot_rejects_rsa() {
    let cert: &[u8] = &[];
    let result = classify_ssh_slot(ClassifyInput {
        slot_id: 0x9A,
        guid: fake_guid(),
        reader: "reader".into(),
        serial: None,
        algo: PivAlgorithm::Rsa2048,
        cert_der: cert,
        pin_policy: None,
        touch_policy: None,
    });
    match result {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.contains("Rsa2048"),
                "expected Rsa2048 in reason: {reason}"
            );
            assert!(
                reason.contains("EcP256"),
                "expected EcP256 mention in reason: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Build a self-signed Ed25519 cert via openssl. Returns
/// `(cert_der, raw_pubkey)` so the test can pin the markl payload
/// against the key the cert actually carries. Ed25519 certs are signed
/// with pure EdDSA, hence `MessageDigest::null()`.
fn ed25519_self_signed_cert(cn: &str) -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder};

    let key = PKey::generate_ed25519().expect("ed25519 keygen");
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, cn)
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::null()).unwrap();
    let cert = builder.build();

    (
        cert.to_der().unwrap(),
        key.raw_public_key().expect("raw ed25519 pubkey"),
    )
}

#[test]
fn classify_ssh_slot_supports_ed25519() {
    use piggy_markl::{FormatId, PurposeId};

    let (cert_der, raw_pubkey) = ed25519_self_signed_cert("piggy-test-ed25519");
    let result = classify_ssh_slot(ClassifyInput {
        slot_id: 0x9A,
        guid: fake_guid(),
        reader: "reader".into(),
        serial: None,
        algo: PivAlgorithm::Ed25519,
        cert_der: &cert_der,
        pin_policy: None,
        touch_policy: None,
    });
    match result {
        Classification::Supported { id, cn, .. } => {
            assert_eq!(id.purpose(), Some(&PurposeId::PiggyPivAuthV1));
            assert_eq!(id.format(), FormatId::SshEd25519Pub);
            assert_eq!(id.data(), &raw_pubkey[..], "payload must be the raw key");
            assert_eq!(cn.as_deref(), Some("piggy-test-ed25519"));
        }
        other => panic!("expected Supported, got {other:?}"),
    }
}

#[test]
fn classify_ssh_slot_rejects_ed25519_payload_under_non_ed25519_cert() {
    // An Ed25519-algo slot whose cert doesn't actually carry an
    // Ed25519 SPKI (here: garbage DER) must classify Unsupported via
    // the decode path, not panic or mis-build a markl ID.
    let cert: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let result = classify_ssh_slot(ClassifyInput {
        slot_id: 0x9C,
        guid: fake_guid(),
        reader: "reader".into(),
        serial: None,
        algo: PivAlgorithm::Ed25519,
        cert_der: cert,
        pin_policy: None,
        touch_policy: None,
    });
    match result {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.starts_with("pubkey decode failed:"),
                "expected decode-failure reason: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

/// Build a self-signed ECDSA cert on the given curve. Returns
/// `(cert_der, compressed_point)`.
fn ec_self_signed_cert(nid: openssl::nid::Nid, cn: &str) -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder};

    let group = openssl::ec::EcGroup::from_curve_name(nid).unwrap();
    let ec = openssl::ec::EcKey::generate(&group).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let compressed = ec
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )
        .unwrap();
    let key = PKey::from_ec_key(ec).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, cn)
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    (cert.to_der().unwrap(), compressed)
}

#[test]
fn classify_ssh_slot_supports_p384() {
    use piggy_markl::{FormatId, PurposeId};

    let (cert_der, compressed) =
        ec_self_signed_cert(openssl::nid::Nid::SECP384R1, "piggy-test-p384");
    assert_eq!(compressed.len(), 49);
    let result = classify_ssh_slot(ClassifyInput {
        slot_id: 0x9A,
        guid: fake_guid(),
        reader: "reader".into(),
        serial: None,
        algo: PivAlgorithm::EcP384,
        cert_der: &cert_der,
        pin_policy: None,
        touch_policy: None,
    });
    match result {
        Classification::Supported { id, cn, .. } => {
            assert_eq!(id.purpose(), Some(&PurposeId::PiggyPivAuthV1));
            assert_eq!(id.format(), FormatId::SshEcdsaNistp384Pub);
            assert_eq!(id.data(), &compressed[..]);
            assert_eq!(cn.as_deref(), Some("piggy-test-p384"));
        }
        other => panic!("expected Supported, got {other:?}"),
    }
}

#[test]
fn classify_ssh_slot_rejects_curve_algo_mismatch() {
    // A slot whose declared algorithm (P-384) disagrees with the curve
    // its cert actually carries (P-256) must classify Unsupported via
    // the compressed-length check, not mis-build a 33-byte markl ID
    // under the 49-byte ssh_ecdsa_nistp384_pub format.
    let (cert_der, _) =
        ec_self_signed_cert(openssl::nid::Nid::X9_62_PRIME256V1, "piggy-test-mismatch");
    let result = classify_ssh_slot(ClassifyInput {
        slot_id: 0x9A,
        guid: fake_guid(),
        reader: "reader".into(),
        serial: None,
        algo: PivAlgorithm::EcP384,
        cert_der: &cert_der,
        pin_policy: None,
        touch_policy: None,
    });
    match result {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.starts_with("pubkey decode failed:"),
                "expected decode-failure reason: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn classify_slot_threads_policies_into_unsupported_record() {
    // Even when the slot is unsupported (RSA), the caller's policy
    // info should still appear on the record — useful for showing the
    // user *why* their RSA-in-retired-slot is unusable while still
    // surfacing the slot's other metadata.
    let guid = fake_guid();
    let cert: &[u8] = &[];
    match classify_slot(ClassifyInput {
        slot_id: 0x83,
        guid,
        reader: "Yubico YubiKey 00 00".into(),
        serial: None,
        algo: PivAlgorithm::Rsa2048,
        cert_der: cert,
        pin_policy: Some(PinPolicy::Once),
        touch_policy: Some(TouchPolicy::Cached),
    }) {
        Classification::Unsupported {
            pin_policy,
            touch_policy,
            ..
        } => {
            assert_eq!(pin_policy, Some(PinPolicy::Once));
            assert_eq!(touch_policy, Some(TouchPolicy::Cached));
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
