//! Unit tests for `piggy_ids::classify_slot_9d` and `classify_slot`.
//! No PIV context needed — we feed synthetic algorithm values and cert
//! bytes.

use piggy_ids::{classify_slot, classify_slot_9d, Classification};
use piggy_piv::{Guid, PivAlgorithm};

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
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn rsa_in_retired_slot_reason_names_that_slot() {
    let guid = fake_guid();
    let cert: &[u8] = &[];
    match classify_slot(
        0x82,
        guid,
        "Yubico YubiKey 00 00".into(),
        None,
        PivAlgorithm::Rsa2048,
        cert,
    ) {
        Classification::Unsupported {
            reason, slot_id, ..
        } => {
            assert!(
                reason.starts_with("slot 82 is"),
                "reason missing expected prefix 'slot 82 is': {reason}"
            );
            assert_eq!(slot_id, 0x82);
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
