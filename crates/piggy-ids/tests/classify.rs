//! Unit tests for `piggy_ids::classify_slot_9d`, `classify_slot`, and
//! `classify_ssh_slot`. No PIV context needed — we feed synthetic
//! algorithm values and cert bytes.

use piggy_ids::{Classification, classify_slot, classify_slot_9d, classify_ssh_slot};
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
    match classify_slot(
        0x82,
        guid,
        "Yubico YubiKey 00 00".into(),
        None,
        PivAlgorithm::Rsa2048,
        cert,
        // No policy info plumbed in.
        None,
        None,
    ) {
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
    let result = classify_ssh_slot(
        0x9D,
        fake_guid(),
        "reader".into(),
        None,
        PivAlgorithm::EcP256,
        cert,
        None,
        None,
    );
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
    let result = classify_ssh_slot(
        0x9A,
        fake_guid(),
        "reader".into(),
        None,
        PivAlgorithm::Rsa2048,
        cert,
        None,
        None,
    );
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

#[test]
fn classify_slot_threads_policies_into_unsupported_record() {
    // Even when the slot is unsupported (RSA), the caller's policy
    // info should still appear on the record — useful for showing the
    // user *why* their RSA-in-retired-slot is unusable while still
    // surfacing the slot's other metadata.
    let guid = fake_guid();
    let cert: &[u8] = &[];
    match classify_slot(
        0x83,
        guid,
        "Yubico YubiKey 00 00".into(),
        None,
        PivAlgorithm::Rsa2048,
        cert,
        Some(PinPolicy::Once),
        Some(TouchPolicy::Cached),
    ) {
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
