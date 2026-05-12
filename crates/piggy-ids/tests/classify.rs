//! Unit tests for `piggy_ids::classify_slot_9d`. No PIV context needed —
//! we feed synthetic algorithm values and cert bytes.

use piggy_ids::{classify_slot_9d, Classification};
use piggy_piv::{Guid, PivAlgorithm};

fn fake_guid() -> Guid {
    Guid::from_hex("00112233445566778899aabbccddeeff").expect("valid hex")
}

#[test]
fn rsa_in_9d_is_unsupported() {
    let guid = fake_guid();
    let cert: &[u8] = &[]; // irrelevant when algorithm rejects the slot
    match classify_slot_9d(guid, PivAlgorithm::Rsa2048, cert) {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.starts_with("slot 9D is"),
                "reason missing expected prefix 'slot 9D is': {reason}"
            );
            assert!(
                reason.contains("Rsa2048"),
                "reason missing algorithm name 'Rsa2048': {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn malformed_cert_in_9d_is_unsupported() {
    let guid = fake_guid();
    let cert: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF]; // not a valid X.509 cert
    match classify_slot_9d(guid, PivAlgorithm::EcP256, cert) {
        Classification::Unsupported { reason, .. } => {
            assert!(
                reason.starts_with("pubkey decode failed:"),
                "reason missing expected prefix 'pubkey decode failed:': {reason}"
            );
            assert!(
                reason.contains("decode"),
                "reason missing inner 'decode' substring: {reason}"
            );
        }
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
