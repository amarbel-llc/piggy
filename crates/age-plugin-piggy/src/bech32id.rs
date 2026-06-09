//! Bech32 encoding of piggy age recipients and identities.
//!
//! Matches age's plugin convention byte-for-byte (see
//! `age_plugin::print_new_identity`): the recipient HRP is `age1piggy`, the
//! identity HRP is `age-plugin-piggy-` (the whole string then uppercased),
//! both with [`Variant::Bech32`] (not Bech32m). Recipient and identity both
//! encode the 33-byte compressed P-256 public key — the identity carries no
//! private key (it stays on the card).
//!
//! Hand-rolled rather than calling `print_new_identity` so the functions are
//! pure (no stdout, no clock) and testable.

use bech32::{ToBase32, Variant};

use crate::PLUGIN_NAME;
use crate::p256_stanza::COMPRESSED_BYTES;

fn recipient_hrp() -> String {
    format!("age1{PLUGIN_NAME}")
}

fn identity_hrp() -> String {
    // Lowercase for `bech32::encode` (it rejects mixed/upper HRPs); the
    // encoded string is uppercased afterwards, and `bech32::decode` returns
    // the HRP lowercased again — so this same value is used on both sides.
    format!("age-plugin-{PLUGIN_NAME}-")
}

/// `age1piggy1…` for a compressed P-256 pubkey.
pub(crate) fn encode_recipient(pubkey: &[u8; COMPRESSED_BYTES]) -> String {
    bech32::encode(&recipient_hrp(), pubkey.to_base32(), Variant::Bech32).expect("HRP is valid")
}

/// `AGE-PLUGIN-PIGGY-1…` for a compressed P-256 pubkey.
pub(crate) fn encode_identity(pubkey: &[u8; COMPRESSED_BYTES]) -> String {
    bech32::encode(&identity_hrp(), pubkey.to_base32(), Variant::Bech32)
        .expect("HRP is valid")
        .to_uppercase()
}

// The runtime never decodes these strings itself — age decodes the Bech32 and
// hands `add_recipient` / `add_identity` the raw bytes. So the decoders exist
// only to round-trip-test the encoders; gate them to the test build.

/// Decode an `age1piggy…` recipient back to its compressed pubkey.
#[cfg(test)]
pub(crate) fn decode_recipient(s: &str) -> Option<[u8; COMPRESSED_BYTES]> {
    decode_with_hrp(s, &recipient_hrp())
}

/// Decode an `AGE-PLUGIN-PIGGY-…` identity back to its compressed pubkey.
#[cfg(test)]
pub(crate) fn decode_identity(s: &str) -> Option<[u8; COMPRESSED_BYTES]> {
    decode_with_hrp(s, &identity_hrp())
}

#[cfg(test)]
fn decode_with_hrp(s: &str, expected_hrp: &str) -> Option<[u8; COMPRESSED_BYTES]> {
    use crate::p256_stanza::validate_compressed;
    use bech32::FromBase32;

    let (hrp, data, variant) = bech32::decode(s).ok()?;
    if variant != Variant::Bech32 || hrp != expected_hrp {
        return None;
    }
    let bytes = Vec::<u8>::from_base32(&data).ok()?;
    let compressed: [u8; COMPRESSED_BYTES] = bytes.try_into().ok()?;
    validate_compressed(&compressed)?;
    Some(compressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
    use rand::rngs::OsRng;

    fn pubkey() -> [u8; COMPRESSED_BYTES] {
        let point = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(true);
        let mut compressed = [0u8; COMPRESSED_BYTES];
        compressed.copy_from_slice(point.as_bytes());
        compressed
    }

    #[test]
    fn recipient_round_trips_with_expected_hrp() {
        let pk = pubkey();
        let encoded = encode_recipient(&pk);
        assert!(
            encoded.starts_with("age1piggy1"),
            "recipient HRP must be age1piggy: {encoded}"
        );
        assert_eq!(decode_recipient(&encoded), Some(pk));
    }

    #[test]
    fn identity_round_trips_with_expected_hrp() {
        let pk = pubkey();
        let encoded = encode_identity(&pk);
        assert!(
            encoded.starts_with("AGE-PLUGIN-PIGGY-1"),
            "identity HRP must be AGE-PLUGIN-PIGGY-: {encoded}"
        );
        assert_eq!(decode_identity(&encoded), Some(pk));
    }

    #[test]
    fn decode_rejects_wrong_hrp() {
        let pk = pubkey();
        // A recipient string is not a valid identity and vice versa.
        assert_eq!(decode_identity(&encode_recipient(&pk)), None);
        assert_eq!(decode_recipient(&encode_identity(&pk)), None);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert_eq!(decode_recipient("not-bech32"), None);
        assert_eq!(decode_identity("AGE-PLUGIN-PIGGY-1qqqq"), None);
    }
}
