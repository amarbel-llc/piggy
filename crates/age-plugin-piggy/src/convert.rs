//! `age-plugin-piggy convert <RECIPIENT>` — turn an existing piggy recipient
//! into its age recipient + identity strings, fully offline (no card).
//!
//! Accepts either a piggy markl recipient ID
//! (`piggy-recipient-v1@pivy_ecdh_p256_pub-…` or the bare blech32 body) or
//! the raw 33-byte compressed P-256 public key as hex. Prints:
//!
//! ```text
//! # recipient: age1piggy1…
//! AGE-PLUGIN-PIGGY-1…
//! ```
//!
//! The identity line is what you save (e.g. for `sops.age.keyFile` or
//! `age -i`); the `# recipient:` comment travels with it. Both encode only
//! the public key — the private key never leaves the card.
//!
//! A future `--generate` will read the public key from a live card via
//! `piggy-piv`; this offline `convert` covers users who already hold a
//! piggy recipient.

use std::io;
use std::str::FromStr;

use piggy_markl::{FormatId, Id};

use crate::bech32id::{encode_identity, encode_recipient};
use crate::p256_stanza::{COMPRESSED_BYTES, validate_compressed};

pub(crate) fn run(input: Option<&str>) -> io::Result<()> {
    let input = input.ok_or_else(|| usage_err("missing RECIPIENT argument".to_owned()))?;
    let pubkey = resolve_pubkey(input).map_err(usage_err)?;
    println!("# recipient: {}", encode_recipient(&pubkey));
    println!("{}", encode_identity(&pubkey));
    Ok(())
}

/// Resolve the input to a compressed P-256 public key, trying a markl ID
/// first, then raw hex.
fn resolve_pubkey(input: &str) -> Result<[u8; COMPRESSED_BYTES], String> {
    if let Ok(id) = Id::from_str(input) {
        return match id.format() {
            FormatId::PivyEcdhP256Pub => to_compressed(id.data()),
            other => Err(format!(
                "unsupported recipient format {other:?}; age-plugin-piggy is P-256/PIV only"
            )),
        };
    }

    if let Ok(bytes) = hex::decode(input.trim()) {
        return to_compressed(&bytes);
    }

    Err(format!(
        "could not parse {input:?} as a markl recipient ID or a 33-byte hex P-256 public key"
    ))
}

fn to_compressed(bytes: &[u8]) -> Result<[u8; COMPRESSED_BYTES], String> {
    let compressed: [u8; COMPRESSED_BYTES] = bytes
        .try_into()
        .map_err(|_| format!("expected a {COMPRESSED_BYTES}-byte compressed P-256 point"))?;
    validate_compressed(&compressed)
        .ok_or_else(|| "not a valid compressed P-256 public key".to_owned())?;
    Ok(compressed)
}

fn usage_err(message: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "age-plugin-piggy convert: {message}\n\
             usage: age-plugin-piggy convert <markl-recipient-id | 33-byte-hex-pubkey>"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
    use piggy_markl::PurposeId;
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
    fn resolves_a_markl_recipient_id() {
        let pk = pubkey();
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            pk.to_vec(),
        )
        .unwrap();
        assert_eq!(resolve_pubkey(&id.to_wire()).unwrap(), pk);
    }

    #[test]
    fn resolves_hex() {
        let pk = pubkey();
        assert_eq!(resolve_pubkey(&hex::encode(pk)).unwrap(), pk);
    }

    #[test]
    fn rejects_nonsense() {
        assert!(resolve_pubkey("definitely-not-a-key").is_err());
    }
}
