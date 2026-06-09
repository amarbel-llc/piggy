//! `age-plugin-piggy generate [--guid <GUID>]` — derive the age recipient +
//! identity from a PIV card's slot-9D public key.
//!
//! Read-only and PIN-free: it enumerates the card and reads slot 9D's
//! certificate (the same probe `piggy health` does), never decrypts. The
//! private key stays on the card — the identity carries only the public key.
//!
//! With several cards attached, pass `--guid <GUID>` to disambiguate
//! (GUIDs are what `piggy health` / `piggy pass recipients list-available`
//! print). The offline sibling `convert` takes an already-known recipient
//! instead of touching a card.

use std::io;

use p256::{PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use piggy_piv::PivContext;
use ssh_key::public::{EcdsaPublicKey, KeyData};

use crate::bech32id::{encode_identity, encode_recipient};
use crate::p256_stanza::COMPRESSED_BYTES;

/// PIV Key Management slot (ECDH), where piggy keeps its encryption key.
const SLOT_9D: u8 = 0x9d;

pub(crate) fn run(guid_hint: Option<&str>) -> io::Result<()> {
    let pubkey = read_slot_9d_compressed(guid_hint).map_err(to_io)?;
    println!("# recipient: {}", encode_recipient(&pubkey));
    println!("{}", encode_identity(&pubkey));
    Ok(())
}

fn read_slot_9d_compressed(guid_hint: Option<&str>) -> Result<[u8; COMPRESSED_BYTES], String> {
    let ctx = PivContext::new().map_err(|e| format!("PC/SC context: {e}"))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| format!("enumerate cards: {e}"))?;
    if tokens.is_empty() {
        return Err("no PIV card detected".to_owned());
    }

    let token = match guid_hint {
        Some(guid) => tokens
            .into_iter()
            .find(|t| t.guid().to_hex().eq_ignore_ascii_case(guid))
            .ok_or_else(|| format!("no attached card has GUID {guid}"))?,
        None => {
            if tokens.len() > 1 {
                let guids: Vec<String> = tokens.iter().map(|t| t.guid().to_hex()).collect();
                return Err(format!(
                    "{} cards attached; disambiguate with --guid <GUID> (attached: {})",
                    tokens.len(),
                    guids.join(", ")
                ));
            }
            tokens.into_iter().next().expect("non-empty checked above")
        }
    };

    let slot = token
        .read_slot(SLOT_9D)
        .map_err(|e| format!("read slot 9D: {e}"))?;
    let uncompressed = match slot.public_key().key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) => point.as_bytes().to_vec(),
        _ => return Err("slot 9D does not hold a NIST P-256 key".to_owned()),
    };
    compress(&uncompressed)
}

/// SEC1 bytes (compressed or uncompressed) → 33-byte compressed point.
fn compress(sec1: &[u8]) -> Result<[u8; COMPRESSED_BYTES], String> {
    let pubkey =
        PublicKey::from_sec1_bytes(sec1).map_err(|e| format!("slot 9D public key: {e}"))?;
    pubkey
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| "compressed point is not 33 bytes".to_owned())
}

fn to_io(message: String) -> io::Error {
    io::Error::other(format!("age-plugin-piggy generate: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use rand::rngs::OsRng;

    #[test]
    fn compress_accepts_uncompressed_and_round_trips() {
        let secret = SecretKey::random(&mut OsRng);
        let want = secret.public_key().to_encoded_point(true);
        let uncompressed = secret.public_key().to_encoded_point(false);

        let got = compress(uncompressed.as_bytes()).expect("compress");
        assert_eq!(&got[..], want.as_bytes());
    }
}
