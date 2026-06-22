//! PIV management-key authentication — the gate that unlocks every write
//! operation (GENERATE ASYMMETRIC, PUT DATA, key/PIN management) for the rest
//! of a [`PinSession`]'s transaction.
//!
//! Mirrors pivy's `piv_auth_admin` (`vendor/pivy/src/piv.c`). The exchange is a
//! GENERAL AUTHENTICATE (INS 0x87) against the management key in PIV slot 9B:
//!
//! 1. **request a witness** — data `7C { 81 (empty) }` → card returns
//!    `7C { 81 <witness> }` (one cipher block: 8 bytes for 3DES);
//! 2. **answer it** — encrypt the witness under the management key and reply
//!    `7C { 82 <enc> }` → `9000` on success, `6982` on a wrong key.
//!
//! Only the 3-key 3DES management key (the factory default, and what the fibby
//! virtual card models) is supported today. AES management keys (the YubicoPIV
//! 5.7+ default) are a follow-up — [`PinSession::authenticate_admin`] errors
//! clearly on any other algorithm rather than mis-authenticating.

use openssl::symm::{Cipher, Crypter, Mode};

use crate::apdu::{Apdu, alg, ga_tag};
use crate::error::PivError;
use crate::tlv::{TlvReader, TlvWriter};
use crate::token::PinSession;

/// PIV management-key slot.
const SLOT_MGMT: u8 = 0x9B;

/// The 3-key 3DES factory-default management key (`01 02 … 08` repeated three
/// times) shipped on every fresh YubiKey. pivy's `DEFAULT_ADMIN_KEY`.
pub const DEFAULT_ADMIN_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

impl PinSession<'_> {
    /// Authenticate to the management key (PIV slot 9B) so subsequent write
    /// operations in this session are permitted. `key_alg` must be
    /// [`alg::TDEA_3KEY`] (`0x03`) today.
    ///
    /// Returns `PivError::ManagementAuthFailed` on a wrong key (SW 6982), or a
    /// `PivError::Apdu` for any other non-success status.
    pub fn authenticate_admin(&mut self, key: &[u8], key_alg: u8) -> Result<(), PivError> {
        if key_alg != alg::TDEA_3KEY {
            return Err(PivError::Other(format!(
                "management-key algorithm {key_alg:#04x} is not supported \
                 (only 3-key 3DES, 0x03)"
            )));
        }
        if key.len() != 24 {
            return Err(PivError::Other(format!(
                "3DES management key must be 24 bytes, got {}",
                key.len()
            )));
        }

        // Phase 1 — request the card's witness. Data = 7C { 81 (empty) }.
        let witness = {
            let apdu =
                Apdu::general_authenticate(key_alg, SLOT_MGMT, &ga_request(ga_tag::CHALLENGE, &[]));
            let (resp, sw) = self.transmit(&apdu)?;
            if !sw.is_success() {
                return Err(PivError::Apdu { sw: sw.as_u16() });
            }
            parse_witness(&resp)?
        };

        // Encrypt the witness under the management key (3DES-EDE3, one ECB
        // block — the card decrypts it and compares to the witness it issued).
        let enc = des3_ecb_encrypt(key, &witness)?;

        // Phase 2 — answer with the encrypted witness. Data = 7C { 82 <enc> }.
        let apdu =
            Apdu::general_authenticate(key_alg, SLOT_MGMT, &ga_request(ga_tag::RESPONSE, &enc));
        let (_resp, sw) = self.transmit(&apdu)?;
        if sw.as_u16() == 0x6982 {
            return Err(PivError::ManagementAuthFailed);
        }
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }
}

/// Build the GENERAL AUTHENTICATE data field `7C { <tag> <value> }`.
fn ga_request(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut inner = TlvWriter::new();
    inner.write_tag_value(tag as u32, value);
    let mut outer = TlvWriter::new();
    outer.write_tag_value(0x7C, inner.as_bytes());
    outer.into_vec()
}

/// Parse `7C { 81 <witness> }` and return the witness bytes.
fn parse_witness(resp: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut r = TlvReader::new(resp);
    let tag = r.read_tag()?;
    if tag != 0x7C {
        return Err(PivError::Tlv {
            message: format!("admin auth: expected dynamic-auth tag 0x7C, got {tag:#X}"),
        });
    }
    let inner = r.read_value()?;
    let mut ir = TlvReader::new(inner);
    let itag = ir.read_tag()?;
    if itag != ga_tag::CHALLENGE as u32 {
        return Err(PivError::Tlv {
            message: format!("admin auth: expected witness tag 0x81, got {itag:#X}"),
        });
    }
    Ok(ir.read_value()?.to_vec())
}

/// 3DES-EDE3 ECB single-block encryption, no padding. The witness is exactly
/// one 8-byte block.
fn des3_ecb_encrypt(key: &[u8], block: &[u8]) -> Result<Vec<u8>, PivError> {
    let cipher = Cipher::des_ede3();
    let mut c = Crypter::new(cipher, Mode::Encrypt, key, None)
        .map_err(|e| PivError::Other(format!("3DES init: {e}")))?;
    c.pad(false);
    let mut out = vec![0u8; block.len() + cipher.block_size()];
    let mut n = c
        .update(block, &mut out)
        .map_err(|e| PivError::Other(format!("3DES encrypt: {e}")))?;
    n += c
        .finalize(&mut out[n..])
        .map_err(|e| PivError::Other(format!("3DES finalize: {e}")))?;
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ga_request_witness_request_matches_wire() {
        // Phase-1 witness request must be exactly `7C 02 81 00`.
        assert_eq!(
            ga_request(ga_tag::CHALLENGE, &[]),
            vec![0x7C, 0x02, 0x81, 0x00]
        );
    }

    #[test]
    fn ga_request_response_frames_encrypted_witness() {
        // Phase-2 with an 8-byte block must be `7C 0A 82 08 <8 bytes>`.
        let enc = [0xAA; 8];
        let got = ga_request(ga_tag::RESPONSE, &enc);
        assert_eq!(&got[..4], &[0x7C, 0x0A, 0x82, 0x08]);
        assert_eq!(&got[4..], &enc);
    }

    #[test]
    fn parse_witness_extracts_eight_bytes() {
        let wire = [0x7C, 0x0A, 0x81, 0x08, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(parse_witness(&wire).unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn des3_ecb_round_trips_against_independent_decrypt() {
        // Encrypt a witness; an independent 3DES-EDE3 ECB decrypt must recover
        // it — the exact check the card (and fibby) performs in phase 2.
        let witness = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let enc = des3_ecb_encrypt(&DEFAULT_ADMIN_KEY, &witness).unwrap();
        assert_eq!(enc.len(), 8);

        let cipher = Cipher::des_ede3();
        let mut d = Crypter::new(cipher, Mode::Decrypt, &DEFAULT_ADMIN_KEY, None).unwrap();
        d.pad(false);
        let mut out = vec![0u8; enc.len() + cipher.block_size()];
        let mut n = d.update(&enc, &mut out).unwrap();
        n += d.finalize(&mut out[n..]).unwrap();
        out.truncate(n);
        assert_eq!(out, witness);
    }

    #[test]
    fn default_admin_key_is_the_factory_3des_key() {
        assert_eq!(DEFAULT_ADMIN_KEY.len(), 24);
        assert_eq!(&DEFAULT_ADMIN_KEY[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&DEFAULT_ADMIN_KEY[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&DEFAULT_ADMIN_KEY[16..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
