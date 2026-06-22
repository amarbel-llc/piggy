//! PIN/PUK change + management-key rotation — the credential-hardening write
//! ops a full provision (piggy#194 full setup) performs after generating keys,
//! so a freshly-provisioned card ends with known, non-default secrets.
//!
//! - CHANGE REFERENCE DATA (INS 0x24): replace the PIV PIN (P2=0x80) or PUK
//!   (P2=0x81). Data is `old‖new`, each padded to 8 bytes with 0xFF (the same
//!   reference-data block VERIFY uses). Takes the OLD value directly — no prior
//!   VERIFY needed.
//! - SET MANAGEMENT KEY (YubicoPIV INS 0xFF): set a new 3DES admin key. Data is
//!   `<alg> <0x9B> <key_len> <key>`. Requires a prior
//!   [`PinSession::authenticate_admin`] in the same session.
//!
//! AES management keys (YubicoPIV 5.7+) are a follow-up, mirroring the 3DES-only
//! limitation in [`super::admin`].

use crate::apdu::{Apdu, alg, ins};
use crate::error::PivError;
use crate::token::PinSession;

/// PIV management-key slot reference.
const SLOT_MGMT: u8 = 0x9B;
/// CHANGE REFERENCE DATA P2 for the PIV PIN.
const P2_PIN: u8 = 0x80;
/// CHANGE REFERENCE DATA P2 for the PUK.
const P2_PUK: u8 = 0x81;

impl PinSession<'_> {
    /// Change the PIV PIN (CHANGE REFERENCE DATA, P2=0x80).
    pub fn change_pin(&mut self, old: &str, new: &str) -> Result<(), PivError> {
        self.change_reference_data(P2_PIN, old.as_bytes(), new.as_bytes())
    }

    /// Change the PUK (CHANGE REFERENCE DATA, P2=0x81).
    pub fn change_puk(&mut self, old: &str, new: &str) -> Result<(), PivError> {
        self.change_reference_data(P2_PUK, old.as_bytes(), new.as_bytes())
    }

    fn change_reference_data(&mut self, p2: u8, old: &[u8], new: &[u8]) -> Result<(), PivError> {
        let apdu = change_reference_data_apdu(p2, old, new)?;
        let (_resp, sw) = self.transmit(&apdu)?;
        if sw.is_pin_incorrect() {
            return Err(PivError::PinIncorrect {
                retries: sw.pin_retries_remaining().unwrap_or(0) as u32,
            });
        }
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }

    /// Set a new 3-key 3DES management key (YubicoPIV SET MANAGEMENT KEY).
    /// Requires a prior [`PinSession::authenticate_admin`] in this session.
    pub fn set_management_key_3des(&mut self, key: &[u8]) -> Result<(), PivError> {
        let apdu = set_management_key_apdu(key)?;
        let (_resp, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }
}

/// Pad a PIN/PUK to the 8-byte PIV reference-data block with trailing 0xFF.
fn pad_reference(s: &[u8]) -> Result<[u8; 8], PivError> {
    if s.len() > 8 {
        return Err(PivError::Other(format!(
            "PIN/PUK must be at most 8 bytes, got {}",
            s.len()
        )));
    }
    if s.is_empty() {
        return Err(PivError::Other("PIN/PUK must not be empty".into()));
    }
    let mut b = [0xFFu8; 8];
    b[..s.len()].copy_from_slice(s);
    Ok(b)
}

/// CHANGE REFERENCE DATA APDU: `00 24 00 <p2> 10 <old8> <new8>`.
fn change_reference_data_apdu(p2: u8, old: &[u8], new: &[u8]) -> Result<Apdu, PivError> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&pad_reference(old)?);
    data.extend_from_slice(&pad_reference(new)?);
    let mut apdu = Apdu::new(0x00, ins::CHANGE_PIN, 0x00, p2);
    apdu.data = data;
    Ok(apdu)
}

/// SET MANAGEMENT KEY APDU: `00 FF FF FF <Lc> 03 9B 18 <24-byte key>`.
fn set_management_key_apdu(key: &[u8]) -> Result<Apdu, PivError> {
    if key.len() != 24 {
        return Err(PivError::Other(format!(
            "3DES management key must be 24 bytes, got {}",
            key.len()
        )));
    }
    let mut data = Vec::with_capacity(3 + 24);
    data.push(alg::TDEA_3KEY); // 0x03
    data.push(SLOT_MGMT); // 0x9B
    data.push(key.len() as u8); // 0x18
    data.extend_from_slice(key);
    let mut apdu = Apdu::new(0x00, ins::SET_MGMT_KEY, 0xFF, 0xFF);
    apdu.data = data;
    Ok(apdu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_pin_apdu_frames_old_new_padded() {
        let apdu = change_reference_data_apdu(P2_PIN, b"123456", b"654321").unwrap();
        assert_eq!(apdu.ins, 0x24);
        assert_eq!(apdu.p1, 0x00);
        assert_eq!(apdu.p2, 0x80);
        // old "123456" + FF FF, then new "654321" + FF FF.
        assert_eq!(
            apdu.data,
            vec![
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
                0xFF, 0xFF
            ]
        );
    }

    #[test]
    fn change_puk_apdu_uses_p2_81() {
        let apdu = change_reference_data_apdu(P2_PUK, b"12345678", b"87654321").unwrap();
        assert_eq!(apdu.p2, 0x81);
        // Full 8-byte PUK: no padding bytes.
        assert_eq!(&apdu.data[..8], b"12345678");
        assert_eq!(&apdu.data[8..], b"87654321");
    }

    #[test]
    fn pad_reference_rejects_oversized_and_empty() {
        assert!(pad_reference(b"123456789").is_err());
        assert!(pad_reference(b"").is_err());
    }

    #[test]
    fn set_mgmt_key_apdu_frames_03_9b_18() {
        let key = [0xABu8; 24];
        let apdu = set_management_key_apdu(&key).unwrap();
        assert_eq!(apdu.ins, 0xFF);
        assert_eq!(apdu.p1, 0xFF);
        assert_eq!(apdu.p2, 0xFF);
        assert_eq!(&apdu.data[..3], &[0x03, 0x9B, 0x18]);
        assert_eq!(&apdu.data[3..], &key);
    }

    #[test]
    fn set_mgmt_key_rejects_wrong_length() {
        assert!(set_management_key_apdu(&[0u8; 16]).is_err());
    }
}
