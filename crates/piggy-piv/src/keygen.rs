//! On-card key generation — GENERATE ASYMMETRIC (INS 0x47).
//!
//! Mirrors pivy's `piv_generate` / `ykpiv_generate`. Generates a fresh key pair
//! in a slot and returns the new public key. Requires a prior management-key
//! auth (see [`super::admin`]) in the same [`PinSession`].
//!
//! The response is a `7F49 { 86 <point> }` template; for an EC key `<point>` is
//! the SEC1 uncompressed point `04 || X || Y` (65 bytes for P-256, 97 for
//! P-384). The caller turns that into a recipient / self-signed cert.

use crate::apdu::Apdu;
use crate::error::PivError;
use crate::tlv::TlvReader;
use crate::token::PinSession;

/// YubicoPIV PIN/touch policy bytes for GENERATE ASYMMETRIC (`AA`/`AB` tags).
pub mod policy_byte {
    pub const PIN_DEFAULT: u8 = 0x00;
    pub const PIN_NEVER: u8 = 0x01;
    pub const PIN_ONCE: u8 = 0x02;
    pub const PIN_ALWAYS: u8 = 0x03;

    pub const TOUCH_DEFAULT: u8 = 0x00;
    pub const TOUCH_NEVER: u8 = 0x01;
    pub const TOUCH_ALWAYS: u8 = 0x02;
    pub const TOUCH_CACHED: u8 = 0x03;
}

impl PinSession<'_> {
    /// Generate a new key pair in `slot_id` with PIV algorithm byte `key_alg`
    /// (e.g. [`crate::apdu::alg::ECCP256`]). `pin_policy` / `touch_policy` are
    /// the optional YubicoPIV policy bytes (see [`policy_byte`]); `None` leaves
    /// the card default. Returns the new public key as raw SEC1 bytes (the
    /// `86` element of the `7F49` response).
    ///
    /// Requires a prior [`PinSession::authenticate_admin`] in this session.
    pub fn generate_key(
        &mut self,
        slot_id: u8,
        key_alg: u8,
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Result<Vec<u8>, PivError> {
        let apdu = Apdu::generate_asym(slot_id, key_alg, pin_policy, touch_policy);
        let (resp, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        parse_generated_pubkey(&resp)
    }
}

/// Extract the public-key bytes from a GENERATE ASYMMETRIC response:
/// `7F49 { 86 <point> [, …] }`.
fn parse_generated_pubkey(resp: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut r = TlvReader::new(resp);
    let tag = r.read_tag()?;
    if tag != 0x7F49 {
        return Err(PivError::Tlv {
            message: format!("generate: expected response template 0x7F49, got {tag:#X}"),
        });
    }
    let inner = r.read_value()?;
    let mut ir = TlvReader::new(inner);
    while ir.has_remaining() {
        let t = ir.read_tag()?;
        let v = ir.read_value()?;
        // 0x86 = ECC point; 0x81/0x82 = RSA modulus/exponent (unused here).
        if t == 0x86 {
            return Ok(v.to_vec());
        }
    }
    Err(PivError::Tlv {
        message: "generate: no public-key point (tag 0x86) in 0x7F49 response".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::{alg, slot_id};

    #[test]
    fn generate_apdu_eccp256_9d_matches_wire() {
        // No policy bytes: AC { 80 11 } → 00 47 00 9D 05 AC 03 80 01 11.
        let apdu = Apdu::generate_asym(slot_id::KEY_MGMT, alg::ECCP256, None, None);
        assert_eq!(apdu.ins, 0x47);
        assert_eq!(apdu.p2, 0x9D);
        assert_eq!(apdu.data, vec![0xAC, 0x03, 0x80, 0x01, 0x11]);
    }

    #[test]
    fn generate_apdu_includes_policy_bytes() {
        let apdu = Apdu::generate_asym(
            slot_id::PIV_AUTH,
            alg::ECCP256,
            Some(policy_byte::PIN_ONCE),
            Some(policy_byte::TOUCH_CACHED),
        );
        // AC { 80 01 11, AA 01 02, AB 01 03 }.
        assert_eq!(
            apdu.data,
            vec![
                0xAC, 0x09, 0x80, 0x01, 0x11, 0xAA, 0x01, 0x02, 0xAB, 0x01, 0x03
            ]
        );
    }

    #[test]
    fn parse_generated_pubkey_extracts_p256_point() {
        // 7F49 { 86 41 04 || X(32) || Y(32) } — the fibby/real-card shape.
        let mut point = vec![0x04u8];
        point.extend_from_slice(&[0xAB; 64]);
        let mut body = vec![0x86, 0x41];
        body.extend_from_slice(&point);
        let mut wire = vec![0x7F, 0x49, body.len() as u8];
        wire.extend_from_slice(&body);

        let got = parse_generated_pubkey(&wire).unwrap();
        assert_eq!(got, point);
        assert_eq!(got.len(), 65);
    }

    #[test]
    fn parse_generated_pubkey_rejects_wrong_template() {
        let wire = [0x53, 0x02, 0x86, 0x00];
        assert!(parse_generated_pubkey(&wire).is_err());
    }
}
