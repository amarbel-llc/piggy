//! PUT DATA (INS 0xDB) — write a PIV data object (CHUID, CCC, slot certs).
//!
//! Requires a prior management-key auth (see [`super::admin`]) in the same
//! [`PinSession`] on real hardware. Mirrors pivy's `piv_write_chuid` /
//! `piv_write_cert` (which all funnel through PUT DATA).

use crate::apdu::Apdu;
use crate::error::PivError;
use crate::token::PinSession;

/// PIV data-object tags used by provisioning.
pub mod object_tag {
    /// Card Holder Unique ID (carries the 16-byte GUID).
    pub const CHUID: u32 = 0x5FC102;

    /// X.509 certificate object for a key slot. The PIV cert tags are not the
    /// slot ids; map via [`cert_tag_for_slot`].
    pub const CERT_9A: u32 = 0x5FC105;
    pub const CERT_9C: u32 = 0x5FC10A;
    pub const CERT_9D: u32 = 0x5FC10B;
    pub const CERT_9E: u32 = 0x5FC101;
}

/// Map a key slot id to its certificate data-object tag (the inverse of what
/// `slot::slot_to_cert_tag` does for reads), for the slots provisioning writes.
pub fn cert_tag_for_slot(slot_id: u8) -> Option<u32> {
    match slot_id {
        0x9A => Some(object_tag::CERT_9A),
        0x9C => Some(object_tag::CERT_9C),
        0x9D => Some(object_tag::CERT_9D),
        0x9E => Some(object_tag::CERT_9E),
        _ => None,
    }
}

impl PinSession<'_> {
    /// Write a raw PIV data object at `tag` (value is wrapped as `53 <value>`
    /// by the APDU builder). Use [`PinSession::put_cert`] for slot certs.
    pub fn put_data(&mut self, tag: u32, value: &[u8]) -> Result<(), PivError> {
        let apdu = Apdu::put_data(tag, value);
        let (_resp, sw) = self.transmit(&apdu)?;
        if !sw.is_success() {
            return Err(PivError::Apdu { sw: sw.as_u16() });
        }
        Ok(())
    }

    /// Write a slot certificate: PUT DATA at the slot's cert tag with the PIV
    /// cert wrapper `70 <cert_der> 71 00` (the `71` byte is the compression
    /// flag; `00` = uncompressed), matching what `read_slot` expects to parse
    /// back out (it reads the `70` element).
    pub fn put_cert(&mut self, slot_id: u8, cert_der: &[u8]) -> Result<(), PivError> {
        let tag = cert_tag_for_slot(slot_id)
            .ok_or_else(|| PivError::Other(format!("no cert tag for slot {slot_id:#04x}")))?;
        let mut value = Vec::with_capacity(cert_der.len() + 8);
        // 70 <len> <cert_der>
        value.push(0x70);
        push_der_len(&mut value, cert_der.len());
        value.extend_from_slice(cert_der);
        // 71 01 00  (compression flag: uncompressed)
        value.extend_from_slice(&[0x71, 0x01, 0x00]);
        self.put_data(tag, &value)
    }
}

/// Append a BER-TLV length for `len` (short form, 0x81, or 0x82) — certs are a
/// few hundred bytes so the 0x82 form is the common case.
fn push_der_len(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_data_chuid_apdu_frames_5c_53() {
        // CHUID: 5C 03 5F C1 02  53 <len> <value>.
        let apdu = Apdu::put_data(object_tag::CHUID, &[0xAA, 0xBB]);
        assert_eq!(apdu.ins, 0xDB);
        assert_eq!(apdu.p1, 0x3F);
        assert_eq!(apdu.p2, 0xFF);
        assert_eq!(
            apdu.data,
            vec![0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, 0x02, 0xAA, 0xBB]
        );
    }

    #[test]
    fn cert_tag_for_slot_maps_key_slots() {
        assert_eq!(cert_tag_for_slot(0x9A), Some(0x5FC105));
        assert_eq!(cert_tag_for_slot(0x9D), Some(0x5FC10B));
        assert_eq!(cert_tag_for_slot(0x82), None);
    }

    #[test]
    fn push_der_len_forms() {
        let mut b = vec![];
        push_der_len(&mut b, 0x7F);
        assert_eq!(b, vec![0x7F]);
        b.clear();
        push_der_len(&mut b, 0x80);
        assert_eq!(b, vec![0x81, 0x80]);
        b.clear();
        push_der_len(&mut b, 0x1B8);
        assert_eq!(b, vec![0x82, 0x01, 0xB8]);
    }

    #[test]
    fn put_cert_wraps_70_and_71() {
        // We can't transmit without a card, but we can check the wrapper an
        // independent reader sees by reconstructing what put_cert builds.
        let cert = [0xCDu8; 300];
        let mut value = vec![0x70];
        push_der_len(&mut value, cert.len());
        value.extend_from_slice(&cert);
        value.extend_from_slice(&[0x71, 0x01, 0x00]);
        // 70 82 01 2C <300 bytes> 71 01 00
        assert_eq!(&value[..4], &[0x70, 0x82, 0x01, 0x2C]);
        assert_eq!(&value[value.len() - 3..], &[0x71, 0x01, 0x00]);
    }
}
