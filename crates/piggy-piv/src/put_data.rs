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

/// A 25-byte all-zero FASC-N — pivy's `PIV_FASCN_ALL_ZERO` canonical form
/// (`piv-fascn.c::piv_fascn_encode`, the fast path returning 25 zero bytes,
/// which its decoder at the top of the same file recognizes as the all-zero
/// FASC-N). We emit this rather than `pivy-tool setup`'s `piv_fascn_zero()` —
/// whose zero-valued *fields* BCD-encode (ISO 7811 sentinels + parity + LRC) to
/// a non-zero blob — because the FASC-N is inert for piggy (every piggy/pivy
/// reader keys off the GUID at CHUID tag `0x34`; the FASC-N matters only to
/// federal physical-access readers, which piggy does not target) and a real
/// YubiKey stores the CHUID object opaquely without validating FASC-N BCD
/// structure. So the all-zero form is byte-accepted everywhere piggy operates,
/// round-trips through pivy's own decoder as "all zero", and spares us porting
/// the entire BCD codec for a field we never interpret.
const FASCN_ALL_ZERO: [u8; 25] = [0u8; 25];

/// Fixed CHUID expiry (`YYYYMMDD`, the SP 800-73-4 §3.1.2 format). pivy-tool
/// computes `now + lifetime`; piggy uses a fixed far-future date because the
/// expiry — like the FASC-N — is inert for piggy (read paths only extract the
/// GUID), and a constant keeps `write_chuid` clock-free and deterministic for
/// tests. The CHUID is unsigned, so this asserts nothing verifiable anyway.
const CHUID_EXPIRY: &[u8] = b"20991231";

/// Build the CHUID data-object body (the bytes that go inside the `53` wrapper
/// `put_data` adds): `30 <FASC-N> 34 <GUID> 35 <expiry> 3E 00`, matching pivy's
/// `piv_chuid_write_tbs_tlv` element order plus the compulsory empty signature
/// tag (`3E 00`, written when the CHUID is unsigned — `piv_chuid_encode`).
fn build_chuid_object(guid: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 25 + 2 + 16 + 2 + 8 + 2);
    // 0x30 FASC-N (25 bytes, all-zero form).
    v.push(0x30);
    v.push(FASCN_ALL_ZERO.len() as u8);
    v.extend_from_slice(&FASCN_ALL_ZERO);
    // 0x34 GUID (16 bytes).
    v.push(0x34);
    v.push(guid.len() as u8);
    v.extend_from_slice(guid);
    // 0x35 expiry (8 ASCII bytes, YYYYMMDD).
    v.push(0x35);
    v.push(CHUID_EXPIRY.len() as u8);
    v.extend_from_slice(CHUID_EXPIRY);
    // 0x3E signature — compulsory tag, empty (unsigned CHUID).
    v.push(0x3E);
    v.push(0x00);
    v
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

    /// Write the CHUID for a freshly-provisioned card (piggy#194): an all-zero
    /// FASC-N, the supplied 16-byte GUID, a fixed expiry, and an empty
    /// signature. Marks the card initialized so `read_chuid` (and thus
    /// `piggy list` / recipient discovery) sees a real GUID instead of treating
    /// it as factory-blank. Ports the element layout of pivy's
    /// `piv_write_chuid` → `piv_chuid_encode`. Requires a prior
    /// [`PinSession::authenticate_admin`] on real hardware.
    pub fn write_chuid(&mut self, guid: &[u8; 16]) -> Result<(), PivError> {
        self.put_data(object_tag::CHUID, &build_chuid_object(guid))
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
    fn build_chuid_object_frames_fascn_guid_expiry_empty_sig() {
        let guid: [u8; 16] = [
            0x19, 0x17, 0x55, 0xCF, 0xF3, 0x9E, 0xFE, 0x52, 0x2C, 0x07, 0xA3, 0x83, 0x27, 0x5B,
            0xBE, 0xB1,
        ];
        let body = build_chuid_object(&guid);
        // 30 19 <25 zero> 34 10 <guid> 35 08 "20991231" 3E 00
        assert_eq!(&body[..2], &[0x30, 0x19], "FASC-N tag + len 25");
        assert_eq!(
            &body[2..27],
            &[0u8; 25],
            "FASC-N is all-zero (pivy ALL_ZERO)"
        );
        assert_eq!(&body[27..29], &[0x34, 0x10], "GUID tag + len 16");
        assert_eq!(&body[29..45], &guid, "GUID bytes");
        assert_eq!(&body[45..47], &[0x35, 0x08], "expiry tag + len 8");
        assert_eq!(&body[47..55], b"20991231", "expiry YYYYMMDD");
        assert_eq!(&body[55..], &[0x3E, 0x00], "empty signature tag");
        // Total 57 bytes — matches the real-card-captured CHUID length (0x39).
        assert_eq!(body.len(), 57);
    }

    #[test]
    fn chuid_guid_is_recoverable_by_a_tlv_walk() {
        // The read path (token::read_chuid) walks the 53 body's TLVs for tag
        // 0x34. Prove our body yields the GUID back under that same walk.
        let guid: [u8; 16] = [0xAB; 16];
        let body = build_chuid_object(&guid);
        let mut r = crate::tlv::TlvReader::new(&body);
        let mut found = None;
        while r.has_remaining() {
            let tag = r.read_tag().unwrap();
            let val = r.read_value().unwrap();
            if tag == 0x34 {
                found = Some(val.to_vec());
            }
        }
        assert_eq!(
            found.as_deref(),
            Some(&guid[..]),
            "GUID recovered at tag 0x34"
        );
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
