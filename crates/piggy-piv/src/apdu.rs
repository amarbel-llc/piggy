use crate::tlv::TlvWriter;

/// PIV application AID (NIST SP 800-73-4)
pub const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// YubiKey PIV management AID
pub const YKPIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Data object tag for the YubiKey attestation certificate (slot F9)
pub const PIV_TAG_CERT_YK_ATTESTATION: u32 = 0x5FFF01;

/// ISO 7816-4 instruction codes
pub mod ins {
    pub const SELECT: u8 = 0xA4;
    pub const GET_DATA: u8 = 0xCB;
    pub const VERIFY: u8 = 0x20;
    pub const CHANGE_PIN: u8 = 0x24;
    pub const RESET_PIN: u8 = 0x2C;
    pub const GEN_AUTH: u8 = 0x87;
    pub const PUT_DATA: u8 = 0xDB;
    pub const GEN_ASYM: u8 = 0x47;
    pub const CONTINUE: u8 = 0xC0;
    pub const YK_ATTEST: u8 = 0xF9;
    /// YubicoPIV vendor-specific: read the YubiKey factory serial as
    /// a 4-byte big-endian u32 against the already-selected PIV
    /// applet. Mirrors pivy's `INS_GET_SERIAL` (vendor/pivy/src/piv.c
    /// `ykpiv_read_serial`). Non-YubiKey cards reject the INS with a
    /// non-9000 status word; callers treat that as "no serial".
    pub const YK_GET_SERIAL: u8 = 0xF8;
}

/// PIV slot IDs
pub mod slot_id {
    pub const PIV_AUTH: u8 = 0x9A;
    pub const SIGNATURE: u8 = 0x9C;
    pub const KEY_MGMT: u8 = 0x9D;
    pub const CARD_AUTH: u8 = 0x9E;
    // Retired key management slots
    pub const RETIRED_1: u8 = 0x82;
    pub const RETIRED_20: u8 = 0x95;
}

/// PIV algorithm identifiers
pub mod alg {
    pub const TDEA_3KEY: u8 = 0x03;
    pub const AES128: u8 = 0x08;
    pub const AES192: u8 = 0x0A;
    pub const AES256: u8 = 0x0C;
    pub const RSA1024: u8 = 0x06;
    pub const RSA2048: u8 = 0x07;
    pub const ECCP256: u8 = 0x11;
    pub const ECCP384: u8 = 0x14;
    // Ed25519 / X25519 are YubicoPIV proprietary extensions (firmware 5.7+),
    // not NIST SP 800-78. Bytes match Yubico/yubico-piv-tool/lib/ykpiv.h.
    pub const ED25519: u8 = 0xE0;
    pub const X25519: u8 = 0xE1;
}

/// GENERAL AUTHENTICATE dynamic template tags
pub mod ga_tag {
    pub const WITNESS: u8 = 0x80;
    pub const CHALLENGE: u8 = 0x81;
    pub const RESPONSE: u8 = 0x82;
    pub const EXPONENT: u8 = 0x85;
}

/// ISO 7816-4 APDU (Application Protocol Data Unit)
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u16>,
}

impl Apdu {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// SELECT command to activate a PIV applet by AID
    pub fn select(aid: &[u8]) -> Self {
        Self {
            cla: 0x00,
            ins: ins::SELECT,
            p1: 0x04, // Select by AID
            p2: 0x00,
            data: aid.to_vec(),
            le: None,
        }
    }

    /// GET DATA command to read a PIV data object by tag
    pub fn get_data(tag: u32) -> Self {
        // Wrap the tag in a 5C TLV for the GET DATA command
        let mut tlv = TlvWriter::new();
        let tag_bytes = tag_to_bytes(tag);
        tlv.write_tag_value(0x5C, &tag_bytes);

        Self {
            cla: 0x00,
            ins: ins::GET_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: tlv.into_vec(),
            le: None,
        }
    }

    /// GENERAL AUTHENTICATE command for signing/key agreement
    pub fn general_authenticate(alg: u8, slot: u8, data: &[u8]) -> Self {
        Self {
            cla: 0x00,
            ins: ins::GEN_AUTH,
            p1: alg,
            p2: slot,
            data: data.to_vec(),
            le: None,
        }
    }

    /// GENERATE ASYMMETRIC (INS 0x47) — generate a new key pair on `slot`.
    ///
    /// Data is the `AC` template `{ 80 <key_alg> }`, optionally followed by the
    /// YubicoPIV `AA <pin_policy>` / `AB <touch_policy>` policy bytes. The
    /// response carries the new public key in a `7F49 { 86 <point> }` template.
    /// Requires a prior management-key auth (see [`super::admin`]).
    pub fn generate_asym(
        slot: u8,
        key_alg: u8,
        pin_policy: Option<u8>,
        touch_policy: Option<u8>,
    ) -> Self {
        let mut tmpl = TlvWriter::new();
        tmpl.write_tag_value(0x80, &[key_alg]);
        if let Some(p) = pin_policy {
            tmpl.write_tag_value(0xAA, &[p]);
        }
        if let Some(t) = touch_policy {
            tmpl.write_tag_value(0xAB, &[t]);
        }
        let mut outer = TlvWriter::new();
        outer.write_tag_value(0xAC, tmpl.as_bytes());
        Self {
            cla: 0x00,
            ins: ins::GEN_ASYM,
            p1: 0x00,
            p2: slot,
            data: outer.into_vec(),
            le: None,
        }
    }

    /// PUT DATA (INS 0xDB) — write a PIV data object at `tag` (e.g. the CHUID
    /// `5FC102` or a slot cert). Wraps `value` as `5C <tag>` + `53 <value>`.
    /// Requires a prior management-key auth on real hardware.
    pub fn put_data(tag: u32, value: &[u8]) -> Self {
        let mut w = TlvWriter::new();
        w.write_tag_value(0x5C, &tag_to_bytes(tag));
        w.write_tag_value(0x53, value);
        Self {
            cla: 0x00,
            ins: ins::PUT_DATA,
            p1: 0x3F,
            p2: 0xFF,
            data: w.into_vec(),
            le: None,
        }
    }

    /// YubiKey ATTEST command — generates an attestation certificate for a slot.
    pub fn yk_attest(slot: u8) -> Self {
        Self {
            cla: 0x00,
            ins: ins::YK_ATTEST,
            p1: slot,
            p2: 0x00,
            data: Vec::new(),
            le: None,
        }
    }

    /// VERIFY PIN command. PIN is padded to 8 bytes with 0xFF.
    ///
    /// Panics if `pin` is longer than 8 bytes. PIV PINs are 6-8 digits;
    /// silently truncating a longer value would waste a retry attempt on
    /// an invalid PIN.
    pub fn verify_pin(pin: &[u8]) -> Self {
        assert!(
            pin.len() <= 8,
            "PIV PIN must be at most 8 bytes, got {}",
            pin.len()
        );
        let mut padded = [0xFF_u8; 8];
        padded[..pin.len()].copy_from_slice(pin);

        Self {
            cla: 0x00,
            ins: ins::VERIFY,
            p1: 0x00,
            p2: 0x80, // PIV PIN
            data: padded.to_vec(),
            le: None,
        }
    }

    /// Encode APDU to ISO 7816-4 byte format.
    ///
    /// Uses short encoding when data fits in a single Lc byte (≤255).
    /// Switches to extended-length encoding (3-byte Lc: 0x00 + u16 BE)
    /// when data exceeds 255 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data_len = self.data.len();
        let extended = data_len > 255 || matches!(self.le, Some(le) if le > 256);
        let mut buf = Vec::with_capacity(7 + data_len + 3);
        buf.push(self.cla);
        buf.push(self.ins);
        buf.push(self.p1);
        buf.push(self.p2);

        if extended {
            buf.push(0x00); // extended-length marker
            if !self.data.is_empty() {
                buf.push((data_len >> 8) as u8);
                buf.push((data_len & 0xFF) as u8);
                buf.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                buf.push((le >> 8) as u8);
                buf.push((le & 0xFF) as u8);
            }
        } else {
            if !self.data.is_empty() {
                buf.push(data_len as u8);
                buf.extend_from_slice(&self.data);
            }
            if let Some(le) = self.le {
                if le >= 256 {
                    buf.push(0x00);
                } else {
                    buf.push(le as u8);
                }
            }
        }

        buf
    }
}

/// Status word from a smartcard response (SW1-SW2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusWord(pub u8, pub u8);

impl StatusWord {
    pub fn from_bytes(sw1: u8, sw2: u8) -> Self {
        Self(sw1, sw2)
    }

    pub fn is_success(&self) -> bool {
        self.0 == 0x90 && self.1 == 0x00
    }

    pub fn as_u16(&self) -> u16 {
        (self.0 as u16) << 8 | self.1 as u16
    }

    /// SW 61xx: more data available
    pub fn has_more_data(&self) -> bool {
        self.0 == 0x61
    }

    /// Number of remaining bytes when has_more_data() is true.
    /// SW2=0x00 means 256 per ISO 7816-4.
    pub fn remaining_bytes(&self) -> u16 {
        if self.1 == 0 { 256 } else { self.1 as u16 }
    }

    /// SW 63Cx: wrong PIN, x = retries remaining
    pub fn is_pin_incorrect(&self) -> bool {
        self.0 == 0x63 && (self.1 & 0xF0) == 0xC0
    }

    /// Retries remaining if is_pin_incorrect(), else None
    pub fn pin_retries_remaining(&self) -> Option<u8> {
        if self.is_pin_incorrect() {
            Some(self.1 & 0x0F)
        } else {
            None
        }
    }
}

impl std::fmt::Display for StatusWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#06X}", self.as_u16())
    }
}

/// Encode a data object tag as minimal big-endian bytes
fn tag_to_bytes(tag: u32) -> Vec<u8> {
    if tag == 0 {
        return vec![0];
    }
    let bytes = tag.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    bytes[start..].to_vec()
}
