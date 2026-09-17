//! PIV Printed Information object (tag `5FC109`) — read and parse.
//!
//! The Printed Information object holds the human-readable fields printed on a
//! PIV card (SP 800-73-4 §3.1.6): cardholder name, employee affiliation, card
//! expiry, agency serial, issuer, and organization lines, plus a YubicoPIV
//! extension that can escrow the management key. `pivy-tool pinfo` reads and
//! prints it; this module is the read half of that port.
//!
//! Body (inside the `53` wrapper): a flat sequence of BER-TLVs —
//! `01`=name, `02`=affiliation, `04`=expiry, `05`=serial, `06`=issuer,
//! `07`=org line 1, `08`=org line 2, and a nested `88 { 89 <admin-key> }`
//! YubicoPIV extension.

/// PIV Printed Information data-object tag.
pub const PINFO_TAG: u32 = 0x5FC109;

/// The parsed Printed Information object. Every printed field is optional (a
/// card may populate only some); `has_admin_key` records whether the
/// YubicoPIV `88 { 89 … }` management-key escrow is present.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pinfo {
    pub name: Option<String>,
    pub affiliation: Option<String>,
    pub expiry: Option<String>,
    pub serial: Option<String>,
    pub issuer: Option<String>,
    pub org_1: Option<String>,
    pub org_2: Option<String>,
    pub has_admin_key: bool,
}

/// Parse a Printed Information GET DATA response (the `53`-wrapped body) into
/// [`Pinfo`]. Lenient (matching pivy): unknown tags are skipped and a missing
/// field stays `None`.
pub(crate) fn parse_pinfo(response: &[u8]) -> Pinfo {
    let mut pi = Pinfo::default();
    let mut outer = crate::tlv::TlvReader::new(response);
    let Ok(0x53) = outer.read_tag() else {
        return pi;
    };
    let Ok(body) = outer.read_value() else {
        return pi;
    };
    let mut r = crate::tlv::TlvReader::new(body);
    while r.has_remaining() {
        let (Ok(tag), Ok(val)) = (r.read_tag(), r.read_value()) else {
            break;
        };
        let s = |v: &[u8]| String::from_utf8_lossy(v).into_owned();
        match tag {
            0x01 => pi.name = Some(s(val)),
            0x02 => pi.affiliation = Some(s(val)),
            0x04 => pi.expiry = Some(s(val)),
            0x05 => pi.serial = Some(s(val)),
            0x06 => pi.issuer = Some(s(val)),
            0x07 => pi.org_1 = Some(s(val)),
            0x08 => pi.org_2 = Some(s(val)),
            // YubicoPIV extensions (0x88) wrap the escrowed admin key in 0x89.
            0x88 => {
                let mut inner = crate::tlv::TlvReader::new(val);
                while inner.has_remaining() {
                    let (Ok(t), Ok(v)) = (inner.read_tag(), inner.read_value()) else {
                        break;
                    };
                    if t == 0x89 && !v.is_empty() {
                        pi.has_admin_key = true;
                    }
                }
            }
            _ => {}
        }
    }
    pi
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a PINFO body in the `53` envelope a GET DATA response carries.
    fn wrap53(body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x53, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn parse_extracts_all_printed_fields() {
        // 01 name, 02 affiliation, 04 expiry, 05 serial, 06 issuer.
        let mut body = Vec::new();
        for (tag, val) in [
            (0x01u8, b"Jo Tester".as_slice()),
            (0x02, b"Engineering".as_slice()),
            (0x04, b"2030-01-01".as_slice()),
            (0x05, b"CS-42".as_slice()),
            (0x06, b"ACME".as_slice()),
        ] {
            body.push(tag);
            body.push(val.len() as u8);
            body.extend_from_slice(val);
        }
        let pi = parse_pinfo(&wrap53(&body));
        assert_eq!(
            pi,
            Pinfo {
                name: Some("Jo Tester".into()),
                affiliation: Some("Engineering".into()),
                expiry: Some("2030-01-01".into()),
                serial: Some("CS-42".into()),
                issuer: Some("ACME".into()),
                org_1: None,
                org_2: None,
                has_admin_key: false,
            }
        );
    }

    #[test]
    fn parse_detects_yubico_admin_key() {
        // 88 { 89 <key> } marks an escrowed admin key.
        let body = [0x88, 0x05, 0x89, 0x03, 0xAA, 0xBB, 0xCC];
        assert!(parse_pinfo(&wrap53(&body)).has_admin_key);
    }

    #[test]
    fn parse_empty_or_unwrapped_is_default() {
        assert_eq!(parse_pinfo(&[]), Pinfo::default());
        assert_eq!(parse_pinfo(&[0x01, 0x01, b'x']), Pinfo::default());
    }
}
