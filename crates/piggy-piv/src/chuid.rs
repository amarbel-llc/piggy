//! CHUID (Card Holder Unique Identifier, SP 800-73-4 §3.1.2) parse for the
//! `piggy tool list` port.
//!
//! [`token::read_chuid`](crate::token) already extracts the GUID (tag `0x34`)
//! for connect. This module parses the *rest* of the object — the fields
//! `pivy-tool list` reports — from the same `53`-wrapped response:
//! `signed`, the cardholder UUID (`0x36`), the FASC-N (`0x30`, decoded via
//! [`crate::fascn`]), and the expiry (`0x35`). Matched against C's
//! `piv_chuid_*` accessors (`vendor/pivy/src/piv-chuid.c`).

use crate::fascn::Fascn;

/// CHUID fields surfaced by `pivy-tool list`, beyond the GUID the token already
/// holds. Every field is optional: a card may omit the cardholder UUID, and a
/// malformed FASC-N/expiry is tolerated rather than failing the whole listing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Chuid {
    /// Whether the CHUID carries a (non-empty) issuer signature — C's
    /// `piv_chuid_is_signed` (`pc_sig != NULL`). Approximated here as "the
    /// `0x3E` signature field is present and non-empty"; C additionally
    /// requires the bytes to parse as CMS, so a non-empty-but-unparseable
    /// signature would read `true` here and `false` in C (not seen in practice).
    pub signed: bool,
    /// Cardholder UUID (tag `0x36`), present only when the card carries one —
    /// C's `piv_chuid_get_chuuid` returns `NULL` otherwise, and `list` omits the
    /// `cardholder` JSON field.
    pub cardholder: Option<Vec<u8>>,
    /// Decoded FASC-N (tag `0x30`). `None` if the tag is absent or undecodable.
    pub fascn: Option<Fascn>,
    /// Card expiry (tag `0x35`), the raw `YYYYMMDD` ASCII bytes as a string.
    pub expiry: Option<String>,
}

/// CHUID inner TLV tags (SP 800-73-4 §3.1.2), inside the `53` wrapper.
mod tag {
    pub const FASCN: u32 = 0x30;
    pub const CHUUID: u32 = 0x36;
    pub const EXPIRY: u32 = 0x35;
    pub const SIGNATURE: u32 = 0x3E;
}

/// Parse a CHUID GET DATA response (the `53`-wrapped body) into a [`Chuid`].
/// Lenient: unknown tags are skipped, a missing field stays `None`, and a
/// FASC-N that fails to decode is dropped to `None` rather than erroring (the
/// GUID-bearing `read_chuid` path is what connect depends on; this is a
/// best-effort read for display).
pub(crate) fn parse_chuid(response: &[u8]) -> Chuid {
    let mut c = Chuid::default();
    let mut outer = crate::tlv::TlvReader::new(response);
    let Ok(0x53) = outer.read_tag() else {
        return c;
    };
    let Ok(body) = outer.read_value() else {
        return c;
    };
    let mut r = crate::tlv::TlvReader::new(body);
    while r.has_remaining() {
        let (Ok(t), Ok(v)) = (r.read_tag(), r.read_value()) else {
            break;
        };
        match t {
            tag::FASCN => c.fascn = crate::fascn::decode(v).ok(),
            tag::CHUUID => c.cardholder = Some(v.to_vec()),
            tag::EXPIRY => c.expiry = Some(String::from_utf8_lossy(v).into_owned()),
            tag::SIGNATURE => c.signed = !v.is_empty(),
            _ => {}
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical real-card CHUID (from fibby's CANONICAL_REAL_CARD_CHUID):
    /// `53 39 30 19 <FASC-N> 34 10 <GUID> 35 08 "20360528" 3E 00`.
    const CANONICAL_CHUID: &[u8] = &[
        0x53, 0x39, 0x30, 0x19, 0xD0, 0x42, 0x10, 0xD8, 0x21, 0x08, 0x6C, 0x10, 0x84, 0x21, 0x0D,
        0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB, 0x34,
        0x10, 0x19, 0x17, 0x55, 0xCF, 0xF3, 0x9E, 0xFE, 0x52, 0x2C, 0x07, 0xA3, 0x83, 0x27, 0x5B,
        0xBE, 0xB1, 0x35, 0x08, 0x32, 0x30, 0x33, 0x36, 0x30, 0x35, 0x32, 0x38, 0x3E, 0x00,
    ];

    #[test]
    fn parses_canonical_chuid_like_c() {
        let c = parse_chuid(CANONICAL_CHUID);
        // 3E is present but empty -> unsigned (C: pc_sig == NULL).
        assert!(!c.signed);
        // No 0x36 -> cardholder omitted.
        assert_eq!(c.cardholder, None);
        // 0x35 -> "20360528" (matches C's pivy-tool -j list `expiry`).
        assert_eq!(c.expiry.as_deref(), Some("20360528"));
        // 0x30 decodes to the stock-default FASC-N string.
        assert_eq!(
            c.fascn.as_ref().map(|f| f.to_pivy_string()),
            Some("0000-0000-000000-0-1/commercial:0000/employee:0000000000".to_string())
        );
    }

    #[test]
    fn detects_signed_and_cardholder() {
        // A CHUID with a non-empty 0x36 (cardholder) and a non-empty 0x3E.
        let body = [
            0x36, 0x02, 0xAA, 0xBB, // cardholder UUID (truncated test value)
            0x3E, 0x01, 0x01, // non-empty signature -> signed
        ];
        let mut resp = vec![0x53, body.len() as u8];
        resp.extend_from_slice(&body);
        let c = parse_chuid(&resp);
        assert!(c.signed);
        assert_eq!(c.cardholder.as_deref(), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn empty_or_unwrapped_is_default() {
        assert_eq!(parse_chuid(&[]), Chuid::default());
        assert_eq!(parse_chuid(&[0x30, 0x01, 0x00]), Chuid::default());
    }
}
