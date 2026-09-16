//! PIV Key History object (tag `5FC10C`) — encode, parse, and (re)write.
//!
//! The Key History object records how many retired key-management slots
//! (`82`..`95`) hold a certificate on-card (`oncard`), how many are held
//! off-card (`offcard`), and an optional URL for fetching the off-card
//! certs. `pivy-tool update-keyhist` rescans the retired slots and rewrites
//! it; this module is the wire half of that port: build/parse the object and
//! write it via PUT DATA.
//!
//! Body (SP 800-73-4, inside the `53` wrapper `put_data` adds):
//! `C1 01 <oncard> C2 01 <offcard> [F3 <len> <url>]` — matching pivy's
//! `piv_write_keyhistory` element order (the `oncard`/`offcard` counts are
//! `0..20`, so each is a single value byte).

use crate::error::PivError;
use crate::token::PinSession;

/// PIV Key History data-object tag.
pub const KEYHIST_TAG: u32 = 0x5FC10C;

/// A parsed Key History object: retired-slot certs held on-card, off-card,
/// and the optional off-card fetch URL.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyHistory {
    pub oncard: u8,
    pub offcard: u8,
    pub url: Option<String>,
}

/// Build the Key History object body (the value inside the `53` wrapper):
/// `C1 01 <oncard> C2 01 <offcard> [F3 <len> <url>]`, matching pivy's
/// `piv_write_keyhistory`.
pub fn build_keyhistory_body(oncard: u8, offcard: u8, url: Option<&str>) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + url.map_or(0, |u| u.len() + 3));
    v.extend_from_slice(&[0xC1, 0x01, oncard]);
    v.extend_from_slice(&[0xC2, 0x01, offcard]);
    if let Some(u) = url {
        v.push(0xF3);
        push_ber_len(&mut v, u.len());
        v.extend_from_slice(u.as_bytes());
    }
    v
}

/// Parse a Key History GET DATA response (the `53`-wrapped body) into
/// [`KeyHistory`]. Lenient (matching pivy): a malformed or empty response,
/// or a missing field, yields the default for that field rather than an
/// error — `read_keyhistory` already maps the "absent object" `6A82` to the
/// default before calling this.
pub(crate) fn parse_keyhistory(response: &[u8]) -> KeyHistory {
    let mut kh = KeyHistory::default();
    let mut outer = crate::tlv::TlvReader::new(response);
    let Ok(0x53) = outer.read_tag() else {
        return kh;
    };
    let Ok(body) = outer.read_value() else {
        return kh;
    };
    let mut r = crate::tlv::TlvReader::new(body);
    while r.has_remaining() {
        let (Ok(tag), Ok(val)) = (r.read_tag(), r.read_value()) else {
            break;
        };
        match tag {
            0xC1 => kh.oncard = val.first().copied().unwrap_or(0),
            0xC2 => kh.offcard = val.first().copied().unwrap_or(0),
            0xF3 => kh.url = Some(String::from_utf8_lossy(val).into_owned()),
            _ => {}
        }
    }
    kh
}

/// Append a BER-TLV length (short form, then the `0x81`/`0x82` long forms).
fn push_ber_len(buf: &mut Vec<u8>, len: usize) {
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

impl PinSession<'_> {
    /// Write the PIV Key History object (PUT DATA at `5FC10C`) — the wire
    /// half of `pivy-tool update-keyhist`. Requires a prior
    /// [`PinSession::authenticate_admin`] on real hardware.
    pub fn write_keyhistory(
        &mut self,
        oncard: u8,
        offcard: u8,
        url: Option<&str>,
    ) -> Result<(), PivError> {
        self.put_data(KEYHIST_TAG, &build_keyhistory_body(oncard, offcard, url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_fresh_card_body_is_c1_00_c2_00() {
        // A card with no retired certs and no prior key history: C's
        // piv_write_keyhistory emits exactly `C1 01 00 C2 01 00`.
        assert_eq!(
            build_keyhistory_body(0, 0, None),
            vec![0xC1, 0x01, 0x00, 0xC2, 0x01, 0x00]
        );
    }

    #[test]
    fn build_with_counts_and_url() {
        let body = build_keyhistory_body(3, 2, Some("https://x/"));
        assert_eq!(&body[..6], &[0xC1, 0x01, 0x03, 0xC2, 0x01, 0x02]);
        assert_eq!(body[6], 0xF3);
        assert_eq!(body[7], 10); // short-form length of "https://x/"
        assert_eq!(&body[8..], b"https://x/");
    }

    #[test]
    fn parse_round_trips_build() {
        let body = build_keyhistory_body(4, 1, Some("u"));
        // Wrap in 53 like a GET DATA response.
        let mut resp = vec![0x53, body.len() as u8];
        resp.extend_from_slice(&body);
        assert_eq!(
            parse_keyhistory(&resp),
            KeyHistory {
                oncard: 4,
                offcard: 1,
                url: Some("u".into())
            }
        );
    }

    #[test]
    fn parse_empty_or_unwrapped_is_default() {
        assert_eq!(parse_keyhistory(&[]), KeyHistory::default());
        // Not 53-wrapped -> default (lenient).
        assert_eq!(parse_keyhistory(&[0xC1, 0x01, 0x05]), KeyHistory::default());
    }
}
