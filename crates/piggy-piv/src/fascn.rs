//! PIV FASC-N (Federal Agency Smart Credential Number) decode + format.
//!
//! The FASC-N lives in the CHUID (SP 800-73-4, tag `0x30`), BCD-packed per
//! ISO 7811: a stream of 5-bit characters — 4 weighted data bits (`w1 w2 w4 w8`,
//! MSB-first in the 5-bit code) plus an odd-parity bit — framed by a Start
//! Sentinel (SS), Field Separators (FS), an End Sentinel (ES), and a trailing
//! LRC check character. `pivy-tool list` renders it as
//! `agency-system-crednum-cs-ici/orgtype:oi/assoc:pi`; this module is the
//! read/format half of that, matched byte-for-byte against C
//! (`vendor/pivy/src/piv-fascn.c` + the `bcdbuf` reader in `utils.c`), so the
//! Rust `piggy tool list` port emits the same `fasc-n` field.

/// Error decoding a FASC-N BCD stream. The C side raises `FASCNFormatError`
/// with descriptive text; piggy keeps a small typed set (the exact C error
/// strings are not part of the differential — only the decoded value is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FascnError {
    /// The bit stream ended before a complete FASC-N was read.
    UnexpectedEnd,
    /// A 5-bit group was not a valid BCD digit or sentinel.
    IllegalSymbol(u8),
    /// A field began with a Start Sentinel (only valid once, at the very start).
    UnexpectedStartSentinel,
    /// The stream did not begin with a Start Sentinel.
    MissingStartSentinel,
    /// The final field was not terminated by the End Sentinel.
    MissingEndSentinel,
    /// The organization-category digit was not `1`..=`4`.
    BadOrgCategory(String),
    /// The person-association digit was not `1`..=`7`.
    BadAssociation(String),
    /// The trailing LRC check character did not match.
    LrcMismatch,
}

/// FASC-N organization category (the `OC` digit), rendered like C's
/// `piv_fascn_org_type_to_string`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgCategory {
    Federal,
    State,
    Commercial,
    Foreign,
}

impl OrgCategory {
    fn from_digit(d: &str) -> Result<Self, FascnError> {
        match d.chars().next() {
            Some('1') => Ok(Self::Federal),
            Some('2') => Ok(Self::State),
            Some('3') => Ok(Self::Commercial),
            Some('4') => Ok(Self::Foreign),
            _ => Err(FascnError::BadOrgCategory(d.to_string())),
        }
    }

    /// The lowercase label C prints for this category.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Federal => "federal",
            Self::State => "state",
            Self::Commercial => "commercial",
            Self::Foreign => "foreign",
        }
    }
}

/// FASC-N person/organization association (the `POA` digit), rendered like C's
/// `piv_fascn_assoc_to_string`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Association {
    Employee,
    Civil,
    Executive,
    Uniformed,
    Contractor,
    Affiliate,
    Beneficiary,
}

impl Association {
    fn from_digit(d: &str) -> Result<Self, FascnError> {
        match d.chars().next() {
            Some('1') => Ok(Self::Employee),
            Some('2') => Ok(Self::Civil),
            Some('3') => Ok(Self::Executive),
            Some('4') => Ok(Self::Uniformed),
            Some('5') => Ok(Self::Contractor),
            Some('6') => Ok(Self::Affiliate),
            Some('7') => Ok(Self::Beneficiary),
            _ => Err(FascnError::BadAssociation(d.to_string())),
        }
    }

    /// The lowercase label C prints for this association.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Employee => "employee",
            Self::Civil => "civil",
            Self::Executive => "executive-staff",
            Self::Uniformed => "uniformed-service",
            Self::Contractor => "contractor",
            Self::Affiliate => "affiliate",
            Self::Beneficiary => "beneficiary",
        }
    }
}

/// A decoded FASC-N. Field names mirror SP 800-73-4 / C's `struct piv_fascn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fascn {
    pub agency: String,
    pub system: String,
    pub crednum: String,
    pub cs: String,
    pub ici: String,
    pub pi: String,
    pub oc: OrgCategory,
    pub oi: String,
    pub poa: Association,
}

impl Fascn {
    /// The canonical all-zero FASC-N, matching C's `piv_fascn_zero()` — the
    /// default a stock YubiKey ships. (Note C's zero form is NOT all-zero
    /// fields: `ici` is `1`, `oc` commercial, `poa` employee.)
    fn zero() -> Self {
        Self {
            agency: "0000".into(),
            system: "0000".into(),
            crednum: "000000".into(),
            cs: "0".into(),
            ici: "1".into(),
            pi: "0000000000".into(),
            oc: OrgCategory::Commercial,
            oi: "0000".into(),
            poa: Association::Employee,
        }
    }

    /// Render exactly like C's `piv_fascn_to_string`:
    /// `agency-system-crednum-cs-ici/orgtype:oi/assoc:pi`.
    pub fn to_pivy_string(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}/{}:{}/{}:{}",
            self.agency,
            self.system,
            self.crednum,
            self.cs,
            self.ici,
            self.oc.as_str(),
            self.oi,
            self.poa.as_str(),
            self.pi,
        )
    }
}

/// One decoded 5-bit ISO-7811 symbol.
enum Symbol {
    Digit(char),
    StartSentinel,
    FieldSeparator,
    EndSentinel,
}

/// Map a 5-bit code to its symbol, matching C's `bcdbuf_read` acceptance set
/// (`utils.c`): the odd-parity-encoded digit codes plus SS/FS/ES.
fn decode_symbol(v: u8) -> Result<Symbol, FascnError> {
    Ok(match v {
        0x01 => Symbol::Digit('0'),
        0x10 => Symbol::Digit('1'),
        0x08 => Symbol::Digit('2'),
        0x19 => Symbol::Digit('3'),
        0x04 => Symbol::Digit('4'),
        0x15 => Symbol::Digit('5'),
        0x0d => Symbol::Digit('6'),
        0x1c => Symbol::Digit('7'),
        0x02 => Symbol::Digit('8'),
        0x13 => Symbol::Digit('9'),
        0x1a => Symbol::StartSentinel,
        0x16 => Symbol::FieldSeparator,
        0x1f => Symbol::EndSentinel,
        _ => return Err(FascnError::IllegalSymbol(v)),
    })
}

/// MSB-first 5-bit reader over the packed FASC-N bytes, accumulating the LRC
/// exactly as C's `bcdbuf_read` does (`lrc ^= v & 0x1e` on every read).
struct BcdReader<'a> {
    data: &'a [u8],
    bit: usize,
    lrc: u8,
}

impl<'a> BcdReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            bit: 0,
            lrc: 0,
        }
    }

    /// Read the next 5 bits (MSB-first), or `None` at end of stream. Does NOT
    /// touch the LRC — callers choose whether a read participates (data reads
    /// do; the final LRC-check read does not), matching C.
    fn read5_raw(&mut self) -> Option<u8> {
        if self.bit + 5 > self.data.len() * 8 {
            return None;
        }
        let mut v = 0u8;
        for _ in 0..5 {
            let byte = self.data[self.bit / 8];
            let b = (byte >> (7 - (self.bit % 8))) & 1;
            v = (v << 1) | b;
            self.bit += 1;
        }
        Some(v)
    }

    /// Read one symbol and fold it into the running LRC (as `bcdbuf_read`).
    fn read_symbol(&mut self) -> Result<Symbol, FascnError> {
        let v = self.read5_raw().ok_or(FascnError::UnexpectedEnd)?;
        self.lrc ^= v & 0x1e;
        decode_symbol(v)
    }

    /// Read a field of digits, up to `limit` characters, stopping at a
    /// separator (FS/ES) or when `limit` digits have accumulated — mirroring
    /// `bcdbuf_read_string`. Returns the digits and the terminator that stopped
    /// it (`None` when the limit was hit with no separator).
    fn read_field(&mut self, limit: usize) -> Result<(String, Option<Symbol>), FascnError> {
        let mut s = String::new();
        loop {
            match self.read_symbol()? {
                Symbol::StartSentinel => return Err(FascnError::UnexpectedStartSentinel),
                Symbol::FieldSeparator => return Ok((s, Some(Symbol::FieldSeparator))),
                Symbol::EndSentinel => return Ok((s, Some(Symbol::EndSentinel))),
                Symbol::Digit(c) => {
                    s.push(c);
                    if limit != 0 && s.len() >= limit {
                        return Ok((s, None));
                    }
                }
            }
        }
    }

    /// Read the trailing LRC character and verify it against the accumulated
    /// value, as C's `bcdbuf_read_and_check_lrc` (compare the masked 5-bit
    /// value, NOT folded into `lrc`).
    fn check_lrc(&mut self) -> Result<(), FascnError> {
        let v = self.read5_raw().ok_or(FascnError::UnexpectedEnd)?;
        if (v & 0x1e) != self.lrc {
            return Err(FascnError::LrcMismatch);
        }
        Ok(())
    }
}

/// Decode a FASC-N BCD byte stream (the CHUID tag-`0x30` value) into a
/// [`Fascn`], mirroring C's `piv_fascn_decode`. All-zero input (7..=25 bytes)
/// short-circuits to the canonical zero FASC-N like C does.
pub fn decode(data: &[u8]) -> Result<Fascn, FascnError> {
    // All-zero special case (C: piv_fascn_decode → piv_fascn_zero()).
    if (7..=25).contains(&data.len()) && data.iter().all(|&b| b == 0x00) {
        return Ok(Fascn::zero());
    }

    let mut r = BcdReader::new(data);

    match r.read_symbol()? {
        Symbol::StartSentinel => {}
        _ => return Err(FascnError::MissingStartSentinel),
    }

    // Field lengths and order are fixed by SP 800-73-4 / C's cmd sequence:
    // agency(5) system(5) crednum(7) cs(2) ici(2) pi(10) oc(1) oi(4) poa(2).
    let (agency, _) = r.read_field(5)?;
    let (system, _) = r.read_field(5)?;
    let (crednum, _) = r.read_field(7)?;
    let (cs, _) = r.read_field(2)?;
    let (ici, _) = r.read_field(2)?;
    let (pi, _) = r.read_field(10)?;
    let (oc, _) = r.read_field(1)?;
    let (oi, _) = r.read_field(4)?;
    let (poa, poa_term) = r.read_field(2)?;

    let oc = OrgCategory::from_digit(&oc)?;
    let poa = Association::from_digit(&poa)?;

    if !matches!(poa_term, Some(Symbol::EndSentinel)) {
        return Err(FascnError::MissingEndSentinel);
    }

    r.check_lrc()?;

    Ok(Fascn {
        agency,
        system,
        crednum,
        cs,
        ici,
        pi,
        oc,
        oi,
        poa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The throwaway YubiKey 4's real FASC-N, captured in the canonical CHUID
    /// (`crates/fibby/src/virtual_card.rs` CANONICAL_REAL_CARD_CHUID, tag 0x30
    /// value — public, non-sensitive). Decodes to the stock-default FASC-N.
    const CANONICAL_FASCN: &[u8] = &[
        0xD0, 0x42, 0x10, 0xD8, 0x21, 0x08, 0x6C, 0x10, 0x84, 0x21, 0x0D, 0x83, 0x68, 0x58, 0x21,
        0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB,
    ];

    /// The exact string C's `pivy-tool -j list` prints for `fasc-n` on the
    /// tool-fibby card (verified 2026-09-17 via `just debug-tool-list-capture`).
    const CANONICAL_FASCN_STR: &str = "0000-0000-000000-0-1/commercial:0000/employee:0000000000";

    #[test]
    fn decodes_canonical_card_fascn_byte_for_byte() {
        let f = decode(CANONICAL_FASCN).expect("canonical FASC-N decodes");
        assert_eq!(f.to_pivy_string(), CANONICAL_FASCN_STR);
        assert_eq!(f.agency, "0000");
        assert_eq!(f.ici, "1");
        assert_eq!(f.pi, "0000000000");
        assert_eq!(f.oc, OrgCategory::Commercial);
        assert_eq!(f.poa, Association::Employee);
    }

    #[test]
    fn all_zero_bytes_yield_canonical_zero_form() {
        // C special-cases an all-zero FASC-N to piv_fascn_zero(), whose string
        // is identical to the stock-default card above.
        assert_eq!(
            decode(&[0u8; 25]).unwrap().to_pivy_string(),
            CANONICAL_FASCN_STR
        );
    }

    #[test]
    fn illegal_symbol_is_an_error() {
        // 0x00 (ISO_BCD_NONE) is never a valid on-wire symbol; a stream that is
        // neither all-zero nor a valid SS-led FASC-N must error, not panic.
        assert!(matches!(
            decode(&[0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            Err(FascnError::MissingStartSentinel | FascnError::IllegalSymbol(_))
        ));
    }
}
