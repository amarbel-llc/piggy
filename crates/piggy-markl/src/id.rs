//! Markl ID — `[purpose@]format-data`.
//!
//! Mirrors `go/internal/bravo/markl/id.go`. The wire form is:
//!
//! ```text
//! [purpose@]format-data
//! ```
//!
//! where `format-data` is the blech32 (HRP=format, data=blech32-encoded
//! payload + 6-char checksum). Splitting the optional purpose off uses
//! the **first** `@` (matching Go's `strings.Cut`); since the
//! purpose-id lexical rule disallows `@`, "first" and "last" coincide
//! for valid inputs.
//!
//! ADR-0001 invariant: any `Id` whose `data` is non-empty MUST carry
//! a `format`, and `data.len()` MUST equal that format's declared
//! size (or be SSH-wire-format-shaped for variable-size formats —
//! piggy doesn't use those today).

use thiserror::Error;

use crate::blech32;
use crate::format::{FormatId, UnknownFormat};
use crate::purpose::{Incompatible, PurposeId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Id {
    purpose: Option<PurposeId>,
    format: FormatId,
    data: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("blech32 decode failed: {0}")]
    Blech32(#[from] blech32::Error),
    #[error("unknown format id: {0}")]
    UnknownFormat(String),
    #[error(
        "wrong payload size: format {format:?} requires {expected} bytes, decoded {actual}"
    )]
    WrongSize {
        format: FormatId,
        expected: usize,
        actual: usize,
    },
    #[error("incompatible purpose/format: {0}")]
    Incompatible(#[from] Incompatible),
}

impl From<UnknownFormat> for ParseError {
    fn from(value: UnknownFormat) -> Self {
        ParseError::UnknownFormat(value.0)
    }
}

impl Id {
    /// Construct from a known purpose, format, and pre-validated
    /// payload bytes. Enforces the ADR-0001 size invariant for
    /// fixed-size formats and the purpose↔format compatibility
    /// constraint when `purpose` is `Some`.
    pub fn new(
        purpose: Option<PurposeId>,
        format: FormatId,
        data: Vec<u8>,
    ) -> Result<Self, ParseError> {
        let expected = format.size();
        if data.len() != expected {
            return Err(ParseError::WrongSize {
                format,
                expected,
                actual: data.len(),
            });
        }
        if let Some(p) = &purpose {
            p.validate_format(format)?;
        }
        Ok(Self { purpose, format, data })
    }

    pub fn purpose(&self) -> Option<&PurposeId> {
        self.purpose.as_ref()
    }

    pub fn format(&self) -> FormatId {
        self.format
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Render the markl ID in wire form. Always lowercase.
    ///
    /// When a purpose is present the blech32 HRP is the combined
    /// string `purpose@format` so the checksum covers both parts —
    /// matches madder's MarshalText (RFC 0002 §3) after the
    /// purpose-aware fix that landed with madder#150.
    pub fn to_wire(&self) -> String {
        let hrp = match &self.purpose {
            Some(p) => format!("{}@{}", p.as_str(), self.format.as_str()),
            None => self.format.as_str().to_string(),
        };
        blech32::encode(&hrp, &self.data).expect("encode of validated payload cannot fail")
    }

    /// Parse a wire-form markl ID per RFC 0002 §4. blech32-decodes
    /// the whole input first (HRP may include `purpose@format`),
    /// then splits the decoded HRP on the first `@` to recover the
    /// purpose.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let (combined_hrp, data) = blech32::decode(s)?;
        let (purpose_str, format_str) = match combined_hrp.find('@') {
            Some(i) => (Some(&combined_hrp[..i]), &combined_hrp[i + 1..]),
            None => (None, combined_hrp.as_str()),
        };
        let purpose = purpose_str.map(PurposeId::parse);
        let format = FormatId::parse(format_str)?;

        Self::new(purpose, format, data)
    }
}

impl core::fmt::Display for Id {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl core::str::FromStr for Id {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pivy_pubkey_payload() -> Vec<u8> {
        // 33 bytes: SEC 1 compressed point format leads with 0x02 or
        // 0x03; payload bytes after that are arbitrary for tests.
        let mut v = vec![0x03];
        v.extend((0..32u8).map(|i| i.wrapping_mul(13)));
        v
    }

    #[test]
    fn round_trip_with_purpose() {
        let payload = pivy_pubkey_payload();
        let id = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            payload.clone(),
        )
        .unwrap();
        let wire = id.to_wire();
        assert!(wire.starts_with("piggy-recipient-v1@pivy_ecdh_p256_pub-"));
        let parsed = Id::parse(&wire).unwrap();
        assert_eq!(parsed.purpose(), Some(&PurposeId::PiggyRecipientV1));
        assert_eq!(parsed.format(), FormatId::PivyEcdhP256Pub);
        assert_eq!(parsed.data(), payload.as_slice());
    }

    #[test]
    fn round_trip_without_purpose() {
        let payload = pivy_pubkey_payload();
        let id =
            Id::new(None, FormatId::PivyEcdhP256Pub, payload.clone()).unwrap();
        let wire = id.to_wire();
        assert!(!wire.contains('@'));
        assert!(wire.starts_with("pivy_ecdh_p256_pub-"));
        let parsed = Id::parse(&wire).unwrap();
        assert!(parsed.purpose().is_none());
        assert_eq!(parsed.data(), payload.as_slice());
    }

    #[test]
    fn wrong_size_rejected_at_construction() {
        let err =
            Id::new(None, FormatId::PivyEcdhP256Pub, vec![0xff; 32]).unwrap_err();
        assert!(matches!(
            err,
            ParseError::WrongSize {
                format: FormatId::PivyEcdhP256Pub,
                expected: 33,
                actual: 32
            }
        ));
    }

    #[test]
    fn incompatible_purpose_rejected_at_construction() {
        let err = Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::Sha256,
            vec![0u8; 32],
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::Incompatible(_)));
    }

    #[test]
    fn unknown_format_rejected_at_parse() {
        // Construct an encoded string with a fake HRP using blech32
        // directly so the inner blech32 decode succeeds but the
        // FormatId lookup fails.
        let payload = vec![0u8; 32];
        let wire = blech32::encode("not_a_format", &payload).unwrap();
        let err = Id::parse(&wire).unwrap_err();
        assert!(matches!(err, ParseError::UnknownFormat(s) if s == "not_a_format"));
    }

    #[test]
    fn purpose_carrying_unknown_string_parses_but_rejects_validation() {
        let payload = pivy_pubkey_payload();
        // Build a canonical (RFC 0002) wire string with HRP =
        // "future-purpose-v0@pivy_ecdh_p256_pub", then assert
        // parse → Id::new → validate_format → Other rejects.
        let wire =
            blech32::encode("future-purpose-v0@pivy_ecdh_p256_pub", &payload).unwrap();
        let err = Id::parse(&wire).unwrap_err();
        assert!(matches!(err, ParseError::Incompatible(_)));
    }

    #[test]
    fn purpose_split_uses_first_at_in_hrp() {
        // The `applyDecodedHRPAndData` step splits the decoded HRP
        // on the first `@`. Since the purpose-id lexical rule
        // excludes `@`, in practice there's only one — but document
        // the parse rule.
        let payload = pivy_pubkey_payload();
        let wire = blech32::encode(
            "piggy-recipient-v1@pivy_ecdh_p256_pub",
            &payload,
        )
        .unwrap();
        let parsed = Id::parse(&wire).unwrap();
        assert_eq!(parsed.purpose(), Some(&PurposeId::PiggyRecipientV1));
        assert_eq!(parsed.format(), FormatId::PivyEcdhP256Pub);
    }
}
