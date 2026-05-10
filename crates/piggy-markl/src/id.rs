//! Markl ID — `[purpose@]format-data`.
//!
//! Mirrors `go/internal/bravo/markl/id.go`. The wire form is:
//!
//! ```text
//! [purpose@]format-data
//! ```
//!
//! where `format-data` is a blech32 string with HRP=`format` (the
//! purpose, when present, is **textually prepended** as `purpose@`
//! after blech32 encoding — the checksum binds to `(format, data)`
//! only). Splitting the optional purpose off uses the **first** `@`
//! in the input (matching Go's `strings.Cut`); since the purpose-id
//! lexical rule disallows `@`, "first" and "last" coincide for valid
//! inputs.
//!
//! The split-HRP rule was restored by amarbel-llc/madder#159 after
//! the brief combined-HRP form (madder#150 / commit 8dc78c7) broke
//! cross-purpose digest equality. RFC 0002 §3.3 + §4 reflect the
//! restored rule.
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
    /// blech32-encodes `(format, data)` only; if a purpose is present
    /// it is textually prepended as `purpose@`. The checksum covers
    /// the format + data, never the purpose — matches madder's
    /// `StringWithFormat` after the split-HRP revert (madder#159).
    pub fn to_wire(&self) -> String {
        let body = blech32::encode(self.format.as_str(), &self.data)
            .expect("encode of validated payload cannot fail");
        match &self.purpose {
            Some(p) => format!("{}@{}", p.as_str(), body),
            None => body,
        }
    }

    /// Parse a wire-form markl ID per RFC 0002 §4. Splits on the
    /// first `@` *textually* to recover the purpose, then
    /// blech32-decodes the body with HRP=`format`. Mirrors madder's
    /// `Set` after madder#159.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let (purpose_str, body) = match s.find('@') {
            Some(i) => (Some(&s[..i]), &s[i + 1..]),
            None => (None, s),
        };
        let (format_str, data) = blech32::decode(body)?;
        let purpose = purpose_str.map(PurposeId::parse);
        let format = FormatId::parse(&format_str)?;

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
        // Build a canonical (RFC 0002) wire string textually:
        // "future-purpose-v0@" prepended to blech32(pivy_ecdh_p256_pub,
        // payload). Assert parse → Id::new → validate_format → Other
        // rejects.
        let body = blech32::encode("pivy_ecdh_p256_pub", &payload).unwrap();
        let wire = format!("future-purpose-v0@{body}");
        let err = Id::parse(&wire).unwrap_err();
        assert!(matches!(err, ParseError::Incompatible(_)));
    }

    #[test]
    fn purpose_split_uses_first_at_in_input() {
        // RFC 0002 §4 splits the input on the first `@` textually
        // (before blech32-decoding the body). Since the purpose-id
        // lexical rule excludes `@`, in practice there's only one —
        // but document the parse rule.
        let payload = pivy_pubkey_payload();
        let body = blech32::encode("pivy_ecdh_p256_pub", &payload).unwrap();
        let wire = format!("piggy-recipient-v1@{body}");
        let parsed = Id::parse(&wire).unwrap();
        assert_eq!(parsed.purpose(), Some(&PurposeId::PiggyRecipientV1));
        assert_eq!(parsed.format(), FormatId::PivyEcdhP256Pub);
    }

    #[test]
    fn cross_purpose_blech32_body_is_identical() {
        // RFC 0002 §3.3 (post-#159) property: the same (format, data)
        // under different purposes produces the same blech32 byte
        // sequence; only the textual purpose@ prefix differs.
        // Mirrors madder's TestRFC0002CrossPurposeBlech32Equal.
        let data = vec![0u8; 32];
        let purposeless = Id::new(None, FormatId::Sha256, data.clone()).unwrap();
        let blob_digest = Id::new(
            Some(PurposeId::DodderBlobDigestSha256V1),
            FormatId::Sha256,
            data.clone(),
        )
        .unwrap();
        let object_digest = Id::new(
            Some(PurposeId::DodderObjectDigestV2),
            FormatId::Sha256,
            data,
        )
        .unwrap();

        let purposeless_wire = purposeless.to_wire();
        let blob_body = blob_digest.to_wire();
        let object_body = object_digest.to_wire();

        let blob_after_at = blob_body.split_once('@').expect("purpose@body").1;
        let object_after_at = object_body.split_once('@').expect("purpose@body").1;
        assert_eq!(blob_after_at, purposeless_wire);
        assert_eq!(object_after_at, purposeless_wire);
        assert_eq!(blob_after_at, object_after_at);
    }
}
