//! Purpose ID registry.
//!
//! Mirrors `go/internal/bravo/markl/purposes.go` plus the
//! `validatePurposeAndFormatId` check from `id_blech_coding.go`.
//! Prototype scope: only the purposes piggy uses or expects to see in
//! the wild are registered. The dodder-* purposes are scaffolded so
//! a `piggy-ids` file mistakenly carrying a dodder purpose fails
//! cleanly (and so we have a place to add them when madder hands off
//! its registry).

use thiserror::Error;

use crate::format::FormatId;

/// Purpose ID values that piggy understands. Other purposes parse as
/// `Other(String)` so future / unrecognised purposes don't bring the
/// codec down — but the `validate_format` call still returns
/// `Incompatible` since piggy can't reason about them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PurposeId {
    /// `piggy-recipient-v1` — piggy 2.x recipient pubkey, constrained
    /// to `pivy_ecdh_p256_pub`. **Reserved by piggy** in RFC 0002 §6.3
    /// (drafted in piggy at madder#150). Until the official RFC lands
    /// this is the de facto definition.
    PiggyRecipientV1,
    /// `dodder-blob-digest-sha256-v1` — blob content hash. Piggy does
    /// not produce these, but accepts them for round-trip purposes.
    DodderBlobDigestSha256V1,
    /// `dodder-object-digest-v2` — object metadata hash.
    DodderObjectDigestV2,
    /// `dodder-object-sig-v2` — object signature.
    DodderObjectSigV2,
    /// `dodder-repo-public_key-v1` — repository public key.
    DodderRepoPublicKeyV1,
    /// `dodder-repo-private_key-v1` — repository private key.
    DodderRepoPrivateKeyV1,
    /// Any other syntactically-valid purpose ID. Parses but cannot
    /// validate format compatibility.
    Other(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("format id {format:?} is not compatible with purpose {purpose:?}")]
pub struct Incompatible {
    pub purpose: PurposeId,
    pub format: FormatId,
}

impl PurposeId {
    /// Wire-format name as it appears before the `@` separator.
    pub fn as_str(&self) -> &str {
        match self {
            PurposeId::PiggyRecipientV1 => "piggy-recipient-v1",
            PurposeId::DodderBlobDigestSha256V1 => "dodder-blob-digest-sha256-v1",
            PurposeId::DodderObjectDigestV2 => "dodder-object-digest-v2",
            PurposeId::DodderObjectSigV2 => "dodder-object-sig-v2",
            PurposeId::DodderRepoPublicKeyV1 => "dodder-repo-public_key-v1",
            PurposeId::DodderRepoPrivateKeyV1 => "dodder-repo-private_key-v1",
            PurposeId::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "piggy-recipient-v1" => PurposeId::PiggyRecipientV1,
            "dodder-blob-digest-sha256-v1" => PurposeId::DodderBlobDigestSha256V1,
            "dodder-object-digest-v2" => PurposeId::DodderObjectDigestV2,
            "dodder-object-sig-v2" => PurposeId::DodderObjectSigV2,
            "dodder-repo-public_key-v1" => PurposeId::DodderRepoPublicKeyV1,
            "dodder-repo-private_key-v1" => PurposeId::DodderRepoPrivateKeyV1,
            other => PurposeId::Other(other.to_string()),
        }
    }

    /// Verify that `format` is one of the formats this purpose
    /// constrains itself to. For `Other`, conservatively rejects
    /// every format — piggy doesn't know the registry's rules for
    /// purposes it didn't enumerate.
    pub fn validate_format(&self, format: FormatId) -> Result<(), Incompatible> {
        let ok = match self {
            PurposeId::PiggyRecipientV1 => matches!(format, FormatId::PivyEcdhP256Pub),
            PurposeId::DodderBlobDigestSha256V1 => {
                matches!(format, FormatId::Sha256 | FormatId::Blake2b256)
            }
            PurposeId::DodderObjectDigestV2 => {
                matches!(format, FormatId::Sha256 | FormatId::Blake2b256)
            }
            PurposeId::DodderObjectSigV2 => {
                matches!(format, FormatId::Ed25519Sig | FormatId::EcdsaP256Sig)
            }
            PurposeId::DodderRepoPublicKeyV1 => {
                matches!(format, FormatId::Ed25519Pub | FormatId::EcdsaP256Pub)
            }
            PurposeId::DodderRepoPrivateKeyV1 => matches!(
                format,
                FormatId::Ed25519Sec | FormatId::Ed25519Ssh | FormatId::EcdsaP256Ssh
            ),
            PurposeId::Other(_) => false,
        };
        if ok {
            Ok(())
        } else {
            Err(Incompatible {
                purpose: self.clone(),
                format,
            })
        }
    }
}

impl core::fmt::Display for PurposeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piggy_recipient_v1_accepts_only_pivy_ecdh_p256_pub() {
        let p = PurposeId::PiggyRecipientV1;
        assert!(p.validate_format(FormatId::PivyEcdhP256Pub).is_ok());
        assert!(p.validate_format(FormatId::Sha256).is_err());
        assert!(p.validate_format(FormatId::EcdsaP256Pub).is_err());
    }

    #[test]
    fn dodder_blob_digest_sha256_v1_accepts_both_sha256_and_blake2b256() {
        let p = PurposeId::DodderBlobDigestSha256V1;
        assert!(p.validate_format(FormatId::Sha256).is_ok());
        assert!(p.validate_format(FormatId::Blake2b256).is_ok());
        assert!(p.validate_format(FormatId::Ed25519Pub).is_err());
    }

    #[test]
    fn other_purpose_rejects_every_format() {
        let p = PurposeId::parse("future-purpose-v0");
        assert!(matches!(p, PurposeId::Other(_)));
        for f in [FormatId::PivyEcdhP256Pub, FormatId::Sha256, FormatId::Ed25519Sig] {
            assert!(p.validate_format(f).is_err(), "should reject {f}");
        }
    }

    #[test]
    fn round_trip_purpose_names() {
        for p in [
            PurposeId::PiggyRecipientV1,
            PurposeId::DodderBlobDigestSha256V1,
            PurposeId::DodderObjectDigestV2,
            PurposeId::DodderObjectSigV2,
            PurposeId::DodderRepoPublicKeyV1,
            PurposeId::DodderRepoPrivateKeyV1,
        ] {
            let s = p.as_str().to_string();
            let parsed = PurposeId::parse(&s);
            assert_eq!(parsed, p);
        }
    }
}
