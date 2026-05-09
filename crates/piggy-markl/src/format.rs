//! Format ID registry.
//!
//! Mirrors `go/internal/bravo/markl/format.go` in amarbel-llc/madder.
//! Prototype scope: only the formats piggy actively uses are
//! implemented; the rest are scaffolded so the registry is complete
//! enough that an out-of-spec format-id fails with `UnknownFormat`
//! rather than `InvalidCharacterInData` or similar lower-level error.
//!
//! Sizes match RFC 0002 §5 (drafted in piggy at madder#150).

use thiserror::Error;

/// Format ID literal as it appears in the blech32 HRP. Held as a
/// borrowed string slice to stay copyable and zero-alloc on lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatId {
    PivyEcdhP256Pub,
    Sha256,
    Blake2b256,
    Ed25519Pub,
    Ed25519Sec,
    Ed25519Sig,
    EcdsaP256Pub,
    EcdsaP256Sig,
    AgeX25519Pub,
    AgeX25519Sec,
    Nonce,
    Ed25519Ssh,
    EcdsaP256Ssh,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown format id: {0:?}")]
pub struct UnknownFormat(pub String);

impl FormatId {
    /// Wire-format name as it appears in the HRP.
    pub fn as_str(self) -> &'static str {
        match self {
            FormatId::PivyEcdhP256Pub => "pivy_ecdh_p256_pub",
            FormatId::Sha256 => "sha256",
            FormatId::Blake2b256 => "blake2b256",
            FormatId::Ed25519Pub => "ed25519_pub",
            FormatId::Ed25519Sec => "ed25519_sec",
            FormatId::Ed25519Sig => "ed25519_sig",
            FormatId::EcdsaP256Pub => "ecdsa_p256_pub",
            FormatId::EcdsaP256Sig => "ecdsa_p256_sig",
            FormatId::AgeX25519Pub => "age_x25519_pub",
            FormatId::AgeX25519Sec => "age_x25519_sec",
            FormatId::Nonce => "nonce",
            FormatId::Ed25519Ssh => "ed25519_ssh",
            FormatId::EcdsaP256Ssh => "ecdsa_p256_ssh",
        }
    }

    /// Required payload size in bytes. RFC 0002 §5 corrected the
    /// `*_ssh` formats from "variable" to fixed sizes during the
    /// landing of madder#150 — the SSH-agent integration is
    /// implementation-internal, not part of the wire format.
    pub fn size(self) -> usize {
        match self {
            FormatId::PivyEcdhP256Pub
            | FormatId::EcdsaP256Pub
            | FormatId::EcdsaP256Ssh => 33,
            FormatId::Sha256
            | FormatId::Blake2b256
            | FormatId::Ed25519Pub
            | FormatId::AgeX25519Pub
            | FormatId::AgeX25519Sec
            | FormatId::Nonce
            | FormatId::Ed25519Ssh => 32,
            FormatId::Ed25519Sec | FormatId::Ed25519Sig | FormatId::EcdsaP256Sig => 64,
        }
    }

    pub fn parse(s: &str) -> Result<Self, UnknownFormat> {
        match s {
            "pivy_ecdh_p256_pub" => Ok(FormatId::PivyEcdhP256Pub),
            "sha256" => Ok(FormatId::Sha256),
            "blake2b256" => Ok(FormatId::Blake2b256),
            "ed25519_pub" => Ok(FormatId::Ed25519Pub),
            "ed25519_sec" => Ok(FormatId::Ed25519Sec),
            "ed25519_sig" => Ok(FormatId::Ed25519Sig),
            "ecdsa_p256_pub" => Ok(FormatId::EcdsaP256Pub),
            "ecdsa_p256_sig" => Ok(FormatId::EcdsaP256Sig),
            "age_x25519_pub" => Ok(FormatId::AgeX25519Pub),
            "age_x25519_sec" => Ok(FormatId::AgeX25519Sec),
            "nonce" => Ok(FormatId::Nonce),
            "ed25519_ssh" => Ok(FormatId::Ed25519Ssh),
            "ecdsa_p256_ssh" => Ok(FormatId::EcdsaP256Ssh),
            other => Err(UnknownFormat(other.to_string())),
        }
    }
}

impl core::fmt::Display for FormatId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_format_names() {
        for f in [
            FormatId::PivyEcdhP256Pub,
            FormatId::Sha256,
            FormatId::Blake2b256,
            FormatId::Ed25519Pub,
            FormatId::Ed25519Sec,
            FormatId::Ed25519Sig,
            FormatId::EcdsaP256Pub,
            FormatId::EcdsaP256Sig,
            FormatId::AgeX25519Pub,
            FormatId::AgeX25519Sec,
            FormatId::Nonce,
            FormatId::Ed25519Ssh,
            FormatId::EcdsaP256Ssh,
        ] {
            let s = f.as_str();
            let parsed = FormatId::parse(s).unwrap();
            assert_eq!(parsed, f, "round-trip failed for {s}");
        }
    }

    #[test]
    fn unknown_format_error() {
        let err = FormatId::parse("not-a-format").unwrap_err();
        assert_eq!(err.0, "not-a-format");
    }

    #[test]
    fn pivy_ecdh_p256_pub_size_is_33() {
        assert_eq!(FormatId::PivyEcdhP256Pub.size(), 33);
    }

    #[test]
    fn ssh_formats_have_fixed_sizes_per_rfc_0002() {
        // RFC 0002 §5: ssh formats are fixed-size, not variable.
        assert_eq!(FormatId::Ed25519Ssh.size(), 32);
        assert_eq!(FormatId::EcdsaP256Ssh.size(), 33);
    }
}
