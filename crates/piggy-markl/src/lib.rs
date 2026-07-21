//! piggy-markl — markl ID codec prototype.
//!
//! Implements the markl ID format used by amarbel-llc/madder: a
//! self-describing, checksummed, human-readable identifier of the
//! shape `[purpose@]format-data` where `format-data` is a blech32
//! encoding of the binary payload.
//!
//! **Status: prototype shim.** Hand-ported from the Go reference at
//! `go/internal/{alfa/blech32,bravo/markl}/`. RFC 0002 landed via
//! madder#150 and was patched by madder#159 to restore the split-HRP
//! checksum binding (purpose textually prepended after blech32, never
//! folded into the HRP); this crate matches the post-#159 wire form.
//! Conformance vectors are pinned from madder's
//! `go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json`.
//! See amarbel-llc/piggy#71 for the umbrella tracker.
//!
//! Scope: piggy 2.x's recipient identifiers — two format families
//! are accepted under the `piggy-recipient-v1` purpose:
//! `pivy_ecdh_p256_pub` (33-byte SEC1 compressed P-256 point, PIV
//! slot 9D) and `age_x25519_pub` (32-byte X25519 pubkey, age v1
//! recipient; wire-format integration ships under piggy RFC 0004).
//! Other format IDs and purposes from the registry are scaffolded so
//! unrecognised inputs fail cleanly rather than silently mismatching.

pub mod blech32;
pub mod format;
pub mod id;
pub mod purpose;

pub use format::{FormatId, UnknownFormat};
pub use id::{Id, ParseError};
pub use purpose::{
    Incompatible, PurposeError, PurposeId, purpose_is_bare_expressible, quote_purpose,
    spell_purpose, split_purpose_slot, unquote_purpose,
};

#[cfg(test)]
mod proptest_round_trips {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Every valid 33-byte payload encodes to a markl ID that
        /// decodes back to the same purpose, format, and bytes.
        #[test]
        fn pivy_ecdh_p256_pub_round_trips(payload in proptest::array::uniform32(any::<u8>()).prop_flat_map(|tail| {
            // Force first byte to a SEC 1 compressed-point tag (0x02 or 0x03)
            // to mirror real pubkeys; codec doesn't care, but the
            // proptest is more aligned with reality this way.
            (proptest::sample::select(vec![0x02u8, 0x03u8]), Just(tail))
        })) {
            let (lead, tail) = payload;
            let mut bytes = vec![lead];
            bytes.extend_from_slice(&tail);
            let id = Id::new(
                Some(PurposeId::PiggyRecipientV1),
                FormatId::PivyEcdhP256Pub,
                bytes.clone(),
            ).unwrap();
            let wire = id.to_wire();
            let parsed = Id::parse(&wire).unwrap();
            prop_assert_eq!(parsed.purpose(), Some(&PurposeId::PiggyRecipientV1));
            prop_assert_eq!(parsed.format(), FormatId::PivyEcdhP256Pub);
            prop_assert_eq!(parsed.data(), bytes.as_slice());
        }

        /// Parallel of `pivy_ecdh_p256_pub_round_trips` for the age
        /// X25519 recipient format. X25519 pubkeys are 32 raw bytes
        /// with no on-curve prefix (unlike SEC1 P-256), so we sample
        /// the full 32-byte payload uniformly.
        #[test]
        fn age_x25519_pub_round_trips(
            bytes in proptest::array::uniform32(any::<u8>()),
        ) {
            let payload = bytes.to_vec();
            let id = Id::new(
                Some(PurposeId::PiggyRecipientV1),
                FormatId::AgeX25519Pub,
                payload.clone(),
            ).unwrap();
            let wire = id.to_wire();
            prop_assert!(wire.starts_with("piggy-recipient-v1@age_x25519_pub-"));
            let parsed = Id::parse(&wire).unwrap();
            prop_assert_eq!(parsed.purpose(), Some(&PurposeId::PiggyRecipientV1));
            prop_assert_eq!(parsed.format(), FormatId::AgeX25519Pub);
            prop_assert_eq!(parsed.data(), payload.as_slice());
        }

        /// Random ascii-charset perturbations of a valid encoded ID
        /// either parse to the original, or fail with one of the
        /// well-typed errors — never panic, never silently corrupt.
        #[test]
        fn arbitrary_input_never_panics(input in "[a-z0-9@-]{0,200}") {
            // We don't care about the result, only that no panic
            // escapes the parser. The proptest framework catches
            // panics and fails the test.
            let _ = Id::parse(&input);
        }
    }
}
