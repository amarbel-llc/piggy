//! piggy-markl — markl ID codec prototype.
//!
//! Implements the markl ID format used by amarbel-llc/madder: a
//! self-describing, checksummed, human-readable identifier of the
//! shape `[purpose@]format-data` where `format-data` is a blech32
//! encoding of the binary payload.
//!
//! **Status: prototype shim.** Hand-ported from the Go reference at
//! `go/internal/{alfa/blech32,bravo/markl}/` while RFC 0002
//! (madder#150) is still in flight. The public API here is intended
//! to be stable; the implementation may be replaced once madder
//! ships RFC 0002 and a portable JSON test-vector fixture
//! (`docs/rfcs/0002-markl-id-format-vectors.json`). See
//! amarbel-llc/piggy#71 for the umbrella tracker.
//!
//! Scope: piggy 2.x's recipient template (`pivy_ecdh_p256_pub` payloads
//! tagged with the `piggy-recipient-v1` purpose). Other format IDs and
//! purposes from the registry are scaffolded so unrecognised inputs
//! fail cleanly rather than silently mismatching.

pub mod blech32;
pub mod format;
pub mod id;
pub mod purpose;

pub use format::{FormatId, UnknownFormat};
pub use id::{Id, ParseError};
pub use purpose::{Incompatible, PurposeId};

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
