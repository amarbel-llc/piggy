//! Conformance tests against madder RFC 0002's portable test
//! vectors (madder#150 + #159). Sourced from
//! `go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json`
//! at madder commit `fd53684` (the split-HRP revert) and pinned in
//! this crate's `testdata/` directory.
//!
//! Round-trips every valid vector (encode-from-bytes match,
//! decode-from-string match) and asserts each invalid vector fails
//! with the expected error variant.

use piggy_markl::{blech32, FormatId, Id, ParseError, PurposeId};
use serde::Deserialize;

const VECTORS: &str = include_str!("../testdata/0002-markl-id-format-vectors.json");

#[derive(Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
    invalid: Vec<Invalid>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    purpose: Option<String>,
    format: String,
    payload_hex: String,
    encoded: String,
}

#[derive(Deserialize)]
struct Invalid {
    name: String,
    encoded: String,
    error: String,
}

fn hex_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len().is_multiple_of(2), "odd-length hex string: {s:?}");
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16).expect("hex digit") as u8;
        let lo = (chunk[1] as char).to_digit(16).expect("hex digit") as u8;
        out.push((hi << 4) | lo);
    }
    out
}

#[test]
fn rfc_0002_valid_vectors_round_trip() {
    let fixture: Fixture = serde_json::from_str(VECTORS).expect("parse vectors fixture");
    let mut failures = Vec::new();

    for v in &fixture.vectors {
        let payload = hex_decode(&v.payload_hex);
        let format = match FormatId::parse(&v.format) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("[{}] unknown format {:?}: {e:?}", v.name, v.format));
                continue;
            }
        };
        let purpose = v.purpose.as_deref().map(PurposeId::parse);

        // Build the Id directly and assert encoded form matches.
        let built = match Id::new(purpose.clone(), format, payload.clone()) {
            Ok(id) => id,
            Err(e) => {
                failures.push(format!("[{}] Id::new failed: {e:?}", v.name));
                continue;
            }
        };
        let actual_encoded = built.to_wire();
        if actual_encoded != v.encoded {
            failures.push(format!(
                "[{}] encode mismatch:\n  expected: {}\n  actual:   {}",
                v.name, v.encoded, actual_encoded
            ));
            continue;
        }

        // Round-trip via parse and assert fields match.
        let parsed = match Id::parse(&v.encoded) {
            Ok(id) => id,
            Err(e) => {
                failures.push(format!("[{}] parse failed: {e:?}", v.name));
                continue;
            }
        };
        if parsed.format() != format {
            failures.push(format!(
                "[{}] parsed format {:?} != expected {:?}",
                v.name,
                parsed.format(),
                format
            ));
        }
        if parsed.data() != payload.as_slice() {
            failures.push(format!(
                "[{}] parsed payload differs from expected",
                v.name
            ));
        }
        match (parsed.purpose(), purpose.as_ref()) {
            (Some(a), Some(b)) if a == b => {}
            (None, None) => {}
            (a, b) => failures.push(format!(
                "[{}] parsed purpose {:?} != expected {:?}",
                v.name, a, b
            )),
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} valid-vector failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn rfc_0002_invalid_vectors_reject() {
    let fixture: Fixture = serde_json::from_str(VECTORS).expect("parse vectors fixture");
    let mut failures = Vec::new();

    for v in &fixture.invalid {
        match Id::parse(&v.encoded) {
            Ok(id) => {
                failures.push(format!(
                    "[{}] expected rejection {:?} but parsed: format={:?} purpose={:?}",
                    v.name,
                    v.error,
                    id.format(),
                    id.purpose()
                ));
                continue;
            }
            Err(e) => {
                if !matches_expected_error(&e, &v.error) {
                    failures.push(format!(
                        "[{}] expected error {:?}, got {e:?}",
                        v.name, v.error
                    ));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} invalid-vector failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Map RFC 0002 error names to piggy-markl error variants.
fn matches_expected_error(actual: &ParseError, expected_name: &str) -> bool {
    matches!(
        (actual, expected_name),
        (ParseError::Blech32(blech32::Error::MixedCase), "MixedCase")
            | (ParseError::Blech32(blech32::Error::SeparatorMissing), "SeparatorMissing")
            | (ParseError::Blech32(blech32::Error::InvalidChecksum), "InvalidChecksum")
            | (
                ParseError::Blech32(blech32::Error::InvalidCharacterInData { .. }),
                "InvalidCharacter",
            )
            | (ParseError::WrongSize { .. }, "WrongSize")
            | (ParseError::Incompatible(_), "IncompatiblePurposeAndFormat")
    )
}
