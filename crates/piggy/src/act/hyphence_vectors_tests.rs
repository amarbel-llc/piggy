//! Replays hyphence's RFC 0005 canonical-emission vectors (a pinned copy in
//! testdata/hyphence-0005-vectors.txt) against the hyphence crate piggy
//! links. The records are hyphence documents, not acts: `piggy act canon`
//! refuses all of them before RFC 0005 is reached, so the canonical records
//! go straight through hyphence's decode, typed head and encoder here. The
//! refuse records are also replayed through `piggy act canon` in
//! zz-tests_bats/conformance/act_canonical.bats.

use hyphence::{Document, Head};

use super::tests::{Vector, read_vectors};

const VECTORS: &str = include_str!("../../testdata/hyphence-0005-vectors.txt");

fn vectors() -> Vec<Vector> {
    let vectors = read_vectors(VECTORS);
    assert_eq!(vectors.len(), 18, "the 1c63a98 copy holds 18 records");
    vectors
}

/// RFC 0005 emission: decode the document, read its typed head, encode it.
fn emit(document: &[u8]) -> Result<Vec<u8>, String> {
    let doc = Document::decode(document).map_err(|e| format!("decode: {e}"))?;
    let head = Head::from_document(&doc).map_err(|e| format!("typed head: {e}"))?;
    head.encode(doc.body.as_deref())
        .map_err(|e| format!("encode: {e}"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn canonical_records_encode_to_their_canonical_form_and_are_fixed_points() {
    for v in vectors().iter().filter(|v| v.outcome == "canonical") {
        let canonical = v.canonical.as_deref().expect("a canonical block");
        let emitted = emit(&v.document).unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(text(&emitted), text(canonical), "{}", v.name);
        assert_eq!(
            emit(canonical).map(|b| text(&b)),
            Ok(text(canonical)),
            "{}: the canonical form is not a fixed point",
            v.name
        );
    }
}

#[test]
fn refuse_records_are_refused_by_decode_or_the_typed_head() {
    for v in vectors().iter().filter(|v| v.outcome == "refuse") {
        let doc = Document::decode(&v.document);
        let refused_as = match &doc {
            Err(_) => "envelope",
            Ok(doc) => match Head::from_document(doc) {
                Err(_) => "content",
                Ok(_) => panic!("{}: accepted", v.name),
            },
        };
        assert_eq!(Some(refused_as), v.rule.as_deref(), "{}", v.name);
    }
}
