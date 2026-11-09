//! Replays docs/rfcs/0013-vectors.txt (from its crate-local copy) and pins
//! the properties RFC 0013 §3.1 states outright.

use super::*;

const VECTORS: &str = include_str!("../../testdata/0013-vectors.txt");

struct Vector {
    name: String,
    outcome: String,
    rule: Option<String>,
    document: Vec<u8>,
    canonical: Option<Vec<u8>>,
    sealed: Option<Vec<u8>>,
}

/// The vector file's record format: `key: value` lines, and documents as
/// runs of `| ` lines under a `key:` line with nothing after the colon.
fn vectors() -> Vec<Vector> {
    let mut out = Vec::new();

    for record in VECTORS.split("\n\n") {
        let lines: Vec<&str> = record
            .lines()
            .filter(|l| !l.starts_with('#') || l.starts_with("| "))
            .collect();
        if lines.is_empty() {
            continue;
        }

        let mut scalars = std::collections::HashMap::new();
        let mut blocks: std::collections::HashMap<&str, Vec<u8>> = std::collections::HashMap::new();
        let mut current: Option<&str> = None;

        for line in lines {
            if let Some(content) = line.strip_prefix("| ").or((line == "|").then_some("")) {
                let block = blocks
                    .get_mut(current.expect("a document line outside a block"))
                    .unwrap();
                block.extend_from_slice(content.as_bytes());
                block.push(b'\n');
                continue;
            }
            let (key, value) = line.split_once(':').expect("a key: value line");
            let value = value.trim();
            if value.is_empty() {
                blocks.insert(key, Vec::new());
                current = Some(key);
            } else {
                scalars.insert(key, value.to_owned());
                current = None;
            }
        }

        let Some(name) = scalars.get("name").cloned() else {
            continue;
        };
        let mut document = blocks.remove("document").expect("a document");
        if let Some(hex) = scalars.get("body-hex") {
            document.extend(hex::decode(hex).expect("body-hex"));
        }

        out.push(Vector {
            name,
            outcome: scalars["outcome"].clone(),
            rule: scalars.get("rule").cloned(),
            document,
            canonical: blocks.remove("canonical"),
            sealed: blocks.remove("sealed"),
        });
    }

    out
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn vectors_replay() {
    let vectors = vectors();
    assert!(vectors.len() > 20, "only {} vectors read", vectors.len());

    for v in vectors {
        let parsed = parse(&v.document);

        match v.outcome.as_str() {
            "canonical" => {
                let act = parsed.unwrap_or_else(|r| panic!("{}: refused: {r}", v.name));
                let canonical = act.canonical();
                assert_eq!(
                    text(&canonical),
                    text(v.canonical.as_deref().expect("canonical")),
                    "{}",
                    v.name
                );
                assert_eq!(
                    parse(&canonical).map(|a| a.canonical()),
                    Ok(canonical.clone()),
                    "{}: the canonical form is not a fixed point",
                    v.name
                );
                assert_eq!(
                    act.sealed_canonical().map(|s| text(&s)),
                    v.sealed.as_deref().map(text),
                    "{}: sealed form",
                    v.name
                );
            }
            "refuse" => {
                let refusal = parsed
                    .err()
                    .unwrap_or_else(|| panic!("{}: accepted", v.name));
                assert_eq!(
                    Some(refusal.rule.as_str()),
                    v.rule.as_deref(),
                    "{}: refused as {refusal}",
                    v.name
                );
            }
            other => panic!("{}: unknown outcome {other}", v.name),
        }
    }
}

/// The acceptance criterion of the slice: one act, three arrivals, one
/// canonical form.
#[test]
fn three_arrivals_one_canonical_form() {
    let forms: Vec<Vec<u8>> = vectors()
        .into_iter()
        .filter(|v| v.name.starts_with("canonical/root-"))
        .map(|v| parse(&v.document).unwrap().canonical())
        .collect();

    assert_eq!(forms.len(), 4);
    assert!(forms.windows(2).all(|w| w[0] == w[1]));
}

fn approval() -> Act {
    let v = vectors()
        .into_iter()
        .find(|v| v.name == "canonical/approval-with-body")
        .unwrap();
    parse(&v.document).unwrap()
}

#[test]
fn the_body_is_carried_byte_for_byte() {
    let act = approval();
    let body = act.body().unwrap();

    assert_eq!(
        body,
        b"[moxy !clown-plugin-v1\n\t[-> folio !mcp-server-v1 deny]]\n"
    );
    assert!(act.canonical().ends_with(body));
}

#[test]
fn namespace_pairing_is_section_4_8() {
    let card = approval();
    assert_eq!(card.check_namespace_pairing(), Ok(()));

    let narrow = vectors()
        .into_iter()
        .find(|v| v.name == "canonical/narrow-sealed-sets-sort-on-parsed-bytes")
        .map(|v| parse(&v.document).unwrap())
        .unwrap();
    assert_eq!(narrow.check_namespace_pairing(), Ok(()));

    for (from, to) in [
        (
            "- kind = approval",
            "- kind = revocation\n- names = piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400",
        ),
        ("- issuer = operator", "- issuer = clown:x"),
        (
            "- assurance = piggy:hardware",
            "- assurance = piggy:software",
        ),
        (
            "- namespace = piggy-approval-v1",
            "- namespace = piggy-quote-v1",
        ),
    ] {
        let doc = text(&card.canonical()).replace(from, to);
        let act = parse(doc.as_bytes()).unwrap_or_else(|r| panic!("{to}: {r}"));
        assert_eq!(
            act.check_namespace_pairing().map_err(|r| r.rule),
            Err(Rule::NamespacePairing),
            "{to}"
        );
    }
}

/// §3.1 step 2, the cases a vector line cannot carry safely: trailing
/// whitespace and a description line that trims to nothing.
#[test]
fn descriptions_trim_drop_empties_and_join() {
    let lines = ["  a b \t".to_owned(), " \t ".to_owned(), "\tc".to_owned()];
    assert_eq!(merge_descriptions(&lines), Ok(Some("a b c".to_owned())));
    assert_eq!(merge_descriptions(&[" ".to_owned()]), Ok(None));
}

#[test]
fn canon_does_not_apply_the_pairing() {
    let doc = text(&approval().canonical()).replace("- kind = approval", "- kind = escalation");
    // An escalation under piggy-approval-v1 breaks §4.8, which is §5.2
    // step 3, not step 1: canon refuses it only if a step-1 rule does.
    let refusal = parse(doc.as_bytes()).err().map(|r| r.rule);
    assert_ne!(refusal, Some(Rule::NamespacePairing));
}
