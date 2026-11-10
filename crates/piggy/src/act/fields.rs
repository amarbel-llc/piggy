//! The RFC 0013 §2 field table: which unprefixed fields an act may carry, in
//! what order (the order of the table is the canonical order, §3.1 step 3),
//! which repeat as a set, and what value each admits.

use hyphence::{Head, HeadLine, Line, MarklId, Value};
use piggy_markl::{FormatId, Id, PurposeId};

use crate::operator_act::display_class;

/// One row of the §2 table.
pub struct FieldSpec {
    pub name: &'static str,
    /// Repeatable, one line per value; the values form a set.
    pub set: bool,
    pub shape: Shape,
    /// The kinds the field may appear on, when its Required cell names
    /// kinds; `None` admits it on every kind. The Required column is also
    /// the admission list (§2).
    pub kinds: Option<&'static [&'static str]>,
}

/// The value a field admits. Each variant is one "Values" cell of §2.
#[derive(Clone, Copy)]
pub enum Shape {
    OneOf(&'static [&'static str]),
    /// `<domain>:<name>`, spelled bare.
    Namespaced,
    /// An opaque word hyphence spells bare (no reserved runes).
    Bare,
    /// Opaque to piggy, compared by bytes only (§4.2): a right, or a
    /// consumer's prefixed field. Any text (quoted when hyphence must quote
    /// it) or a markl id as hyphence reads one (`roustabout:grammar:x@…`).
    Opaque,
    /// A principal id, or `operator`: the same lexeme as [`Shape::Bare`].
    Issuer,
    /// A public key: one of the purposes, format Ed25519 or P-256 in the SSH
    /// key form.
    Key(&'static [PurposeId]),
    /// A record digest: `piggy-record-digest-v1`, sha256 or blake2b256. An act
    /// digest (§3.5) is one.
    RecordDigest,
    /// Any markl-id piggy-markl decodes (a consumer's record).
    AnyMarkl,
    /// A markl-id or an opaque bare word (the consumer's naming).
    MarklOrBare,
    /// A hyphence RFC 0003 locked edge, `<name>@<digest>`.
    LockedEdge,
    Timestamp,
    Hash,
    Namespace,
    Signature,
}

pub const KINDS: &[&str] = &[
    "root",
    "link",
    "grant",
    "narrow",
    "escalation",
    "approval",
    "revocation",
];

const PRINCIPAL_KEY: &[PurposeId] = &[PurposeId::PiggyPrincipalPubV1];
const SIGNING_KEY: &[PurposeId] = &[PurposeId::PiggyPivSigV1, PurposeId::PiggyPrincipalPubV1];

/// The namespaces an act's seal may name: RFC 0012 §3's registry.
const NAMESPACES: &[&str] = &[
    "piggy-quote-v1",
    "piggy-escalation-v1",
    "piggy-certificate-v1",
    "piggy-approval-v1",
    "piggy-revocation-v1",
    "piggy-record-v1",
];

/// RFC 0013 §2, in table order.
pub const TABLE: &[FieldSpec] = &[
    spec("kind", Shape::OneOf(KINDS)),
    spec("producer", Shape::Namespaced),
    spec("subject", Shape::Bare).on(&["root", "link", "grant", "narrow", "escalation"]),
    spec("subject-key", Shape::Key(PRINCIPAL_KEY)).on(&["root", "link"]),
    spec("object", Shape::MarklOrBare).on(&["grant", "escalation", "revocation"]),
    spec("profile", Shape::LockedEdge).on(&["root", "link", "grant", "escalation", "narrow"]),
    spec("issuer", Shape::Issuer),
    spec("issuer-key", Shape::Key(SIGNING_KEY)),
    spec("issuer-record", Shape::RecordDigest),
    set("right", Shape::Opaque).on(&["root", "link", "grant", "narrow", "escalation"]),
    set("names", Shape::RecordDigest).on(&["narrow", "escalation", "revocation", "approval"]),
    set("records", Shape::AnyMarkl).on(&["approval", "escalation", "root", "link"]),
    set("prev", Shape::RecordDigest),
    spec("not-before", Shape::Timestamp),
    spec("not-after", Shape::Timestamp),
    spec("issued-at", Shape::Timestamp),
    spec("assurance", Shape::Namespaced),
    spec("nonce", Shape::Bare),
    spec("key", Shape::Key(SIGNING_KEY)),
    spec("namespace", Shape::Namespace),
    spec("hash", Shape::Hash),
    spec("signature", Shape::Signature),
];

const fn spec(name: &'static str, shape: Shape) -> FieldSpec {
    FieldSpec {
        name,
        set: false,
        shape,
        kinds: None,
    }
}

const fn set(name: &'static str, shape: Shape) -> FieldSpec {
    FieldSpec {
        name,
        set: true,
        shape,
        kinds: None,
    }
}

impl FieldSpec {
    const fn on(self, kinds: &'static [&'static str]) -> FieldSpec {
        FieldSpec {
            kinds: Some(kinds),
            ..self
        }
    }
}

/// The table row for an unprefixed field name, with its canonical position.
pub fn lookup(name: &str) -> Option<(usize, &'static FieldSpec)> {
    TABLE.iter().enumerate().find(|(_, spec)| spec.name == name)
}

/// A consumer's field: `<prefix>:<rest>`, both parts non-empty (§2).
pub fn is_prefixed(name: &str) -> bool {
    matches!(name.split_once(':'), Some((prefix, rest)) if !prefix.is_empty() && !rest.is_empty())
}

/// Whether the seal's namespace is one signed through `operator-act@piggy`
/// (a card act) rather than an ordinary sign request.
pub fn is_card_namespace(namespace: &str) -> bool {
    display_class(namespace).is_some()
}

/// A value's parsed (unquoted) form, the bytes a set sorts and dedups on
/// (§3.1 step 3): a text as itself, a markl id as its unquoted purpose, `@`,
/// then `format-data`.
pub fn parsed_bytes(value: &Value) -> String {
    match value {
        Value::Text(text) => text.clone(),
        Value::Markl(MarklId { purpose, digest }) => {
            format!("{}@{digest}", purpose.as_deref().unwrap_or(""))
        }
    }
}

/// A markl id spelled for piggy-markl's parser (purpose quoted when needed).
fn markl_text(id: &MarklId) -> String {
    match &id.purpose {
        Some(purpose) => format!("{}@{}", piggy_markl::spell_purpose(purpose), id.digest),
        None => format!("@{}", id.digest),
    }
}

/// Why a value is outside its §2 cell, or `None` when it is inside.
pub fn check(shape: Shape, value: &Value) -> Option<String> {
    if let Some(problem) = control_character(value) {
        return Some(problem);
    }

    match shape {
        Shape::OneOf(allowed) => match text(value) {
            Some(t) if allowed.contains(&t) => None,
            _ => Some(format!("must be one of {}", allowed.join(", "))),
        },
        Shape::Namespaced => match text(value) {
            Some(t) if spells_bare(t) && is_prefixed(t) => None,
            _ => Some("must be a bare <domain>:<name>".into()),
        },
        Shape::Bare | Shape::Issuer => match text(value) {
            Some(t) if spells_bare(t) => None,
            _ => Some("must be a bare word (no reserved runes)".into()),
        },
        // Opaque: any text (quoted when it must be) or markl id, held to the
        // character rule above and nothing else.
        Shape::Opaque => None,
        Shape::Key(purposes) => {
            let id = markl(value);
            let ok = id.as_ref().is_ok_and(|id| {
                id.purpose().is_some_and(|p| purposes.contains(p))
                    && matches!(
                        id.format(),
                        FormatId::SshEd25519Pub | FormatId::SshEcdsaNistp256Pub
                    )
            });
            // §2 "Key payloads": a P-256 payload that does not decompress is
            // a value outside §2 (§5.2 step 1).
            if let Ok(id) = &id {
                if ok && id.format() == FormatId::SshEcdsaNistp256Pub {
                    if let Err(refusal) = super::seal::decompress_p256(id.data()) {
                        return Some(refusal.detail);
                    }
                }
            }
            (!ok).then(|| {
                let names: Vec<_> = purposes.iter().map(PurposeId::as_str).collect();
                format!(
                    "must be a {} markl-id, format ssh_ed25519_pub or ssh_ecdsa_nistp256_pub{}",
                    names.join(" or "),
                    decode_detail(&id)
                )
            })
        }
        Shape::RecordDigest => {
            let id = markl(value);
            let ok = id.as_ref().is_ok_and(|id| {
                id.purpose() == Some(&PurposeId::PiggyRecordDigestV1)
                    && matches!(id.format(), FormatId::Sha256 | FormatId::Blake2b256)
            });
            (!ok).then(|| {
                format!(
                    "must be a piggy-record-digest-v1 markl-id, sha256 or blake2b256{}",
                    decode_detail(&id)
                )
            })
        }
        Shape::AnyMarkl => match markl(value) {
            Ok(_) => None,
            Err(e) => Some(format!("must be a markl-id: {e}")),
        },
        Shape::MarklOrBare => match value {
            Value::Text(t) if spells_bare(t) => None,
            Value::Text(_) => Some("must be a markl-id or a bare word".into()),
            Value::Markl(_) => match markl(value) {
                Ok(_) => None,
                Err(e) => Some(format!("must be a markl-id or a bare word: {e}")),
            },
        },
        Shape::LockedEdge => match value {
            Value::Markl(MarklId {
                purpose: Some(_),
                digest,
            }) => match Id::parse(&digest.to_string()) {
                Ok(_) => None,
                Err(e) => Some(format!("the lock is not a markl digest: {e}")),
            },
            _ => Some("must be a locked edge, <name>@<digest>".into()),
        },
        Shape::Timestamp => match text(value) {
            Some(t) if is_timestamp(t) => None,
            _ => Some("must be a timestamp spelled YYYY-MM-DDThh:mm:ssZ".into()),
        },
        Shape::Hash => match text(value) {
            Some("sha256" | "sha512") => None,
            _ => Some("must be sha256 or sha512".into()),
        },
        Shape::Namespace => match text(value) {
            Some(t) if NAMESPACES.contains(&t) => None,
            _ => Some(format!(
                "must be an RFC 0012 §3 namespace: {}",
                NAMESPACES.join(", ")
            )),
        },
        Shape::Signature => {
            let id = markl(value);
            let ok = id.as_ref().is_ok_and(|id| {
                id.purpose() == Some(&PurposeId::PiggyRecordSigV1)
                    && matches!(id.format(), FormatId::Ed25519Sig | FormatId::EcdsaP256Sig)
            });
            (!ok).then(|| {
                format!(
                    "must be a piggy-record-sig-v1 markl-id, ed25519_sig or ecdsa_p256_sig{}",
                    decode_detail(&id)
                )
            })
        }
    }
}

fn text(value: &Value) -> Option<&str> {
    match value {
        Value::Text(t) => Some(t),
        Value::Markl(_) => None,
    }
}

/// The value decoded by piggy-markl; a text value is not a markl-id.
fn markl(value: &Value) -> Result<Id, String> {
    match value {
        Value::Markl(id) => Id::parse(&markl_text(id)).map_err(|e| e.to_string()),
        Value::Text(_) => Err("not a markl-id".into()),
    }
}

fn decode_detail(id: &Result<Id, String>) -> String {
    match id {
        Err(e) => format!(" ({e})"),
        Ok(_) => String::new(),
    }
}

/// RFC 0012 §2.5's character rule applied to a value: no C0 or C1 control
/// other than TAB (a value is one line, so LF is out too).
fn control_character(value: &Value) -> Option<String> {
    parsed_bytes(value)
        .chars()
        .find(|&c| c != '\t' && c.is_control())
        .map(|c| format!("holds the control character {c:?}"))
}

/// Whether hyphence's canonical encoder writes `text` bare (a valid bare word
/// under the strict sigil rule) rather than quoted.
pub fn spells_bare(text: &str) -> bool {
    let probe = Head {
        lines: vec![HeadLine::new(Line::Field {
            name: "x".into(),
            value: Value::Text(text.into()),
        })],
        ..Head::default()
    };

    probe
        .encode(None)
        .is_ok_and(|bytes| bytes == format!("---\n- x = {text}\n---\n").as_bytes())
}

/// RFC 0013 §2's one RFC 3339 spelling: `YYYY-MM-DDThh:mm:ssZ`, with every
/// field in range.
pub(super) fn is_timestamp(t: &str) -> bool {
    let b = t.as_bytes();
    if b.len() != 20 {
        return false;
    }

    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        b[range.clone()]
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| t[range].parse().ok())
            .flatten()
    };

    let shape = b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z';
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return false;
    };

    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };

    shape && (1..=days_in_month).contains(&day) && hour < 24 && minute < 60 && second < 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_have_one_spelling() {
        for ok in ["2026-11-09T23:00:00Z", "2024-02-29T00:00:00Z"] {
            assert!(is_timestamp(ok), "{ok}");
        }
        for bad in [
            "2026-11-09T23:00:00+00:00",
            "2026-11-09t23:00:00z",
            "2026-11-09T23:00:00.5Z",
            "2026-11-09 23:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-09T24:00:00Z",
            "2026-11-09T23:60:00Z",
            "+026-11-09T23:00:00Z",
        ] {
            assert!(!is_timestamp(bad), "{bad}");
        }
    }

    #[test]
    fn bare_words_are_what_hyphence_writes_bare() {
        for ok in [
            "root",
            "clown:72dca00c-1c93",
            "spinclass:profile:dev",
            "piggy:hardware",
        ] {
            assert!(spells_bare(ok), "{ok}");
        }
        for bad in ["a b", "a,b", "", "a\"b", "todo:"] {
            assert!(!spells_bare(bad), "{bad}");
        }
    }

    #[test]
    fn the_table_order_is_the_rfc_order() {
        let names: Vec<_> = TABLE.iter().map(|s| s.name).collect();
        assert_eq!(names.first(), Some(&"kind"));
        assert_eq!(names.last(), Some(&"signature"));
        assert_eq!(
            names.iter().position(|n| *n == "hash"),
            Some(names.len() - 2)
        );
    }
}
