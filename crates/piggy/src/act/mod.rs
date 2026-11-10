//! `piggy-act-v1`: one signed act as a hyphence document (piggy RFC 0013).
//!
//! This module reads an act (§1, §2, §5.2 step 1), refuses what the RFC
//! refuses naming the rule, and writes the canonical form (§3.1). The head
//! model and its canonical spelling are hyphence's ([`hyphence::Head`]);
//! piggy adds the field table, the ordering and the refusals. The body is
//! opaque: it is checked against RFC 0012 §2.5's character rule and carried
//! byte for byte, never parsed (§4.9).

pub mod cli;
mod fields;
pub mod produce;
pub mod seal;
pub mod store;
pub mod verify;

use std::fmt;

use hyphence::{Document, Head, HeadLine, Line, Prefix, Value};

pub use fields::{is_card_namespace, parsed_bytes};

/// The type line of an act.
pub const TYPE: &str = "piggy-act-v1";

/// Why a document is not an act. `rule` is a stable name for the rule that
/// refused it, the one the vectors and the CLI report; `detail` says where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub rule: Rule,
    pub detail: String,
}

/// The rules of RFC 0013 §1, §2 and §5.2 step 1 a document can break, plus
/// the §4.8 pairing [`Act::check_namespace_pairing`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Not a hyphence document, or a line its content grammar refuses.
    Envelope,
    /// No `! piggy-act-v1` line, another type, or a second type line.
    Type,
    /// A locked type line.
    TypeLock,
    /// A line kind §1 forbids: a bare `-` tag or reference, `<`, `@`.
    LineKind,
    QuotedFieldName,
    DuplicateField,
    UnknownField,
    MissingField,
    /// A field §2 says MUST be absent here.
    ForbiddenField,
    /// A value outside its §2 cell (or a description outside §1's
    /// character rule).
    Value,
    /// A body outside RFC 0012 §2.5's character rule.
    Body,
    /// A `namespace`/`kind`/`issuer`/`assurance` combination §4.8 does not
    /// list. Never raised by [`parse`].
    NamespacePairing,
    /// §5.2 step 3's other rules: `issuer-key` is not `key`, or a `narrow`'s
    /// `issuer` is not its `subject`. Never raised by [`parse`].
    IssuerBinding,
    /// §5.2 step 2: the signature does not verify under `key`, or a detached
    /// sshsig does not match the seal fields (§3.3). Never raised by
    /// [`parse`].
    Signature,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Envelope => "envelope",
            Rule::Type => "type",
            Rule::TypeLock => "type-lock",
            Rule::LineKind => "line-kind",
            Rule::QuotedFieldName => "quoted-field-name",
            Rule::DuplicateField => "duplicate-field",
            Rule::UnknownField => "unknown-field",
            Rule::MissingField => "missing-field",
            Rule::ForbiddenField => "forbidden-field",
            Rule::Value => "value",
            Rule::Body => "body",
            Rule::NamespacePairing => "namespace-pairing",
            Rule::IssuerBinding => "issuer-binding",
            Rule::Signature => "signature",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.rule.as_str(), self.detail)
    }
}

impl std::error::Error for Refusal {}

fn refuse<T>(rule: Rule, detail: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        rule,
        detail: detail.into(),
    })
}

/// A parsed act: its fields in canonical order (§3.1 step 3), the merged
/// description, and the body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Act {
    description: Option<String>,
    /// Canonical order; set values sorted and deduplicated; `signature`
    /// included when present.
    fields: Vec<(String, Value)>,
    body: Option<Vec<u8>>,
}

/// Read an act, refusing what RFC 0013 §1, §2 and §5.2 step 1 refuse.
/// `signature` is optional here: an unsealed act is what a producer
/// canonicalizes before signing (§3.2).
pub fn parse(input: &[u8]) -> Result<Act, Refusal> {
    let doc = Document::decode(input).or_else(|e| refuse(Rule::Envelope, e.to_string()))?;

    for line in &doc.metadata {
        match line.prefix {
            Prefix::ObjectRef => {
                return refuse(Rule::LineKind, format!("a `<` line: < {}", line.value));
            }
            Prefix::Blob => {
                return refuse(Rule::LineKind, format!("an `@` line: @ {}", line.value));
            }
            _ => {}
        }
    }

    let head = Head::from_document(&doc).or_else(|e| refuse(Rule::Envelope, e.to_string()))?;

    let mut descriptions = Vec::new();
    let mut fields: Vec<(String, Value)> = Vec::new();
    let mut seen_type = false;

    // Head::from_document keeps one typed line per metadata line, in order.
    for (raw, typed) in doc.metadata.iter().zip(&head.lines) {
        match &typed.line {
            Line::Description(text) => descriptions.push(text.clone()),
            Line::Term(value) => {
                return refuse(
                    Rule::LineKind,
                    format!("a bare `-` tag or reference: {}", parsed_bytes(value)),
                );
            }
            Line::Blob(path) => return refuse(Rule::LineKind, format!("an `@` line: {path}")),
            Line::Type { name, lock } => {
                if seen_type {
                    return refuse(Rule::Type, "a second type line");
                }
                seen_type = true;
                if lock.is_some() {
                    return refuse(
                        Rule::TypeLock,
                        format!("the type line is locked: ! {}", raw.value),
                    );
                }
                if name != TYPE {
                    return refuse(Rule::Type, format!("type {name:?}, want {TYPE}"));
                }
            }
            Line::Field { name, value } => {
                if raw.value.starts_with(['"', '\'']) {
                    return refuse(Rule::QuotedFieldName, format!("{name:?}"));
                }
                check_field(name, value, &fields)?;
                fields.push((name.clone(), value.clone()));
            }
        }
    }

    if !seen_type {
        return refuse(Rule::Type, format!("no `! {TYPE}` line"));
    }

    let description = merge_descriptions(&descriptions)?;
    let body = check_body(doc.body)?;

    let act = Act {
        description,
        fields: canonical_order(fields),
        body,
    };
    act.check_admission()?;
    act.check_presence()?;
    act.check_key_purposes()?;

    Ok(act)
}

fn check_field(name: &str, value: &Value, earlier: &[(String, Value)]) -> Result<(), Refusal> {
    match fields::lookup(name) {
        Some((_, spec)) => {
            if !spec.set && earlier.iter().any(|(n, _)| n == name) {
                return refuse(Rule::DuplicateField, format!("`{name}` appears twice"));
            }
            if let Some(problem) = fields::check(spec.shape, value) {
                return refuse(
                    Rule::Value,
                    format!("`{name} = {}` {problem}", parsed_bytes(value)),
                );
            }
            Ok(())
        }
        None if fields::is_prefixed(name) => match fields::check(fields::Shape::Opaque, value) {
            // A consumer's field is opaque like a right: carried and signed.
            None => Ok(()),
            Some(problem) => refuse(
                Rule::Value,
                format!("`{name} = {}` {problem}", parsed_bytes(value)),
            ),
        },
        None => refuse(
            Rule::UnknownField,
            format!("`{name}` is not an RFC 0013 §2 field"),
        ),
    }
}

/// §3.1 step 2: trim each `#` line of ASCII space and TAB, drop the empty
/// ones, join the rest with single spaces.
fn merge_descriptions(lines: &[String]) -> Result<Option<String>, Refusal> {
    let kept: Vec<&str> = lines
        .iter()
        .map(|l| l.trim_matches([' ', '\t']))
        .filter(|l| !l.is_empty())
        .collect();

    if kept.is_empty() {
        return Ok(None);
    }

    let merged = kept.join(" ");
    if let Some(c) = merged.chars().find(|&c| c != '\t' && c.is_control()) {
        return refuse(
            Rule::Value,
            format!("a description holds the control character {c:?}"),
        );
    }

    Ok(Some(merged))
}

/// §1, §4.9: a body is opaque bytes that obey RFC 0012 §2.5's character
/// rule. A separator with nothing after it is not a body (§3.1 step 7).
fn check_body(body: Option<Vec<u8>>) -> Result<Option<Vec<u8>>, Refusal> {
    match body {
        None => Ok(None),
        Some(bytes) if bytes.is_empty() => Ok(None),
        Some(bytes) => {
            // Characters only: the 4096-byte cap is the card act's
            // whole-text rule (§3.4), not the body's.
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return refuse(Rule::Body, "the body is not UTF-8");
            };
            if let Some(c) = text
                .chars()
                .find(|&c| c != '\n' && c != '\t' && c.is_control())
            {
                return refuse(
                    Rule::Body,
                    format!("the body holds the control character {c:?}"),
                );
            }
            Ok(Some(bytes))
        }
    }
}

/// §3.1 step 3: piggy's fields in table order, then prefixed fields by name
/// as bytes; set values (and a prefixed field's values) sorted as bytes over
/// their parsed form and deduplicated.
fn canonical_order(mut fields: Vec<(String, Value)>) -> Vec<(String, Value)> {
    let rank = |name: &str| fields::lookup(name).map_or(usize::MAX, |(i, _)| i);

    fields.sort_by(|(a_name, a_value), (b_name, b_value)| {
        rank(a_name)
            .cmp(&rank(b_name))
            .then_with(|| a_name.as_bytes().cmp(b_name.as_bytes()))
            .then_with(|| parsed_bytes(a_value).cmp(&parsed_bytes(b_value)))
    });
    fields.dedup_by(|(a_name, a_value), (b_name, b_value)| {
        a_name == b_name && parsed_bytes(a_value) == parsed_bytes(b_value)
    });

    fields
}

impl Act {
    /// The canonical form (§3.1): what is signed and shown at the prompt.
    pub fn canonical(&self) -> Vec<u8> {
        self.encode(false)
    }

    /// The sealed canonical form (§3.5), the bytes the act digest is over:
    /// the canonical form with its `signature` line. `None` when the act is
    /// not sealed.
    pub fn sealed_canonical(&self) -> Option<Vec<u8>> {
        self.field("signature").map(|_| self.encode(true))
    }

    /// This act sealed with `signature` (a `piggy-record-sig-v1` id); any
    /// earlier signature is replaced.
    pub fn with_signature(&self, signature: &piggy_markl::Id) -> Act {
        // A piggy-markl id always has a well-formed digest slot, and the
        // record-sig purpose is spelled bare.
        let wire = signature.to_wire();
        let (_, digest) = piggy_markl::split_purpose_slot(&wire);
        let value = Value::Markl(hyphence::MarklId {
            purpose: signature.purpose().map(|p| p.as_str().to_owned()),
            digest: hyphence::Digest::parse(digest).expect("a piggy-markl digest slot"),
        });

        let mut fields: Vec<_> = self
            .fields
            .iter()
            .filter(|(name, _)| name != "signature")
            .cloned()
            .collect();
        fields.push(("signature".to_owned(), value));

        Act {
            fields: canonical_order(fields),
            ..self.clone()
        }
    }

    /// The single value of a non-set field.
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields
            .iter()
            .find_map(|(n, v)| (n == name).then_some(v))
    }

    /// The single value of a non-set field, as text.
    pub fn text(&self, name: &str) -> Option<&str> {
        match self.field(name)? {
            Value::Text(t) => Some(t),
            Value::Markl(_) => None,
        }
    }

    /// Every value of a field, in canonical order.
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.fields
            .iter()
            .filter_map(move |(n, v)| (n == name).then_some(v))
    }

    /// The consumer's fields (§2, prefixed names), each with its values in
    /// canonical order (parsed form).
    pub fn prefixed_fields(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut out = std::collections::BTreeMap::<String, Vec<String>>::new();
        for (name, value) in &self.fields {
            if fields::lookup(name).is_none() {
                out.entry(name.clone())
                    .or_default()
                    .push(parsed_bytes(value));
            }
        }
        out
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }

    /// Whether the seal names a card namespace (an act signed through
    /// `operator-act@piggy`) rather than `piggy-record-v1`.
    pub fn is_card_act(&self) -> bool {
        self.text("namespace").is_some_and(is_card_namespace)
    }

    fn kind(&self) -> &str {
        self.text("kind").unwrap_or_default()
    }

    fn encode(&self, with_signature: bool) -> Vec<u8> {
        let mut lines = Vec::new();

        if let Some(description) = &self.description {
            lines.push(HeadLine::new(Line::Description(description.clone())));
        }
        for (name, value) in &self.fields {
            if name == "signature" && !with_signature {
                continue;
            }
            lines.push(HeadLine::new(Line::Field {
                name: name.clone(),
                value: value.clone(),
            }));
        }
        lines.push(HeadLine::new(Line::Type {
            name: TYPE.into(),
            lock: None,
        }));

        let head = Head {
            lines,
            ..Head::default()
        };

        // Every line came through parse: descriptions hold no line feed and
        // the type name is an identifier, so the encoder has nothing to
        // refuse.
        head.encode(self.body.as_deref())
            .expect("a parsed act always has a canonical spelling")
    }

    /// §2's Required column read as the admission list: a field whose cell
    /// names kinds appears on those kinds only. An act with no `kind` is
    /// left to [`Act::check_presence`].
    fn check_admission(&self) -> Result<(), Refusal> {
        let Some(kind) = self.text("kind") else {
            return Ok(());
        };

        for (name, _) in &self.fields {
            if let Some((_, spec)) = fields::lookup(name) {
                if spec.kinds.is_some_and(|kinds| !kinds.contains(&kind)) {
                    return refuse(
                        Rule::ForbiddenField,
                        format!("`{name}` is not admitted on a {kind}"),
                    );
                }
            }
        }

        Ok(())
    }

    /// §2's Required column, by `kind` and by whether the act is a card act.
    fn check_presence(&self) -> Result<(), Refusal> {
        for always in [
            "kind",
            "producer",
            "issuer",
            "issuer-key",
            "issued-at",
            "assurance",
            "key",
            "namespace",
            "hash",
        ] {
            self.require(always, "every act")?;
        }

        let kind = self.kind();
        let card = self.is_card_act();
        let certifying = matches!(kind, "root" | "link");

        if !matches!(kind, "approval" | "revocation") {
            self.require("subject", kind)?;
        }
        if certifying {
            self.require("subject-key", kind)?;
        }
        if kind == "grant" {
            self.require("object", kind)?;
        }
        if matches!(kind, "root" | "link" | "grant" | "narrow" | "escalation") {
            self.require("right", kind)?;
        }
        if matches!(kind, "narrow" | "escalation" | "revocation") {
            self.require("names", kind)?;
        }
        if kind == "approval" {
            self.require("records", kind)?;
        }

        if card {
            if self.field("issuer-record").is_some() {
                return refuse(
                    Rule::ForbiddenField,
                    "`issuer-record` on a card act (its key is the trust anchor)",
                );
            }
            if certifying {
                self.require("not-after", "a card certifying act")?;
            }
        } else {
            self.require("issuer-record", "a software act")?;
        }

        Ok(())
    }

    fn require(&self, name: &str, why: &str) -> Result<(), Refusal> {
        if self.values(name).next().is_none() {
            return refuse(Rule::MissingField, format!("`{name}` is required on {why}"));
        }
        Ok(())
    }

    /// §2's `issuer-key` and `key` rows: `piggy-piv_sig-v1` on a card act,
    /// `piggy-principal_pub-v1` on a software act.
    fn check_key_purposes(&self) -> Result<(), Refusal> {
        let want = if self.is_card_act() {
            "piggy-piv_sig-v1"
        } else {
            "piggy-principal_pub-v1"
        };

        for name in ["issuer-key", "key"] {
            if let Some(Value::Markl(id)) = self.field(name) {
                if id.purpose.as_deref() != Some(want) {
                    return refuse(
                        Rule::Value,
                        format!(
                            "`{name}` must be a {want} key on {} act",
                            if self.is_card_act() {
                                "a card"
                            } else {
                                "a software"
                            }
                        ),
                    );
                }
            }
        }

        Ok(())
    }

    /// The rest of RFC 0013 §5.2 step 3: `issuer-key` equals `key`, and a
    /// `narrow`'s `issuer` is its `subject`. Like the pairing, a producer
    /// applies it before asking for a signature; canonicalizing does not.
    pub fn check_issuer_binding(&self) -> Result<(), Refusal> {
        let spelled = |name| self.field(name).map(parsed_bytes);
        if spelled("issuer-key") != spelled("key") {
            return refuse(Rule::IssuerBinding, "`issuer-key` is not `key`");
        }
        if self.kind() == "narrow" && self.text("issuer") != self.text("subject") {
            return refuse(
                Rule::IssuerBinding,
                "a narrow is signed by its subject: `issuer` must be `subject`",
            );
        }
        Ok(())
    }

    /// RFC 0013 §4.8 (with §4.7): the seal's namespace allows this `kind`,
    /// this `issuer` and this `assurance`. §5.2 step 3 applies it; a producer
    /// applies it before asking for a signature. Canonicalizing does not.
    pub fn check_namespace_pairing(&self) -> Result<(), Refusal> {
        let namespace = self.text("namespace").unwrap_or_default();
        let kind = self.kind();

        let (card, kinds): (bool, &[&str]) = match namespace {
            "piggy-certificate-v1" => (true, &["root", "link"]),
            "piggy-escalation-v1" => (true, &["escalation", "grant"]),
            "piggy-approval-v1" => (true, &["approval"]),
            "piggy-revocation-v1" => (true, &["revocation"]),
            "piggy-record-v1" => (false, &["link", "grant", "narrow", "revocation"]),
            other => {
                return refuse(
                    Rule::NamespacePairing,
                    format!("namespace {other} carries no act"),
                );
            }
        };

        if !kinds.contains(&kind) {
            return refuse(
                Rule::NamespacePairing,
                format!("kind {kind} is not allowed under {namespace}"),
            );
        }

        let issuer = self.text("issuer").unwrap_or_default();
        if card != (issuer == "operator") {
            return refuse(
                Rule::NamespacePairing,
                format!("issuer {issuer} under {namespace}"),
            );
        }

        let assurance = self.text("assurance").unwrap_or_default();
        if card != (assurance == "piggy:hardware") {
            return refuse(
                Rule::NamespacePairing,
                format!("assurance {assurance} under {namespace}"),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod tests;
