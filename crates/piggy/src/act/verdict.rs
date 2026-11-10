//! The verdict document `piggy-act-verdict-v1`: one JSON object for every
//! outcome of `piggy act verify --format json` (RFC 0013 §5.3; the shape is
//! spinclass FDR 0034's, its first consumer). Fields are written in a fixed
//! order, `schema` first.

use std::collections::BTreeMap;

use serde::Serialize;

use super::verify::{Layer, Outcome};

pub const SCHEMA: &str = "piggy-act-verdict-v1";

#[derive(Serialize)]
struct LayerDoc<'a> {
    act: &'a str,
    kind: &'a str,
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a str>,
}

impl<'a> From<&'a Layer> for LayerDoc<'a> {
    fn from(layer: &'a Layer) -> Self {
        let (profile, body) = match layer.role {
            super::verify::Role::Stencil => (Some(layer.content.as_str()), None),
            super::verify::Role::Patch => (None, Some(layer.content.as_str())),
        };
        LayerDoc {
            act: &layer.act,
            kind: &layer.kind,
            role: layer.role.as_str(),
            profile,
            body,
        }
    }
}

#[derive(Serialize, Default)]
struct Doc<'a> {
    schema: &'static str,
    verdict: &'static str,
    /// The asked-about act's digest; null when it could not be computed (an
    /// unparseable or unsealed input).
    act: Option<&'a str>,
    at: &'a str,
    /// `asserted` when the caller asserted the store is a complete
    /// revocation source, `none` otherwise.
    revocation_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Option<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_expiry: Option<Option<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assurance: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_start_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rights: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    layers: Option<Vec<LayerDoc<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefixed: Option<&'a BTreeMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_act: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unresolved: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

/// The verdict for `act` (its digest, when known) at `at`.
pub fn to_json(outcome: &Outcome, act: Option<&str>, at: &str, revocation_source: bool) -> String {
    let mut doc = Doc {
        schema: SCHEMA,
        act,
        at,
        revocation_source: if revocation_source {
            "asserted"
        } else {
            "none"
        },
        ..Doc::default()
    };

    match outcome {
        Outcome::Valid(v) => {
            let carries_rights = v.rights.is_some();
            doc.verdict = "valid";
            doc.kind = Some(&v.kind);
            doc.subject = Some(v.subject.as_deref());
            doc.object = v.object.as_deref();
            doc.effective_expiry = Some(v.effective_expiry.as_deref());
            doc.assurance = Some(&v.assurance);
            doc.chain_start_key = Some(&v.chain_start_key);
            doc.chain = Some(&v.chain);
            doc.rights = v
                .rights
                .as_ref()
                .map(|r| r.iter().map(String::as_str).collect());
            doc.layers = carries_rights.then(|| v.layers.iter().map(LayerDoc::from).collect());
            doc.prefixed = Some(&v.prefixed);
        }
        Outcome::Invalid(f) => {
            doc.verdict = "invalid";
            doc.failed_step = Some(f.step.as_str());
            doc.failed_act = Some(&f.act).filter(|a| !a.is_empty()).map(String::as_str);
            doc.reason = Some(&f.reason);
        }
        Outcome::Undetermined(u) => {
            doc.verdict = "undetermined";
            doc.unresolved = Some(&u.digests);
            doc.reason = Some(&u.reason);
        }
    }

    let mut json = serde_json::to_string(&doc).expect("a verdict always serializes");
    json.push('\n');
    json
}
