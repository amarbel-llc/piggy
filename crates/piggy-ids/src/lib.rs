//! `piggy-ids` text recipient file format.
//!
//! Pinned by piggy RFC 0003 (`docs/rfcs/0003-piggy-ids-file-format.md`).
//! One recipient per line, with optional inline comment:
//!
//! ```text
//! # comments and blank lines ignored
//! piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # primary yubikey
//! piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # backup
//! ```
//!
//! Parser is permissive about purpose tagging on input — bare
//! `pivy_ecdh_p256_pub-<blech32>` is accepted as syntactic sugar for
//! the purpose-tagged form. Renderer always emits the purpose-tagged
//! canonical form so `parse → render → parse` round-trips to a stable
//! representation.

use thiserror::Error;

use piggy_markl::{FormatId, Id, ParseError as MarklParseError, PurposeId};

pub mod classify;
pub use classify::{classify_slot_9d, Classification};

/// One recipient line: a markl ID plus an optional human comment.
/// Equality is by markl ID alone — comments don't participate in
/// `Diff` so re-running `recipients sync` after a rename is a no-op.
#[derive(Debug, Clone)]
pub struct Recipient {
    id: Id,
    comment: Option<String>,
}

impl Recipient {
    /// Construct a recipient. The id MUST carry the
    /// `piggy-recipient-v1` purpose and the `pivy_ecdh_p256_pub`
    /// format; otherwise `InvalidRecipientShape` is returned.
    pub fn new(id: Id, comment: Option<String>) -> Result<Self, ParseError> {
        validate_recipient_shape(&id)?;
        Ok(Self { id, comment })
    }

    pub fn id(&self) -> &Id {
        &self.id
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Set or replace the inline comment.
    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Recipient {}

impl core::hash::Hash for Recipient {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Match PartialEq: hash by id only.
        self.id.purpose().hash(state);
        self.id.format().hash(state);
        self.id.data().hash(state);
    }
}

/// Parsed contents of a `piggy-ids` file. Input order is preserved;
/// `render()` emits recipients in the same order they were parsed.
#[derive(Debug, Default, Clone)]
pub struct RecipientFile {
    recipients: Vec<Recipient>,
}

impl RecipientFile {
    pub fn new(recipients: Vec<Recipient>) -> Self {
        Self { recipients }
    }

    pub fn recipients(&self) -> &[Recipient] {
        &self.recipients
    }

    pub fn into_recipients(self) -> Vec<Recipient> {
        self.recipients
    }

    pub fn push(&mut self, recipient: Recipient) {
        self.recipients.push(recipient);
    }

    /// Parse a `piggy-ids` text file. Blank lines and comment-only
    /// lines (starting with `#` after optional leading whitespace)
    /// are skipped. All other lines must contain a markl ID
    /// satisfying the recipient shape; trailing `# ...` is parsed
    /// as the recipient's inline comment.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let mut recipients = Vec::new();
        for (idx, raw) in input.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            recipients.push(parse_line(raw, line_no)?);
        }
        Ok(Self { recipients })
    }

    /// Render to canonical form. Each recipient becomes a line:
    /// `<purpose>@<format>-<blech32>` followed by `  # <comment>`
    /// when the recipient has a comment. Trailing newline.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for r in &self.recipients {
            // Always promote to purpose-tagged form on render.
            let canonical_id = canonicalize_for_render(&r.id);
            out.push_str(&canonical_id.to_wire());
            if let Some(comment) = &r.comment {
                out.push_str("  # ");
                out.push_str(comment);
            }
            out.push('\n');
        }
        out
    }

    /// Compute the symmetric difference between this file (treated
    /// as the *current* recipient set) and `desired`. Equality is by
    /// markl ID; comments do not participate.
    pub fn diff<'a>(&'a self, desired: &'a Self) -> Diff<'a> {
        let current: std::collections::HashSet<&Id> =
            self.recipients.iter().map(|r| &r.id).collect();
        let next: std::collections::HashSet<&Id> =
            desired.recipients.iter().map(|r| &r.id).collect();

        let added: Vec<&Recipient> = desired
            .recipients
            .iter()
            .filter(|r| !current.contains(&r.id))
            .collect();
        let removed: Vec<&Recipient> = self
            .recipients
            .iter()
            .filter(|r| !next.contains(&r.id))
            .collect();
        let retained: Vec<&Recipient> = self
            .recipients
            .iter()
            .filter(|r| next.contains(&r.id))
            .collect();

        Diff { added, removed, retained }
    }
}

/// Result of comparing two `RecipientFile`s by markl ID.
#[derive(Debug)]
pub struct Diff<'a> {
    pub added: Vec<&'a Recipient>,
    pub removed: Vec<&'a Recipient>,
    pub retained: Vec<&'a Recipient>,
}

impl<'a> Diff<'a> {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("line {line}: failed to parse markl ID {token:?}: {source}")]
    Markl {
        line: usize,
        token: String,
        #[source]
        source: MarklParseError,
    },
    #[error(
        "line {line}: recipient shape requires purpose=piggy-recipient-v1 and \
         format=pivy_ecdh_p256_pub (got purpose={purpose:?}, format={format:?})"
    )]
    InvalidRecipientShape {
        line: usize,
        purpose: Option<PurposeId>,
        format: FormatId,
    },
    #[error("line {line}: empty token where markl ID was expected")]
    EmptyToken { line: usize },
}

fn validate_recipient_shape(id: &Id) -> Result<(), ParseError> {
    let purpose_ok = matches!(id.purpose(), Some(PurposeId::PiggyRecipientV1));
    let format_ok = matches!(id.format(), FormatId::PivyEcdhP256Pub);
    if purpose_ok && format_ok {
        Ok(())
    } else {
        Err(ParseError::InvalidRecipientShape {
            line: 0, // overwritten by callers that have line context
            purpose: id.purpose().cloned(),
            format: id.format(),
        })
    }
}

fn canonicalize_for_render(id: &Id) -> Id {
    if id.purpose().is_some() {
        id.clone()
    } else {
        // Bare markl ID (no purpose): promote to purpose-tagged form.
        // Validated at parse-time that the format is
        // pivy_ecdh_p256_pub, so re-construction can't fail.
        Id::new(
            Some(PurposeId::PiggyRecipientV1),
            id.format(),
            id.data().to_vec(),
        )
        .expect("canonicalize_for_render: validated input cannot fail Id::new")
    }
}

/// Split a non-blank, non-comment-only line into `(markl_token, comment)`.
fn split_token_and_comment(line: &str) -> (&str, Option<&str>) {
    // Strip leading whitespace; the markl token runs until the first
    // ASCII whitespace, since the markl ID grammar admits only
    // [a-z0-9@_-] (lowercase) or all-uppercase.
    let trimmed = line.trim_start();
    let token_end = trimmed
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(trimmed.len());
    let token = &trimmed[..token_end];
    let rest = trimmed[token_end..].trim_start();
    if let Some(stripped) = rest.strip_prefix('#') {
        Some((token, Some(stripped.trim())))
    } else if rest.is_empty() {
        Some((token, None))
    } else {
        // Unrecognised trailing content (no `#`). Treat as malformed
        // for now — the issue spec doesn't carve out a use case. We
        // could be more permissive later.
        None
    }
    .unwrap_or((token, None))
}

fn parse_line(raw: &str, line_no: usize) -> Result<Recipient, ParseError> {
    let (token, comment) = split_token_and_comment(raw);
    if token.is_empty() {
        return Err(ParseError::EmptyToken { line: line_no });
    }

    let id = Id::parse(token).map_err(|e| ParseError::Markl {
        line: line_no,
        token: token.to_string(),
        source: e,
    })?;

    // Validate purpose AND format. Permit bare format on input
    // (no purpose) — we'll canonicalise on render.
    let format_ok = matches!(id.format(), FormatId::PivyEcdhP256Pub);
    let purpose_ok = matches!(id.purpose(), None | Some(PurposeId::PiggyRecipientV1));
    if !(purpose_ok && format_ok) {
        return Err(ParseError::InvalidRecipientShape {
            line: line_no,
            purpose: id.purpose().cloned(),
            format: id.format(),
        });
    }

    Ok(Recipient {
        id,
        comment: comment.map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey(seed: u8) -> Vec<u8> {
        let mut v = vec![0x03];
        v.extend((0..32u8).map(|i| i.wrapping_mul(seed).wrapping_add(seed)));
        v
    }

    fn sample_id(seed: u8) -> Id {
        Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            sample_pubkey(seed),
        )
        .unwrap()
    }

    #[test]
    fn parse_renders_round_trip_purpose_tagged() {
        let id = sample_id(7);
        let r = Recipient::new(id, Some("primary yubikey".to_string())).unwrap();
        let file = RecipientFile::new(vec![r]);
        let rendered = file.render();
        let reparsed = RecipientFile::parse(&rendered).unwrap();
        assert_eq!(reparsed.recipients().len(), 1);
        assert_eq!(reparsed.recipients()[0].id(), file.recipients()[0].id());
        assert_eq!(
            reparsed.recipients()[0].comment(),
            Some("primary yubikey")
        );
    }

    #[test]
    fn parse_accepts_bare_format_on_input_renders_purpose_tagged() {
        let id = sample_id(11);
        // Build a bare-format wire string by encoding without purpose.
        let bare = Id::new(None, FormatId::PivyEcdhP256Pub, id.data().to_vec())
            .unwrap()
            .to_wire();
        let input = format!("{bare}\n");
        let file = RecipientFile::parse(&input).unwrap();
        let rendered = file.render();
        assert!(rendered.starts_with("piggy-recipient-v1@pivy_ecdh_p256_pub-"));
    }

    #[test]
    fn parse_skips_blank_and_comment_lines() {
        let id_a = sample_id(13);
        let id_b = sample_id(17);
        let input = format!(
            "# top comment\n\n   # indented comment\n{}  # a\n\n{}\n",
            id_a.to_wire(),
            id_b.to_wire(),
        );
        let file = RecipientFile::parse(&input).unwrap();
        assert_eq!(file.recipients().len(), 2);
        assert_eq!(file.recipients()[0].comment(), Some("a"));
        assert_eq!(file.recipients()[1].comment(), None);
    }

    #[test]
    fn parse_rejects_wrong_purpose() {
        // Sha256 with the dodder-blob-digest purpose: valid markl ID,
        // valid (purpose, format) pair per RFC 0002, but not a
        // recipient shape.
        let id = Id::new(
            Some(PurposeId::DodderBlobDigestSha256V1),
            FormatId::Sha256,
            vec![0u8; 32],
        )
        .unwrap();
        let input = id.to_wire();
        let err = RecipientFile::parse(&input).unwrap_err();
        assert!(matches!(err, ParseError::InvalidRecipientShape { .. }));
    }

    #[test]
    fn parse_rejects_wrong_format_with_piggy_purpose() {
        // PiggyRecipientV1 paired with sha256 already fails at the
        // markl level (Incompatible). We surface that as Markl error.
        // Construct manually via wire string to bypass the markl
        // constructor's validation:
        //
        // Encode 32 bytes under sha256 HRP, then prepend the piggy
        // purpose. The markl decoder's validate_format rejects.
        let payload = vec![0x42u8; 32];
        let body = piggy_markl::blech32::encode("sha256", &payload).unwrap();
        let wire = format!("piggy-recipient-v1@{body}");
        let err = RecipientFile::parse(&wire).unwrap_err();
        assert!(matches!(err, ParseError::Markl { .. }));
    }

    #[test]
    fn diff_added_removed_retained() {
        let a = sample_id(2);
        let b = sample_id(3);
        let c = sample_id(5);
        let current = RecipientFile::new(vec![
            Recipient::new(a.clone(), None).unwrap(),
            Recipient::new(b.clone(), None).unwrap(),
        ]);
        let desired = RecipientFile::new(vec![
            Recipient::new(b.clone(), None).unwrap(),
            Recipient::new(c.clone(), None).unwrap(),
        ]);
        let d = current.diff(&desired);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].id(), &c);
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].id(), &a);
        assert_eq!(d.retained.len(), 1);
        assert_eq!(d.retained[0].id(), &b);
    }

    #[test]
    fn diff_with_changed_comments_only_is_no_op() {
        let id = sample_id(19);
        let current = RecipientFile::new(vec![
            Recipient::new(id.clone(), Some("old comment".into())).unwrap(),
        ]);
        let desired = RecipientFile::new(vec![
            Recipient::new(id.clone(), Some("new comment".into())).unwrap(),
        ]);
        let d = current.diff(&desired);
        assert!(d.is_empty(), "comment-only changes should not appear in diff");
        assert_eq!(d.retained.len(), 1);
    }

    #[test]
    fn parse_error_includes_offending_token() {
        // Regression: ParseError::Markl used to omit the offending token,
        // so users hit "line 4: failed to parse markl ID: ..." without
        // knowing which input was bad. The token is now part of the error.
        let input = "# comment\n-a\n";
        let err = RecipientFile::parse(input).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("-a") || msg.contains("\"-a\""),
            "expected error to mention the offending token '-a': {msg}"
        );
    }

    #[test]
    fn parse_error_includes_correct_line_number() {
        // Two comment lines, one valid recipient, one broken line at line 4.
        // The error should report line 4.
        let id = sample_id(7);
        let input = format!(
            "# header\n# more header\n{}\n-a\n",
            id.to_wire()
        );
        let err = RecipientFile::parse(&input).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 4"), "expected line 4 in error: {msg}");
    }

    #[test]
    fn idempotent_parse_render_parse() {
        let id_a = sample_id(23);
        let id_b = sample_id(29);
        let input = format!(
            "{}  # alpha\n{}  # beta\n",
            id_a.to_wire(),
            id_b.to_wire(),
        );
        let first = RecipientFile::parse(&input).unwrap();
        let rendered = first.render();
        let second = RecipientFile::parse(&rendered).unwrap();
        assert_eq!(second.recipients(), first.recipients());
        assert_eq!(second.render(), rendered);
    }
}
