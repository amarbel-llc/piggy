//! Minimal hyphence framing (madder RFC 0001) — the subset pigpen needs.
//!
//! Not a full RFC 0001 implementation: only the `# - @ !` prefixes, the
//! `---\n` boundaries, the required blank-line body separator, and the
//! `@`-XOR-body rule. The cutover (RFC 0008 "Compatibility") replaces
//! this with either piggy's own conforming framing or a shared library.

use crate::{Error, Result};

pub const BOUNDARY: &str = "---\n";

/// One metadata line: a single-byte prefix and its content.
#[derive(Clone)]
pub struct MetaLine {
    pub prefix: u8,
    pub body: String,
}

/// Framing-level view of a document.
#[derive(Default)]
pub struct HyphenceDoc {
    pub meta: Vec<MetaLine>,
    pub body: Vec<u8>,
}

impl HyphenceDoc {
    fn has_at_ref(&self) -> bool {
        self.meta.iter().any(|l| l.prefix == b'@')
    }

    /// Render just the metadata section (both boundaries) in canonical
    /// RFC 0001 order: `#`, `-`, `@`, `!`. Input order preserved within a
    /// prefix.
    pub fn marshal_metadata(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(BOUNDARY.as_bytes());
        for want in [b'#', b'-', b'@', b'!'] {
            for l in &self.meta {
                if l.prefix == want {
                    out.push(l.prefix);
                    out.push(b' ');
                    out.extend_from_slice(l.body.as_bytes());
                    out.push(b'\n');
                }
            }
        }
        out.extend_from_slice(BOUNDARY.as_bytes());
        out
    }

    /// Render the full document.
    pub fn marshal(&self) -> Result<Vec<u8>> {
        if self.has_at_ref() && !self.body.is_empty() {
            return Err(Error::Hyphence(
                "'@' blob reference together with an inline body".into(),
            ));
        }
        let mut out = self.marshal_metadata();
        if !self.body.is_empty() {
            out.push(b'\n');
            out.extend_from_slice(&self.body);
        }
        Ok(out)
    }
}

/// Decode the framing of a pigpen document.
pub fn parse(raw: &[u8]) -> Result<HyphenceDoc> {
    let text = raw;
    let mut pos = 0usize;

    let first = read_line(text, &mut pos).ok_or_else(|| Error::Hyphence("empty input".into()))?;
    if first != BOUNDARY.as_bytes() {
        return Err(Error::Hyphence("missing opening '---' boundary".into()));
    }

    let mut doc = HyphenceDoc::default();
    let mut closed = false;
    while let Some(line) = read_line(text, &mut pos) {
        if line == BOUNDARY.as_bytes() {
            closed = true;
            break;
        }
        let content = strip_lf(line);
        if content.len() < 2 || content[1] != b' ' {
            return Err(Error::Hyphence(format!(
                "malformed metadata line: {:?}",
                String::from_utf8_lossy(line)
            )));
        }
        let prefix = content[0];
        match prefix {
            b'#' | b'-' | b'@' | b'!' => doc.meta.push(MetaLine {
                prefix,
                body: String::from_utf8_lossy(&content[2..]).into_owned(),
            }),
            other => {
                return Err(Error::Hyphence(format!(
                    "unknown metadata prefix {:?}",
                    other as char
                )));
            }
        }
    }
    if !closed {
        return Err(Error::Hyphence("missing closing '---' boundary".into()));
    }

    // Remainder is the body, preceded by the required blank-line separator.
    let rest = &text[pos..];
    if !rest.is_empty() {
        if rest[0] != b'\n' {
            return Err(Error::Hyphence(
                "body present without blank-line separator".into(),
            ));
        }
        doc.body = rest[1..].to_vec();
    }
    if doc.has_at_ref() && !doc.body.is_empty() {
        return Err(Error::Hyphence(
            "'@' blob reference together with an inline body".into(),
        ));
    }
    Ok(doc)
}

fn read_line<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos >= buf.len() {
        return None;
    }
    let start = *pos;
    match buf[start..].iter().position(|&b| b == b'\n') {
        Some(i) => {
            *pos = start + i + 1;
            Some(&buf[start..*pos])
        }
        None => {
            *pos = buf.len();
            Some(&buf[start..])
        }
    }
}

fn strip_lf(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}
