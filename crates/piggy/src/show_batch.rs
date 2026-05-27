//! `piggy pass show-batch <name>...` — decrypt N eboxes in a single
//! PIV-card session (one PIN prompt) and emit per-ebox progress via
//! the NDJSON event stream defined in RFC 0005.
//!
//! See [`docs/rfcs/0005-pass-show-batch-ndjson.md`] for the wire format.
//! Implementation tracked at amarbel-llc/piggy#121.

use std::path::PathBuf;

/// CLI arguments for `piggy pass show-batch`, parsed by clap and
/// passed in from the top-level dispatcher.
//
// dead_code allow is temporary while the stub `run` ignores every
// field. Removed in the follow-up that lands the actual decrypt loop
// (piggy#121).
#[allow(dead_code)]
#[derive(Debug)]
pub struct ShowBatchArgs {
    /// Positional pass-names supplied on the command line. May be
    /// empty if `names_from` is set; one of the two must yield at
    /// least one name.
    pub names: Vec<String>,
    /// Path to a file containing one pass-name per line. Lines are
    /// trimmed; blank lines and lines starting with `#` are ignored.
    /// Pass-names from this file are appended to `names` in order.
    pub names_from: Option<PathBuf>,
    /// Directory under which to write `<out_dir>/<pass-name>` for each
    /// successfully decrypted ebox. Defaults to the current working
    /// directory.
    pub out_dir: PathBuf,
    /// Output format. `Ndjson` is normatively pinned by RFC 0005;
    /// `Human` is implementation-defined and meant for terminal use.
    pub format: OutputFormat,
    /// When true, wipe partial outputs in `out_dir` if any decrypt
    /// fails. Default false (leave partials in place).
    pub all_or_nothing: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Ndjson,
    Human,
}

/// RFC 0005 NDJSON record types and emitter.
///
/// The `#[serde(tag = "type")]` attribute renders each enum variant
/// as an object whose first field is `"type":"<variant-name>"`,
/// followed by that variant's struct fields in declaration order.
/// serde_json preserves struct field declaration order on serialize
/// (de-facto stable; pinned via the `record_types_field_order`
/// cargo test below), so the RFC's §Field Ordering hint ("producer
/// emits `type` first") is honored deterministically.
///
/// `#[serde(rename_all = "kebab-case")]` on `Record` maps `BailOut`
/// → `"bail-out"` to match the RFC's exact tag spelling. Variant-
/// specific renames inside each struct are unnecessary because the
/// field names (`plan.count`, `decrypt.n/name/ok/out_path/
/// diagnostic`, etc.) already match the RFC verbatim.
///
/// Module-level `#![allow(dead_code)]` is temporary while `run()` is
/// a not-implemented stub. The unit tests below exercise every
/// record + diagnostic kind, but cargo's dead-code analysis tracks
/// production usage, not test usage. The allow comes off in the
/// same commit that lands the decrypt loop (piggy#121 task #3) —
/// every type below has a call site there.
pub mod ndjson {
    #![allow(dead_code)]

    use std::io::Write;
    use std::path::{Path, PathBuf};

    use serde::Serialize;

    /// One record in the RFC 0005 NDJSON event stream.
    #[derive(Debug, Serialize)]
    #[serde(tag = "type", rename_all = "kebab-case")]
    pub enum Record {
        Plan(Plan),
        Decrypt(Decrypt),
        Summary(Summary),
        BailOut(BailOut),
    }

    #[derive(Debug, Serialize)]
    pub struct Plan {
        /// Number of `decrypt` records that will follow in this
        /// stream. MUST equal the count of pass-names supplied to
        /// show-batch.
        pub count: u32,
    }

    #[derive(Debug, Serialize)]
    pub struct Decrypt {
        /// 1-indexed position within the batch.
        pub n: u32,
        /// Pass-name as supplied, canonicalised (leading `/`
        /// stripped, `.ebox` suffix stripped).
        pub name: String,
        /// True iff decryption succeeded AND plaintext was written.
        pub ok: bool,
        /// Absolute path to plaintext on success; null on failure.
        pub out_path: Option<PathBuf>,
        /// `None` on success; describes the failure otherwise.
        pub diagnostic: Option<Diagnostic>,
    }

    #[derive(Debug, Serialize)]
    pub struct Summary {
        /// Count of decrypt records with `ok: true`.
        pub ok: u32,
        /// Count of decrypt records with `ok: false`. The invariant
        /// `ok + failed == plan.count` MUST hold; emitters that
        /// violate it are malformed per RFC 0005.
        pub failed: u32,
    }

    #[derive(Debug, Serialize)]
    pub struct BailOut {
        /// Human-readable single-line reason for the abort. Surfaced
        /// as TAP `Bail out!` directive text by bridging consumers.
        pub reason: String,
    }

    #[derive(Debug, Serialize)]
    pub struct Diagnostic {
        /// One of the eight RFC-defined kinds (kebab-case). Producers
        /// MUST emit a defined value; consumers MUST treat
        /// unrecognised values as `internal`.
        pub kind: DiagnosticKind,
        /// Human-readable error message. SHOULD be single-line.
        pub message: String,
        /// True iff a fresh show-batch invocation against the same
        /// name MAY succeed. Omitted (None → serde skips) when
        /// terminal.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub retryable: Option<bool>,
    }

    /// The closed eight-value `diagnostic.kind` taxonomy from RFC
    /// 0005. Per decision 3c, the "wrong recipient for selected
    /// card/slot" case reuses `DecryptFailed` with explanatory
    /// message text rather than introducing a ninth value.
    #[derive(Debug, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum DiagnosticKind {
        NotFound,
        PinCancelled,
        PinIncorrect,
        CardLocked,
        CardAbsent,
        DecryptFailed,
        IoError,
        Internal,
    }

    /// Write a single RFC 0005 record to `out` and flush
    /// immediately. Returns an `io::Error` if either the serialize
    /// or the flush fails.
    ///
    /// The `Streaming Guarantee` from RFC 0005 §Specification
    /// requires a flush after every record so consumers reading
    /// line-by-line observe each event with bounded latency. The
    /// flush is per-record, not per-call to this function — keep
    /// that property in mind if a future refactor batches multiple
    /// records into one write.
    pub fn emit<W: Write>(out: &mut W, record: &Record) -> std::io::Result<()> {
        serde_json::to_writer(&mut *out, record)?;
        out.write_all(b"\n")?;
        out.flush()
    }

    /// Sugar wrappers — show-batch's main loop calls these directly
    /// so call sites read as `emit_plan(out, count)` rather than the
    /// more verbose `emit(out, &Record::Plan(Plan { count }))`.
    pub fn emit_plan<W: Write>(out: &mut W, count: u32) -> std::io::Result<()> {
        emit(out, &Record::Plan(Plan { count }))
    }

    pub fn emit_decrypt_ok<W: Write>(
        out: &mut W,
        n: u32,
        name: &str,
        out_path: &Path,
    ) -> std::io::Result<()> {
        emit(
            out,
            &Record::Decrypt(Decrypt {
                n,
                name: name.to_string(),
                ok: true,
                out_path: Some(out_path.to_path_buf()),
                diagnostic: None,
            }),
        )
    }

    pub fn emit_decrypt_failed<W: Write>(
        out: &mut W,
        n: u32,
        name: &str,
        diagnostic: Diagnostic,
    ) -> std::io::Result<()> {
        emit(
            out,
            &Record::Decrypt(Decrypt {
                n,
                name: name.to_string(),
                ok: false,
                out_path: None,
                diagnostic: Some(diagnostic),
            }),
        )
    }

    pub fn emit_summary<W: Write>(out: &mut W, ok: u32, failed: u32) -> std::io::Result<()> {
        emit(out, &Record::Summary(Summary { ok, failed }))
    }

    pub fn emit_bail_out<W: Write>(out: &mut W, reason: &str) -> std::io::Result<()> {
        emit(
            out,
            &Record::BailOut(BailOut {
                reason: reason.to_string(),
            }),
        )
    }
}

/// Exit code conventions:
/// - 0: every ebox in the batch decrypted successfully.
/// - 1: at least one ebox failed, or the batch was bailed out.
/// - 2: usage error (e.g. neither positional names nor `--names-from`
///   yielded any pass-names, conflicting flags, unreadable
///   `--names-from`).
pub fn run(_args: ShowBatchArgs) -> i32 {
    // TODO(#121): decrypt loop lands in a follow-up commit.
    eprintln!("piggy pass show-batch: not yet implemented (see piggy#121)");
    2
}

#[cfg(test)]
mod tests {
    use super::ndjson::*;

    /// Capture serialized output of a single record. Helper used by
    /// the field-order and shape tests below.
    fn render(record: &Record) -> String {
        let mut buf = Vec::new();
        emit(&mut buf, record).expect("emit to Vec<u8> never fails");
        String::from_utf8(buf).expect("RFC 0005 records are pure UTF-8")
    }

    /// RFC 0005 §Field Ordering: producers SHOULD emit `type` as the
    /// first field of each record. serde-json preserves struct field
    /// declaration order on serialize; this test pins that property
    /// for the four record types.
    #[test]
    fn record_types_field_order() {
        for (record, expected_prefix) in [
            (Record::Plan(Plan { count: 0 }), r#"{"type":"plan""#),
            (
                Record::Decrypt(Decrypt {
                    n: 1,
                    name: "x".into(),
                    ok: true,
                    out_path: Some("/tmp/x".into()),
                    diagnostic: None,
                }),
                r#"{"type":"decrypt""#,
            ),
            (
                Record::Summary(Summary { ok: 0, failed: 0 }),
                r#"{"type":"summary""#,
            ),
            (
                Record::BailOut(BailOut { reason: "x".into() }),
                r#"{"type":"bail-out""#,
            ),
        ] {
            let rendered = render(&record);
            assert!(
                rendered.starts_with(expected_prefix),
                "record {:?} should start with {:?}, got {:?}",
                record,
                expected_prefix,
                rendered
            );
        }
    }

    /// RFC 0005 §Diagnostic Object: every defined `kind` value
    /// renders as a fixed kebab-case string. Producers MUST emit
    /// one of these; consumers MUST treat unrecognised values as
    /// `internal`.
    #[test]
    fn diagnostic_kinds_render_as_kebab_case() {
        for (kind, expected) in [
            (DiagnosticKind::NotFound, "not-found"),
            (DiagnosticKind::PinCancelled, "pin-cancelled"),
            (DiagnosticKind::PinIncorrect, "pin-incorrect"),
            (DiagnosticKind::CardLocked, "card-locked"),
            (DiagnosticKind::CardAbsent, "card-absent"),
            (DiagnosticKind::DecryptFailed, "decrypt-failed"),
            (DiagnosticKind::IoError, "io-error"),
            (DiagnosticKind::Internal, "internal"),
        ] {
            let rendered = render(&Record::Decrypt(Decrypt {
                n: 1,
                name: "x".into(),
                ok: false,
                out_path: None,
                diagnostic: Some(Diagnostic {
                    kind,
                    message: "msg".into(),
                    retryable: None,
                }),
            }));
            let needle = format!(r#""kind":"{}""#, expected);
            assert!(
                rendered.contains(&needle),
                "diagnostic.kind {:?} should serialize to {:?}, got {:?}",
                expected,
                needle,
                rendered
            );
        }
    }

    /// RFC 0005 says `out_path` is `string | null` and `diagnostic`
    /// is `object | null`. serde defaults to emitting `null` for
    /// `Option::None` (not omission), which matches the RFC.
    /// `retryable` is OPTIONAL and `skip_serializing_if = "Option::
    /// is_none"` omits it cleanly.
    #[test]
    fn nullable_fields_render_as_null_when_none() {
        let rendered = render(&Record::Decrypt(Decrypt {
            n: 2,
            name: "missing".into(),
            ok: false,
            out_path: None,
            diagnostic: Some(Diagnostic {
                kind: DiagnosticKind::NotFound,
                message: "no ebox".into(),
                retryable: None,
            }),
        }));
        assert!(rendered.contains(r#""out_path":null"#), "{}", rendered);
        // retryable omitted, not null.
        assert!(!rendered.contains(r#""retryable""#), "{}", rendered);
    }

    /// Every record MUST end with a single LF (no buffering beyond
    /// one line). Multiple emits append cleanly without surplus
    /// whitespace.
    #[test]
    fn stream_records_separated_by_lf_only() {
        let mut buf = Vec::new();
        emit_plan(&mut buf, 2).unwrap();
        emit_summary(&mut buf, 1, 1).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.split('\n').collect();
        // Two records + trailing empty (from the final LF).
        assert_eq!(lines.len(), 3, "expected 2 records + trailing empty");
        assert!(lines[2].is_empty(), "final element should be empty");
        assert!(lines[0].starts_with(r#"{"type":"plan""#));
        assert!(lines[1].starts_with(r#"{"type":"summary""#));
    }
}
