//! `piggy pass show-batch <name>...` — decrypt N eboxes in a single
//! PIV-card session (one PIN prompt) and emit per-ebox progress via
//! the NDJSON event stream defined in RFC 0005.
//!
//! See [`docs/rfcs/0005-pass-show-batch-ndjson.md`] for the wire format.
//! Implementation tracked at amarbel-llc/piggy#121.
//!
//! ## Single-card-path divergence from v1.0 wrap-C posture
//!
//! Unlike most `pass *` handlers, show-batch does NOT shell out to C
//! `pivy-box`. The marquee RFC promise is *one PIN per batch*, and
//! per-ebox `pivy-box stream decrypt` calls would yield N prompts
//! whenever a `pivy-agent` isn't caching. show-batch routes through
//! Rust [`piggy_box::unlock::unlock_ebox`] + a [`BatchOracle`] backed
//! by [`piggy_piv::PinSession`], which holds the card transaction for
//! the whole batch and brackets a single PIN-verify around N ECDH
//! ops. See piggy#56 / #121 for the broader context.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use piggy_box::agent_ext::extract_point_from_sshkey_blob;
use piggy_box::oracle::{EcdhOracle, OracleError};
use piggy_box::stream::EboxStream;
use piggy_box::template::EboxConfigType;
use piggy_box::unlock::unlock_ebox;
use piggy_piv::{PinSession, PivContext, PivToken};
use ssh_key::public::{EcdsaPublicKey, KeyData};

use crate::store;
use ndjson::{Diagnostic, DiagnosticKind};
use piggy::card_oracle::{
    PinSupplier, askpass_pin_supplier, canonicalize_uncompressed, piv_to_oracle_pin_error,
};

/// CLI arguments for `piggy pass show-batch`, parsed by clap and
/// passed in from the top-level dispatcher.
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
    ///
    /// Task #3 emits NDJSON unconditionally; the `human` format
    /// renderer lands in task #8 (docs/plans/2026-05-27-show-batch-
    /// plan.md). The field is plumbed through so the clap surface
    /// stays stable.
    #[allow(dead_code)]
    pub format: OutputFormat,
    /// When true, wipe partial outputs in `out_dir` if any decrypt
    /// fails. Default false (leave partials in place).
    ///
    /// Task #3 never wipes; task #8 implements the cleanup.
    #[allow(dead_code)]
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
pub mod ndjson {
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
    ///
    /// Task #3's coarse error mapping only emits `NotFound`,
    /// `DecryptFailed`, `IoError`, and `Internal`. The PIN/card
    /// variants (`PinCancelled`, `PinIncorrect`, `CardLocked`,
    /// `CardAbsent`) are wired in task #8 once we map `PivError`
    /// variants individually. The unit tests below already exercise
    /// every variant's serialization, so `dead_code` is suppressed
    /// at the enum level.
    #[allow(dead_code)]
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

/// Per-name pre-flight result. `Ready` carries everything needed to
/// decrypt the ebox (parsed stream + original bytes for chunk
/// slicing). `Failed` carries the diagnostic to emit in stream order
/// so the `n=K of count` numbering stays gap-free per RFC 0005.
enum PreflightOutcome {
    Ready {
        canonical_name: String,
        bytes: Vec<u8>,
        stream: EboxStream,
    },
    Failed {
        canonical_name: String,
        diagnostic: Diagnostic,
    },
}

/// Exit code conventions:
/// - 0: every ebox in the batch decrypted successfully.
/// - 1: at least one ebox failed, or the batch was bailed out.
/// - 2: usage error (e.g. neither positional names nor `--names-from`
///   yielded any pass-names, conflicting flags, unreadable
///   `--names-from`).
///
/// This is the task #3 core implementation: working decrypt loop with
/// coarse error mapping (most non-IO failures map to
/// `DiagnosticKind::Internal`). The polish — fine-grained PivError →
/// DiagnosticKind mapping, SIGINT handling, `--names-from`,
/// `--all-or-nothing`, and the human-format renderer — lands in task
/// #8 per docs/plans/2026-05-27-show-batch-plan.md.
pub fn run(args: ShowBatchArgs) -> i32 {
    let mut stdout = std::io::stdout().lock();

    // Step 1: gather names. Task #3 slice only honors positional
    // names; --names-from is parsed by clap and stashed in args but
    // intentionally ignored here. Task #8 wires it.
    if !args.names.iter().all(|n| !n.is_empty()) {
        eprintln!("piggy pass show-batch: empty pass-name in argument list");
        return 2;
    }
    if args.names.is_empty() && args.names_from.is_none() {
        eprintln!("piggy pass show-batch: no pass-names supplied");
        return 2;
    }
    if args.names_from.is_some() {
        // Surface the limitation rather than silently dropping the
        // file. Task #8 removes this branch.
        eprintln!(
            "piggy pass show-batch: --names-from is not yet wired (piggy#121 task #8); \
             pass names positionally for now"
        );
    }
    let names: Vec<String> = args.names;

    // Step 2: out_dir setup. Create with 0o700 — the parent of
    // plaintext outputs should not be world-readable.
    if let Err(e) = std::fs::create_dir_all(&args.out_dir) {
        eprintln!(
            "piggy pass show-batch: cannot create out-dir {}: {e}",
            args.out_dir.display()
        );
        return 2;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&args.out_dir) {
            let mut perms = meta.permissions();
            // Best-effort tighten; an existing 0o755 dir keeps its
            // mode if the chmod fails (e.g. cross-fs mount).
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(&args.out_dir, perms);
        }
    }

    let store_root = store::store_root();

    // Step 3: pre-flight each name. Load bytes, parse stream. We
    // accumulate per-entry results so a name that fails pre-flight
    // (missing/unreadable/malformed) still gets a `decrypt` record
    // emitted in order. Plan record is emitted first with
    // `names.len()` as the count — that count never changes.
    if let Err(e) = ndjson::emit_plan(&mut stdout, names.len() as u32) {
        eprintln!("piggy pass show-batch: stdout write failed: {e}");
        return 1;
    }

    let mut preflight: Vec<PreflightOutcome> = Vec::with_capacity(names.len());
    for raw in &names {
        let canonical = canonicalize_pass_name(raw);
        let path = pass_name_to_ebox_path(&store_root, raw);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                preflight.push(PreflightOutcome::Failed {
                    canonical_name: canonical,
                    diagnostic: Diagnostic {
                        kind: DiagnosticKind::NotFound,
                        message: format!("no ebox at {}", path.display()),
                        retryable: None,
                    },
                });
                continue;
            }
            Err(e) => {
                preflight.push(PreflightOutcome::Failed {
                    canonical_name: canonical,
                    diagnostic: Diagnostic {
                        kind: DiagnosticKind::IoError,
                        message: format!("read {}: {e}", path.display()),
                        retryable: None,
                    },
                });
                continue;
            }
        };
        match EboxStream::from_bytes(&bytes) {
            Ok(stream) => preflight.push(PreflightOutcome::Ready {
                canonical_name: canonical,
                bytes,
                stream,
            }),
            Err(e) => preflight.push(PreflightOutcome::Failed {
                canonical_name: canonical,
                diagnostic: Diagnostic {
                    kind: DiagnosticKind::DecryptFailed,
                    message: format!("invalid ebox stream: {e}"),
                    retryable: None,
                },
            }),
        }
    }

    // Step 4: pick the first ebox that pre-flighted successfully —
    // that's the one we'll match a card against. If none did, the
    // whole batch is per-name failures; no card session needed.
    let first_ready_idx = preflight
        .iter()
        .position(|p| matches!(p, PreflightOutcome::Ready { .. }));
    let Some(first_idx) = first_ready_idx else {
        for (i, outcome) in preflight.into_iter().enumerate() {
            let n = (i + 1) as u32;
            if let PreflightOutcome::Failed {
                canonical_name,
                diagnostic,
            } = outcome
            {
                if let Err(e) =
                    ndjson::emit_decrypt_failed(&mut stdout, n, &canonical_name, diagnostic)
                {
                    eprintln!("piggy pass show-batch: stdout write failed: {e}");
                    return 1;
                }
            }
        }
        let _ = ndjson::emit_summary(&mut stdout, 0, names.len() as u32);
        return 1;
    };

    // The first ready ebox's PRIMARY config[0].part[0] tells us
    // which recipient pubkey to find on a card. Match by SEC1-
    // uncompressed pubkey bytes (the form `unlock_ebox` will hand
    // BatchOracle later, post-decompress).
    let (target_uncompressed, target_curve) = match select_target_pubkey(&preflight[first_idx]) {
        Ok(v) => v,
        Err(diag) => {
            let _ = ndjson::emit_bail_out(
                &mut stdout,
                &format!(
                    "cannot identify target recipient for batch: {}",
                    diag.message
                ),
            );
            return 1;
        }
    };

    // Step 5: enumerate connected PIV tokens; pick the first one
    // whose 9D slot pubkey matches.
    let ctx = match PivContext::new() {
        Ok(c) => c,
        Err(e) => {
            let _ = ndjson::emit_bail_out(&mut stdout, &format!("PCSC unavailable: {e}"));
            return 1;
        }
    };
    let tokens = match ctx.enumerate_tokens() {
        Ok(t) => t,
        Err(e) => {
            let _ = ndjson::emit_bail_out(&mut stdout, &format!("PCSC enumerate failed: {e}"));
            return 1;
        }
    };
    let mut chosen: Option<PivToken> = None;
    let target_slot = piggy_box::template::DEFAULT_SLOT;
    for token in tokens {
        let slot = match token.read_slot(target_slot) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let candidate = match slot.public_key().key_data() {
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(p)) => p.as_bytes().to_vec(),
            _ => continue,
        };
        if candidate == target_uncompressed {
            chosen = Some(token);
            break;
        }
    }
    let Some(mut token) = chosen else {
        let _ = ndjson::emit_bail_out(
            &mut stdout,
            "no attached PIV card has a 9D slot matching the first ebox's recipient",
        );
        return 1;
    };

    // Step 6: open the session and run the batch.
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            let _ = ndjson::emit_bail_out(&mut stdout, &format!("begin_pin_session failed: {e}"));
            return 1;
        }
    };

    let mut oracle = BatchOracle {
        session: &mut session,
        slot_id: target_slot,
        self_pubkey_uncompressed: target_uncompressed,
        target_curve,
        pin_verified: false,
        pin_supplier: askpass_pin_supplier(),
    };

    let mut ok_count: u32 = 0;
    let mut failed_count: u32 = 0;
    for (i, outcome) in preflight.into_iter().enumerate() {
        let n = (i + 1) as u32;
        match outcome {
            PreflightOutcome::Failed {
                canonical_name,
                diagnostic,
            } => {
                if let Err(e) =
                    ndjson::emit_decrypt_failed(&mut stdout, n, &canonical_name, diagnostic)
                {
                    eprintln!("piggy pass show-batch: stdout write failed: {e}");
                    return 1;
                }
                failed_count += 1;
            }
            PreflightOutcome::Ready {
                canonical_name,
                bytes,
                mut stream,
            } => match decrypt_one(&mut stream, &bytes, &mut oracle) {
                Ok(plain) => match atomic_write_0600(&args.out_dir, &canonical_name, &plain) {
                    Ok(out_path) => {
                        if let Err(e) =
                            ndjson::emit_decrypt_ok(&mut stdout, n, &canonical_name, &out_path)
                        {
                            eprintln!("piggy pass show-batch: stdout write failed: {e}");
                            return 1;
                        }
                        ok_count += 1;
                    }
                    Err(e) => {
                        let diag = Diagnostic {
                            kind: DiagnosticKind::IoError,
                            message: e,
                            retryable: None,
                        };
                        if let Err(e) =
                            ndjson::emit_decrypt_failed(&mut stdout, n, &canonical_name, diag)
                        {
                            eprintln!("piggy pass show-batch: stdout write failed: {e}");
                            return 1;
                        }
                        failed_count += 1;
                    }
                },
                Err(diag) => {
                    if let Err(e) =
                        ndjson::emit_decrypt_failed(&mut stdout, n, &canonical_name, diag)
                    {
                        eprintln!("piggy pass show-batch: stdout write failed: {e}");
                        return 1;
                    }
                    failed_count += 1;
                }
            },
        }
    }

    // Explicit session end so we can propagate
    // `SCardEndTransaction` errors as a non-zero exit. If end fails,
    // we've already emitted the per-decrypt records — surface as a
    // bail-out so a downstream TAP bridge sees the truncation flag.
    if let Err(e) = session.end() {
        let _ = ndjson::emit_bail_out(&mut stdout, &format!("SCardEndTransaction failed: {e}"));
        return 1;
    }

    if let Err(e) = ndjson::emit_summary(&mut stdout, ok_count, failed_count) {
        eprintln!("piggy pass show-batch: stdout write failed: {e}");
        return 1;
    }

    if failed_count == 0 { 0 } else { 1 }
}

/// Canonical pass-name per RFC 0005 §Decrypt Record: strip leading
/// `/`, strip trailing `.ebox`.
fn canonicalize_pass_name(raw: &str) -> String {
    let stripped = raw.strip_prefix('/').unwrap_or(raw);
    stripped
        .strip_suffix(".ebox")
        .unwrap_or(stripped)
        .to_string()
}

/// Resolve a pass-name to its on-disk ebox path. Mirrors the bash
/// `cmd_show`: `<store_root>/<pass_name>.ebox`, with a `.ebox` suffix
/// appended only if the user didn't already supply one.
fn pass_name_to_ebox_path(store_root: &Path, raw: &str) -> PathBuf {
    let trimmed = raw.strip_prefix('/').unwrap_or(raw);
    if trimmed.ends_with(".ebox") {
        store_root.join(trimmed)
    } else {
        store_root.join(format!("{trimmed}.ebox"))
    }
}

/// Pull the target recipient SEC1-uncompressed pubkey + curve from the
/// first PRIMARY config's first part. show-batch picks one (card,
/// slot) pair for the whole batch by matching this pubkey against
/// connected cards' 9D slots; the heterogeneous-batch case (different
/// recipients per ebox) is out of scope by RFC 0005 §Single-card
/// Operation and falls into the bail-out path naturally.
fn select_target_pubkey(
    outcome: &PreflightOutcome,
) -> Result<(Vec<u8>, piggy_box::piv_box::EcCurve), Diagnostic> {
    let stream = match outcome {
        PreflightOutcome::Ready { stream, .. } => stream,
        _ => unreachable!("select_target_pubkey called on a Failed outcome"),
    };
    let primary = stream
        .ebox
        .configs
        .iter()
        .find(|c| c.config_type == EboxConfigType::Primary)
        .ok_or_else(|| Diagnostic {
            kind: DiagnosticKind::DecryptFailed,
            message: "ebox has no PRIMARY config".into(),
            retryable: None,
        })?;
    let part = primary.parts.first().ok_or_else(|| Diagnostic {
        kind: DiagnosticKind::DecryptFailed,
        message: "PRIMARY config has no parts".into(),
        retryable: None,
    })?;
    let curve = part.piv_box.curve;
    let recipient = &part.piv_box.recipient_pubkey;
    let uncompressed = canonicalize_uncompressed(recipient).map_err(|e| Diagnostic {
        kind: DiagnosticKind::DecryptFailed,
        message: format!("decompress recipient pubkey: {e}"),
        retryable: None,
    })?;
    Ok((uncompressed, curve))
}

/// Use `unlock_ebox` to materialize the AES key inside `stream.ebox`,
/// then walk the chunk frames in `bytes` and accumulate plaintext.
/// `bytes` is the original on-disk ebox bytes — header + chunks.
fn decrypt_one(
    stream: &mut EboxStream,
    bytes: &[u8],
    oracle: &mut BatchOracle<'_, '_>,
) -> Result<Vec<u8>, Diagnostic> {
    let oracle_dyn: &mut dyn EcdhOracle = oracle;
    if let Err(e) = unlock_ebox(&mut stream.ebox, None, Some(oracle_dyn)) {
        return Err(Diagnostic {
            kind: DiagnosticKind::DecryptFailed,
            message: format!("unlock failed: {e}"),
            retryable: None,
        });
    }

    let header_bytes = stream.to_bytes().map_err(|e| Diagnostic {
        kind: DiagnosticKind::Internal,
        message: format!("re-serialize header: {e}"),
        retryable: None,
    })?;
    if bytes.len() < header_bytes.len() {
        return Err(Diagnostic {
            kind: DiagnosticKind::DecryptFailed,
            message: "ebox bytes shorter than re-serialized header".into(),
            retryable: None,
        });
    }
    let mut chunk_data = &bytes[header_bytes.len()..];

    let mut plaintext = Vec::new();
    let mut expected_seqnr: u32 = 0;
    while !chunk_data.is_empty() {
        if chunk_data.len() < 8 {
            return Err(Diagnostic {
                kind: DiagnosticKind::DecryptFailed,
                message: "truncated chunk frame".into(),
                retryable: None,
            });
        }
        let string_len =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]])
                as usize;
        let frame_len = 4 + 4 + string_len;
        if chunk_data.len() < frame_len {
            return Err(Diagnostic {
                kind: DiagnosticKind::DecryptFailed,
                message: "truncated chunk data".into(),
                retryable: None,
            });
        }
        let frame = &chunk_data[..frame_len];
        let (_, plain) = stream
            .decrypt_chunk(Some(expected_seqnr), frame)
            .map_err(|e| Diagnostic {
                kind: DiagnosticKind::DecryptFailed,
                message: format!("chunk {expected_seqnr}: {e}"),
                retryable: None,
            })?;
        plaintext.extend_from_slice(&plain);
        chunk_data = &chunk_data[frame_len..];
        expected_seqnr += 1;
    }
    Ok(plaintext)
}

/// Write `plaintext` to `<out_dir>/<name>` with mode 0o600 using
/// O_CREAT|O_EXCL semantics so an existing path fails the per-ebox
/// decrypt rather than silently clobbering. Returns the absolute
/// output path on success.
///
/// Parent directories implied by `name` (e.g. `config/ssh/foo` →
/// `<out_dir>/config/ssh/`) are created with mode 0o700.
fn atomic_write_0600(out_dir: &Path, name: &str, plaintext: &[u8]) -> Result<PathBuf, String> {
    let out_path = out_dir.join(name);
    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(parent) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o700);
                    let _ = std::fs::set_permissions(parent, perms);
                }
            }
        }
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&out_path)
        .map_err(|e| format!("open {}: {e}", out_path.display()))?;
    f.write_all(plaintext)
        .map_err(|e| format!("write {}: {e}", out_path.display()))?;
    f.sync_all()
        .map_err(|e| format!("fsync {}: {e}", out_path.display()))?;
    Ok(out_path)
}

/// Session-aware ECDH oracle. Held across the whole show-batch run so
/// the single `verify_pin` early in the batch authenticates every
/// subsequent `ecdh_derive` against the same card transaction.
///
/// - `self_pubkey_uncompressed` is the SEC1-uncompressed bytes of the
///   chosen slot's pubkey. We compare incoming `self_pubkey_ssh_blob`
///   (after `extract_point_from_sshkey_blob`) against it; mismatch
///   returns [`OracleError::NoKey`] so `unlock_ebox` tries the next
///   part. In show-batch's single-card-path posture, NoKey means the
///   ebox was sealed to a different recipient than the one we matched
///   the first ebox against — a `decrypt-failed` (RFC 0005 decision
///   3c, polished in task #8 — task #3 reports it as `decrypt-failed`
///   via the catch-all error path).
/// - `target_curve` is captured at construction so we can build the
///   SSH wire blob without re-deriving from the slot every call.
/// - `pin_verified` flips to true on first successful `verify_pin`.
///   The PIN supplier runs exactly once — `unlock_ebox` may make
///   multiple `ecdh` calls per ebox if a config has multiple parts,
///   and we don't want to prompt N times.
struct BatchOracle<'sess, 'tok> {
    session: &'sess mut PinSession<'tok>,
    slot_id: u8,
    self_pubkey_uncompressed: Vec<u8>,
    #[allow(dead_code)] // reserved for the heterogeneous-batch
    // detection logic in task #8 — keep the field plumbed so we
    // don't have to re-thread it later.
    target_curve: piggy_box::piv_box::EcCurve,
    pin_verified: bool,
    pin_supplier: PinSupplier,
}

impl<'sess, 'tok> EcdhOracle for BatchOracle<'sess, 'tok> {
    fn ecdh(
        &mut self,
        self_pubkey_ssh_blob: &[u8],
        partner_pubkey_ssh_blob: &[u8],
    ) -> Result<Vec<u8>, OracleError> {
        let self_point = extract_point_from_sshkey_blob(self_pubkey_ssh_blob)?;
        let self_uncompressed = canonicalize_uncompressed(&self_point)?;
        if self_uncompressed != self.self_pubkey_uncompressed {
            return Err(OracleError::NoKey);
        }

        if !self.pin_verified {
            let pin = (self.pin_supplier)("PIV PIN")?;
            self.session
                .verify_pin(&pin)
                .map_err(piv_to_oracle_pin_error)?;
            self.pin_verified = true;
        }

        let partner_point = extract_point_from_sshkey_blob(partner_pubkey_ssh_blob)?;
        let partner_uncompressed = canonicalize_uncompressed(&partner_point)?;
        self.session
            .ecdh_derive(self.slot_id, &partner_uncompressed)
            .map_err(|e| OracleError::Transport(format!("ecdh_derive: {e}")))
    }
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
