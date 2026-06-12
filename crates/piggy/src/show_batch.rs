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
use std::sync::atomic::{AtomicBool, Ordering};

use piggy_box::agent_ext::extract_point_from_sshkey_blob;
use piggy_box::oracle::{EcdhOracle, OracleError};
use piggy_box::stream::EboxStream;
use piggy_box::template::EboxConfigType;
use piggy_box::unlock::unlock_ebox;
use piggy_piv::{PinSession, PivContext, PivError, PivToken};
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
    pub format: OutputFormat,
    /// When true, wipe partial outputs in `out_dir` if any decrypt
    /// fails. Default false (leave partials in place).
    pub all_or_nothing: bool,
    /// When true (`--update`, cp/rsync `-u` semantics), skip the
    /// decrypt for any entry whose plaintext at `<out_dir>/<name>`
    /// already exists with an mtime at least as new as the ebox's,
    /// and overwrite stale plaintext instead of failing on the
    /// O_EXCL create. When every entry is fresh no card session is
    /// opened and no PIN is prompted.
    pub update: bool,
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
        /// True when no new plaintext was rendered because an
        /// up-to-date file already existed at `out_path` (the
        /// `--update` freshness skip). OPTIONAL per RFC 0005
        /// §Compatibility — omitted entirely (not `false`) on
        /// records for real decrypts, so pre-`--update` consumers
        /// see an unchanged stream.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        pub skipped: bool,
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
                skipped: false,
            }),
        )
    }

    /// A `--update` freshness skip: `ok: true` with the existing
    /// plaintext's path, plus `skipped: true` so consumers can tell
    /// a no-op apart from a real decrypt.
    pub fn emit_decrypt_skipped<W: Write>(
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
                skipped: true,
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
                skipped: false,
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

/// SIGINT handler state. The handler stores `true` into this atomic
/// and returns. The run loop polls it between decrypts so the user's
/// Ctrl-C interrupts cleanly *after* the current ebox has finished
/// (we don't abort mid-decrypt: that would leak a half-written file
/// and could leave the card transaction in an undefined state).
///
/// Static lifetime is required so the signal handler — which has no
/// closure environment — can reach it. `Ordering::Relaxed` is
/// sufficient: the store + the load are the only synchronization
/// points, and both run on the same thread (libc delivers signals on
/// the same thread that registered the handler in single-threaded
/// programs; show-batch is single-threaded). We never reset the flag
/// — once Ctrl-C is pressed, every remaining iteration sees it.
static SIGINT_CAUGHT: AtomicBool = AtomicBool::new(false);

extern "C" fn sigint_handler(_: libc::c_int) {
    // SAFETY: atomic store is async-signal-safe per POSIX.
    SIGINT_CAUGHT.store(true, Ordering::Relaxed);
}

/// Install the SIGINT handler. Idempotent — repeated installs just
/// overwrite the disposition with the same value. Returns `Err` if
/// the libc call fails (which would be... weird).
fn install_sigint_handler() {
    // SAFETY: libc::signal is the documented way to install a
    // C-callable handler. The handler we install only touches an
    // AtomicBool — async-signal-safe.
    //
    // The double-cast (fn item → *const () → sighandler_t) is
    // needed because Rust's `function_casts_as_integer` lint (stable
    // since 1.81) flags the direct fn-item-to-usize cast. The intermediate
    // pointer cast is the documented workaround.
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }
}

fn sigint_caught() -> bool {
    SIGINT_CAUGHT.load(Ordering::Relaxed)
}

/// Stdout adapter that abstracts NDJSON vs human formatting. Lets
/// `run()` call uniform `emit_*` methods without per-call match arms;
/// the renderer decides whether to emit a structured record or a
/// human line. Human format intentionally does NOT round-trip through
/// the RFC 0005 schema — it's a terminal-friendly convenience, not a
/// machine surface. NDJSON consumers (eng's `2-piggy.bash`, etc.)
/// MUST use `--format ndjson`.
struct Emitter<W: std::io::Write> {
    out: W,
    format: OutputFormat,
}

impl<W: std::io::Write> Emitter<W> {
    fn plan(&mut self, count: u32) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => ndjson::emit_plan(&mut self.out, count),
            OutputFormat::Human => writeln!(self.out, "Decrypting {count} ebox(es):"),
        }
    }

    fn decrypt_ok(
        &mut self,
        n: u32,
        total: u32,
        name: &str,
        out_path: &Path,
    ) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => ndjson::emit_decrypt_ok(&mut self.out, n, name, out_path),
            OutputFormat::Human => {
                writeln!(self.out, "[{n}/{total}] {name} → {} ok", out_path.display())
            }
        }
    }

    fn decrypt_skipped(
        &mut self,
        n: u32,
        total: u32,
        name: &str,
        out_path: &Path,
    ) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => ndjson::emit_decrypt_skipped(&mut self.out, n, name, out_path),
            OutputFormat::Human => {
                writeln!(
                    self.out,
                    "[{n}/{total}] {name} → {} ok (up-to-date, decrypt skipped)",
                    out_path.display()
                )
            }
        }
    }

    fn decrypt_failed(
        &mut self,
        n: u32,
        total: u32,
        name: &str,
        diagnostic: ndjson::Diagnostic,
    ) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => ndjson::emit_decrypt_failed(&mut self.out, n, name, diagnostic),
            OutputFormat::Human => {
                let kind = format!("{:?}", diagnostic.kind).to_ascii_lowercase();
                writeln!(
                    self.out,
                    "[{n}/{total}] {name} FAIL {kind}: {}",
                    diagnostic.message
                )
            }
        }
    }

    fn summary(&mut self, ok: u32, failed: u32) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => ndjson::emit_summary(&mut self.out, ok, failed),
            OutputFormat::Human => {
                writeln!(self.out, "Summary: {ok} ok, {failed} failed")
            }
        }
    }

    fn bail_out(&mut self, reason: &str) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Ndjson => ndjson::emit_bail_out(&mut self.out, reason),
            OutputFormat::Human => writeln!(self.out, "Bail out! {reason}"),
        }
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
    /// `--update` freshness skip: the plaintext at `out_path` is at
    /// least as new as the ebox, so no decrypt happens for this
    /// entry. Counted as `ok` in the summary; the ebox is never read
    /// or parsed (the point of the flag is to avoid the work).
    Skipped {
        canonical_name: String,
        out_path: PathBuf,
    },
}

/// True when `out_path` exists with an mtime at least as new as the
/// ebox's — the `--update` skip condition. Conservative: any stat or
/// mtime error returns false so the decrypt proceeds (never a
/// false skip).
fn plaintext_is_fresh(ebox_path: &Path, out_path: &Path) -> bool {
    let (Ok(ebox_meta), Ok(out_meta)) = (std::fs::metadata(ebox_path), std::fs::metadata(out_path))
    else {
        return false;
    };
    let (Ok(ebox_mtime), Ok(out_mtime)) = (ebox_meta.modified(), out_meta.modified()) else {
        return false;
    };
    out_mtime >= ebox_mtime
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
    install_sigint_handler();

    let format = args.format;
    let mut out = Emitter {
        out: std::io::stdout().lock(),
        format,
    };

    // Step 1: gather names. Positional `args.names` come first; any
    // file passed via `--names-from` is appended in order. Either
    // (but not both) may be empty; at least one resolved name is
    // required. Per RFC 0005, empty pass-names are a usage error.
    if !args.names.iter().all(|n| !n.is_empty()) {
        eprintln!("piggy pass show-batch: empty pass-name in argument list");
        return 2;
    }
    let mut names: Vec<String> = args.names;
    if let Some(path) = &args.names_from {
        match read_names_from(path) {
            Ok(extra) => names.extend(extra),
            Err(e) => {
                eprintln!(
                    "piggy pass show-batch: --names-from {}: {e}",
                    path.display()
                );
                return 2;
            }
        }
    }
    if names.is_empty() {
        eprintln!("piggy pass show-batch: no pass-names supplied (positional or --names-from)");
        return 2;
    }

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

    let total = names.len() as u32;

    // Step 3: pre-flight each name. Load bytes, parse stream. We
    // accumulate per-entry results so a name that fails pre-flight
    // (missing/unreadable/malformed) still gets a `decrypt` record
    // emitted in order. Plan record is emitted first with
    // `names.len()` as the count — that count never changes.
    if let Err(e) = out.plan(total) {
        eprintln!("piggy pass show-batch: stdout write failed: {e}");
        return 1;
    }

    let mut preflight: Vec<PreflightOutcome> = Vec::with_capacity(names.len());
    for raw in &names {
        let canonical = canonicalize_pass_name(raw);
        let path = pass_name_to_ebox_path(&store_root, raw);
        // --update: if the rendered plaintext is already at least as
        // new as the ebox, skip before even reading the ebox bytes.
        // A missing ebox falls through to the read below so it still
        // surfaces as `not-found`.
        if args.update {
            let out_path = args.out_dir.join(&canonical);
            if plaintext_is_fresh(&path, &out_path) {
                preflight.push(PreflightOutcome::Skipped {
                    canonical_name: canonical,
                    out_path,
                });
                continue;
            }
        }
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
    // whole batch is per-name failures and/or `--update` freshness
    // skips; no card session needed (and for an all-fresh batch, no
    // PIN prompt — that is the point of the flag).
    let first_ready_idx = preflight
        .iter()
        .position(|p| matches!(p, PreflightOutcome::Ready { .. }));
    let Some(first_idx) = first_ready_idx else {
        let mut ok_count: u32 = 0;
        let mut failed_count: u32 = 0;
        for (i, outcome) in preflight.into_iter().enumerate() {
            let n = (i + 1) as u32;
            let emitted = match outcome {
                PreflightOutcome::Failed {
                    canonical_name,
                    diagnostic,
                } => {
                    failed_count += 1;
                    out.decrypt_failed(n, total, &canonical_name, diagnostic)
                }
                PreflightOutcome::Skipped {
                    canonical_name,
                    out_path,
                } => {
                    ok_count += 1;
                    out.decrypt_skipped(n, total, &canonical_name, &out_path)
                }
                PreflightOutcome::Ready { .. } => {
                    unreachable!("first_ready_idx is None — no Ready outcome exists")
                }
            };
            if let Err(e) = emitted {
                eprintln!("piggy pass show-batch: stdout write failed: {e}");
                return 1;
            }
        }
        let _ = out.summary(ok_count, failed_count);
        return if failed_count == 0 { 0 } else { 1 };
    };

    // The first ready ebox's PRIMARY config lists one or more recipient
    // pubkeys (1-of-N). Collect them ALL; we'll open the batch session
    // against whichever attached card matches ANY of them (piggy #153).
    let targets = match primary_part_targets(&preflight[first_idx]) {
        Ok(v) => v,
        Err(diag) => {
            let _ = out.bail_out(&format!(
                "cannot identify target recipient for batch: {}",
                diag.message
            ));
            return 1;
        }
    };

    // Step 5: enumerate connected PIV tokens; pick the first whose 9D
    // slot pubkey matches any of the ebox's recipients. The chosen
    // card's own (pubkey, curve) configures BatchOracle — it equals the
    // recipient pubkey of whichever part the card satisfies.
    let ctx = match PivContext::new() {
        Ok(c) => c,
        Err(e) => {
            let _ = out.bail_out(&format!("PCSC unavailable: {e}"));
            return 1;
        }
    };
    let tokens = match ctx.enumerate_tokens() {
        Ok(t) => t,
        Err(e) => {
            let _ = out.bail_out(&format!("PCSC enumerate failed: {e}"));
            return 1;
        }
    };
    let target_slot = piggy_box::template::DEFAULT_SLOT;
    let Some((mut token, (target_uncompressed, target_curve))) =
        select_card_for_targets(tokens, &targets, target_slot)
    else {
        let _ = out
            .bail_out("no attached PIV card has a 9D slot matching any of the ebox's recipients");
        return 1;
    };

    // Step 6: open the session and run the batch.
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            let _ = out.bail_out(&format!("begin_pin_session failed: {e}"));
            return 1;
        }
    };

    // The prompt names only the entries the PIN will actually
    // authorize — `--update` skips and preflight failures never reach
    // the card, so listing them would overstate the authorization.
    let decrypt_names: Vec<String> = preflight
        .iter()
        .filter_map(|p| match p {
            PreflightOutcome::Ready { canonical_name, .. } => Some(canonical_name.clone()),
            _ => None,
        })
        .collect();
    let mut oracle = BatchOracle {
        session: &mut session,
        slot_id: target_slot,
        self_pubkey_uncompressed: target_uncompressed,
        target_curve,
        pin_verified: false,
        pin_supplier: askpass_pin_supplier(),
        pin_prompt: batch_pin_prompt(&decrypt_names),
        last_failure: None,
    };

    let mut ok_count: u32 = 0;
    let mut failed_count: u32 = 0;
    // Track which output paths we've written, so --all-or-nothing can
    // unlink them if any decrypt later fails.
    let mut written_paths: Vec<PathBuf> = Vec::new();
    // When fatal_for_batch fires we record the bail-out reason and
    // break out of the loop to skip the remaining names.
    let mut bail_reason: Option<String> = None;
    for (i, outcome) in preflight.into_iter().enumerate() {
        let n = (i + 1) as u32;
        // SIGINT bail-out: checked at iteration boundary so the
        // current ebox isn't aborted mid-decrypt (which could leak
        // a half-written plaintext or wedge the card transaction).
        // K = n-1 because the prior iteration completed; the current
        // ebox has not started yet.
        if sigint_caught() {
            bail_reason = Some(format!(
                "SIGINT received after decrypt n={} of {total}",
                n - 1
            ));
            break;
        }
        // Per-ebox stats-me: `piggy.pass.show_batch_item.<result>` + duration,
        // one datagram per ebox (in addition to the whole-`show_batch` metric
        // the dispatcher emits). The match yields whether this item decrypted.
        let item_start = std::time::Instant::now();
        let item_ok = match outcome {
            PreflightOutcome::Failed {
                canonical_name,
                diagnostic,
            } => {
                if let Err(e) = out.decrypt_failed(n, total, &canonical_name, diagnostic) {
                    eprintln!("piggy pass show-batch: stdout write failed: {e}");
                    return 1;
                }
                failed_count += 1;
                false
            }
            // Freshness skip counts as ok, but the pre-existing file
            // is NOT recorded in written_paths: --all-or-nothing must
            // not wipe plaintext this run didn't write.
            PreflightOutcome::Skipped {
                canonical_name,
                out_path,
            } => {
                if let Err(e) = out.decrypt_skipped(n, total, &canonical_name, &out_path) {
                    eprintln!("piggy pass show-batch: stdout write failed: {e}");
                    return 1;
                }
                ok_count += 1;
                true
            }
            PreflightOutcome::Ready {
                canonical_name,
                bytes,
                mut stream,
            } => match decrypt_one(&mut stream, &bytes, &mut oracle) {
                Ok(plain) => {
                    match atomic_write_0600(&args.out_dir, &canonical_name, &plain, args.update) {
                        Ok(out_path) => {
                            written_paths.push(out_path.clone());
                            if let Err(e) = out.decrypt_ok(n, total, &canonical_name, &out_path) {
                                eprintln!("piggy pass show-batch: stdout write failed: {e}");
                                return 1;
                            }
                            ok_count += 1;
                            true
                        }
                        Err(e) => {
                            let diag = Diagnostic {
                                kind: DiagnosticKind::IoError,
                                message: e,
                                retryable: None,
                            };
                            if let Err(e) = out.decrypt_failed(n, total, &canonical_name, diag) {
                                eprintln!("piggy pass show-batch: stdout write failed: {e}");
                                return 1;
                            }
                            failed_count += 1;
                            false
                        }
                    }
                }
                Err(DecryptError {
                    diagnostic,
                    fatal_for_batch,
                }) => {
                    // Capture the kind+message *before* moving the
                    // diagnostic into the emitter — we use it as the
                    // bail-out reason when fatal.
                    let kind_label = format!("{:?}", diagnostic.kind);
                    let summary = diagnostic.message.clone();
                    if let Err(e) = out.decrypt_failed(n, total, &canonical_name, diagnostic) {
                        eprintln!("piggy pass show-batch: stdout write failed: {e}");
                        return 1;
                    }
                    failed_count += 1;
                    if fatal_for_batch {
                        // Emit before the `break` (the post-match emit below
                        // won't run for the bailing item).
                        piggy::stats::pass_op(
                            "show_batch_item",
                            piggy::stats::Outcome::Failure,
                            item_start.elapsed(),
                        );
                        bail_reason = Some(format!(
                            "{kind_label} after decrypt n={n} of {total}: {summary}"
                        ));
                        break;
                    }
                    false
                }
            },
        };
        piggy::stats::pass_op(
            "show_batch_item",
            if item_ok {
                piggy::stats::Outcome::Success
            } else {
                piggy::stats::Outcome::Failure
            },
            item_start.elapsed(),
        );
    }

    // Explicit session end so we can propagate
    // `SCardEndTransaction` errors as a non-zero exit. If end fails,
    // and we haven't already decided to bail, surface as a bail-out
    // so a downstream TAP bridge sees the truncation flag.
    if let Err(e) = session.end() {
        if bail_reason.is_none() {
            bail_reason = Some(format!("SCardEndTransaction failed: {e}"));
        }
    }

    // --all-or-nothing: if any failure occurred and the flag is set,
    // unlink every successfully-written plaintext. Best-effort; a
    // consumer that has already read the decrypt-ok records may have
    // copied the bytes — this cleanup reduces window-of-exposure but
    // does NOT guarantee containment.
    if args.all_or_nothing && (failed_count > 0 || bail_reason.is_some()) {
        for path in &written_paths {
            if let Err(e) = std::fs::remove_file(path) {
                eprintln!(
                    "piggy pass show-batch: all-or-nothing wipe failed to remove {}: {e}",
                    path.display()
                );
            }
        }
    }

    if let Some(reason) = bail_reason {
        let _ = out.bail_out(&reason);
        return 1;
    }

    if let Err(e) = out.summary(ok_count, failed_count) {
        eprintln!("piggy pass show-batch: stdout write failed: {e}");
        return 1;
    }

    if failed_count == 0 { 0 } else { 1 }
}

/// Read pass-names one per line from `path`. Trims whitespace,
/// skips blank lines and `#`-prefixed comments. The file is read
/// fully into memory — show-batch's design point is "tens to
/// hundreds of secrets per batch", not millions, so a streaming
/// reader is unnecessary overhead.
///
/// IO errors propagate as-is — callers map them to a usage-error
/// exit (`2`) so misconfigured automation surfaces a clear failure
/// before any decrypt records are emitted.
fn read_names_from(path: &Path) -> std::io::Result<Vec<String>> {
    let body = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        out.push(trimmed.to_string());
    }
    Ok(out)
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

/// Build the `SSH_ASKPASS` prompt for a show-batch run (piggy#140).
///
/// The single PIN entry authorizes decryption of the whole batch, so
/// the prompt names *what* is being decrypted — the count of secrets
/// plus a capped sample of their canonical pass-names — rather than a
/// generic "PIV PIN". `contrib/piggy-askpass.sh` renders this on top of
/// its context banner; `libexec/pivy-askpass` passes it straight to
/// `zenity --title`, so the user sees the batch they are authorizing.
///
/// The name list is capped at [`PROMPT_MAX_NAMES`] so a large batch
/// can't blow out a dialog title; the remainder is summarized as
/// "+N more".
fn batch_pin_prompt(names: &[String]) -> String {
    /// Cap on how many pass-names to spell out before eliding.
    const PROMPT_MAX_NAMES: usize = 3;

    let count = names.len();
    let noun = if count == 1 { "secret" } else { "secrets" };
    let mut list = names
        .iter()
        .take(PROMPT_MAX_NAMES)
        .map(|n| canonicalize_pass_name(n))
        .collect::<Vec<_>>()
        .join(", ");
    if count > PROMPT_MAX_NAMES {
        use std::fmt::Write as _;
        let _ = write!(list, ", +{} more", count - PROMPT_MAX_NAMES);
    }
    format!("piggy PIV PIN — decrypt {count} {noun}: {list}")
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

/// One PRIMARY-config recipient: its SEC1-uncompressed pubkey + curve.
type RecipientTarget = (Vec<u8>, piggy_box::piv_box::EcCurve);

/// Collect EVERY PRIMARY-config recipient (uncompressed pubkey + curve)
/// from the first ready ebox. show-batch picks one (card, slot) pair for
/// the whole batch by matching an attached card's 9D pubkey against
/// **any** of these — not just part[0] — so a multi-recipient (1-of-N)
/// box decrypts whenever any one of its recipients' cards is present
/// (piggy #153). A part whose recipient pubkey won't decompress is
/// skipped rather than failing the whole batch; only an ebox with no
/// usable PRIMARY recipient at all is a hard error.
fn primary_part_targets(outcome: &PreflightOutcome) -> Result<Vec<RecipientTarget>, Diagnostic> {
    let stream = match outcome {
        PreflightOutcome::Ready { stream, .. } => stream,
        _ => unreachable!("primary_part_targets called on a Failed outcome"),
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
    let targets: Vec<RecipientTarget> = primary
        .parts
        .iter()
        .filter_map(|part| {
            canonicalize_uncompressed(&part.piv_box.recipient_pubkey)
                .ok()
                .map(|uncompressed| (uncompressed, part.piv_box.curve))
        })
        .collect();
    if targets.is_empty() {
        return Err(Diagnostic {
            kind: DiagnosticKind::DecryptFailed,
            message: "PRIMARY config has no usable recipient parts".into(),
            retryable: None,
        });
    }
    Ok(targets)
}

/// Pick the attached card to open the batch session against: the first
/// enumerated card whose 9D-slot pubkey matches **any** of the ebox's
/// PRIMARY recipients. Returns the chosen token plus the card's own
/// (uncompressed pubkey, curve) — which is what `BatchOracle` is
/// configured with, and equals the recipient pubkey of whichever part
/// that card satisfies. `None` when no attached card matches any part.
fn select_card_for_targets(
    tokens: Vec<PivToken>,
    targets: &[RecipientTarget],
    target_slot: u8,
) -> Option<(PivToken, RecipientTarget)> {
    for token in tokens {
        let Ok(slot) = token.read_slot(target_slot) else {
            continue;
        };
        let (candidate, curve) = match slot.public_key().key_data() {
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => {
                (p.as_bytes().to_vec(), piggy_box::piv_box::EcCurve::NistP256)
            }
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(p)) => {
                (p.as_bytes().to_vec(), piggy_box::piv_box::EcCurve::NistP384)
            }
            _ => continue,
        };
        if candidate_matches_any(&candidate, targets) {
            return Some((token, (candidate, curve)));
        }
    }
    None
}

/// True when `candidate` (a card's SEC1-uncompressed 9D pubkey) equals
/// the recipient pubkey of any target part. The pure matching core of
/// [`select_card_for_targets`], split out so it's unit-testable without
/// a live PIV token. Curve is not compared here: pubkey-bytes equality
/// is decisive (two curves can't share an uncompressed encoding), and
/// the matched part's curve travels with its target tuple.
fn candidate_matches_any(candidate: &[u8], targets: &[RecipientTarget]) -> bool {
    targets
        .iter()
        .any(|(pubkey, _)| pubkey.as_slice() == candidate)
}

/// Per-ebox failure carrying both the diagnostic to emit and a
/// "fatal for the whole batch" flag. PIN exhaustion or card removal
/// mean subsequent decrypts have no hope; the run loop bails out
/// rather than re-prompting / retrying.
struct DecryptError {
    diagnostic: Diagnostic,
    fatal_for_batch: bool,
}

/// Pre-flight: if NO PRIMARY recipient uses the chosen card's slot
/// curve, return a single-line description so [`decrypt_one`] can
/// surface it as `decrypt-failed` without calling `unlock_ebox`.
/// Returns `None` when any part's curve matches (the card can decrypt
/// that part) or when the ebox has no PRIMARY config (the latter would
/// surface its own error from `unlock_ebox` shortly after). Considers
/// every part, not just part[0] (piggy #153).
///
/// Heterogeneous-curve batches are rare — within a single piggy
/// store they only occur mid-migration when one folder's
/// `piggy-ids` has been re-issued against a different curve — so
/// the goal here is a clearer error message, not a separate
/// `DiagnosticKind`. Per RFC 0005 decision 3c, "wrong recipient"
/// stays under `decrypt-failed`.
fn check_curve_mismatch(
    stream: &EboxStream,
    target_curve: piggy_box::piv_box::EcCurve,
) -> Option<String> {
    let primary = stream
        .ebox
        .configs
        .iter()
        .find(|c| c.config_type == EboxConfigType::Primary)?;
    // No part is part[0]-privileged (piggy #153): the decrypt can use
    // any part whose recipient is on the chosen card, so this is only a
    // real mismatch when NO part matches the card's curve. Report the
    // first part's curve as a representative in the message.
    if primary
        .parts
        .iter()
        .any(|part| part.piv_box.curve == target_curve)
    {
        return None;
    }
    let representative = primary.parts.first()?;
    Some(format!(
        "ebox recipient curve {} does not match the chosen card's slot curve {} \
         (heterogeneous batch — re-encrypt this ebox or run show-batch with a \
         matching card)",
        representative.piv_box.curve.wire_name(),
        target_curve.wire_name(),
    ))
}

/// Use `unlock_ebox` to materialize the AES key inside `stream.ebox`,
/// then walk the chunk frames in `bytes` and accumulate plaintext.
/// `bytes` is the original on-disk ebox bytes — header + chunks.
///
/// Pre-flights the heterogeneous-batch case first: if the ebox's
/// first PRIMARY recipient uses a curve different from the one
/// `BatchOracle` is configured for (i.e. the curve of the chosen
/// card's 9D slot), we know the decrypt will fail without calling
/// `unlock_ebox` — emit a specific `decrypt-failed` message rather
/// than the generic "unlock failed" the runtime would surface.
///
/// On `unlock_ebox` failure (post pre-flight), drains the oracle's
/// typed [`BatchFailure`] via [`BatchOracle::take_failure`] for an
/// RFC-conformant `DiagnosticKind`. When no typed failure was
/// recorded — i.e. every part returned NoKey — the failure is
/// reported as a generic `decrypt-failed` (RFC 0005 decision 3c:
/// wrong recipient).
fn decrypt_one(
    stream: &mut EboxStream,
    bytes: &[u8],
    oracle: &mut BatchOracle<'_, '_>,
) -> Result<Vec<u8>, DecryptError> {
    if let Some(mismatch) = check_curve_mismatch(stream, oracle.target_curve) {
        return Err(DecryptError {
            diagnostic: Diagnostic {
                kind: DiagnosticKind::DecryptFailed,
                message: mismatch,
                retryable: None,
            },
            fatal_for_batch: false,
        });
    }

    let oracle_dyn: &mut dyn EcdhOracle = oracle;
    if let Err(e) = unlock_ebox(&mut stream.ebox, None, Some(oracle_dyn)) {
        return Err(match oracle.take_failure() {
            Some(failure) => DecryptError {
                fatal_for_batch: failure.is_fatal_for_batch(),
                diagnostic: failure.into_diagnostic(),
            },
            None => DecryptError {
                diagnostic: Diagnostic {
                    kind: DiagnosticKind::DecryptFailed,
                    message: format!("unlock failed: {e}"),
                    retryable: None,
                },
                fatal_for_batch: false,
            },
        });
    }
    // Defensive: drain any failure that may have been recorded on a
    // part that ultimately resolved (e.g. a transient PC/SC blip on
    // an early part followed by success on a later part). Without
    // the drain, the *next* ebox's decrypt_one would consume a
    // stale failure.
    let _ = oracle.take_failure();

    let header_bytes = stream.to_bytes().map_err(|e| DecryptError {
        diagnostic: Diagnostic {
            kind: DiagnosticKind::Internal,
            message: format!("re-serialize header: {e}"),
            retryable: None,
        },
        fatal_for_batch: false,
    })?;
    if bytes.len() < header_bytes.len() {
        return Err(DecryptError {
            diagnostic: Diagnostic {
                kind: DiagnosticKind::DecryptFailed,
                message: "ebox bytes shorter than re-serialized header".into(),
                retryable: None,
            },
            fatal_for_batch: false,
        });
    }
    let mut chunk_data = &bytes[header_bytes.len()..];

    let mut plaintext = Vec::new();
    let mut expected_seqnr: u32 = 0;
    while !chunk_data.is_empty() {
        if chunk_data.len() < 8 {
            return Err(DecryptError {
                diagnostic: Diagnostic {
                    kind: DiagnosticKind::DecryptFailed,
                    message: "truncated chunk frame".into(),
                    retryable: None,
                },
                fatal_for_batch: false,
            });
        }
        let string_len =
            u32::from_be_bytes([chunk_data[4], chunk_data[5], chunk_data[6], chunk_data[7]])
                as usize;
        let frame_len = 4 + 4 + string_len;
        if chunk_data.len() < frame_len {
            return Err(DecryptError {
                diagnostic: Diagnostic {
                    kind: DiagnosticKind::DecryptFailed,
                    message: "truncated chunk data".into(),
                    retryable: None,
                },
                fatal_for_batch: false,
            });
        }
        let frame = &chunk_data[..frame_len];
        let (_, plain) = stream
            .decrypt_chunk(Some(expected_seqnr), frame)
            .map_err(|e| DecryptError {
                diagnostic: Diagnostic {
                    kind: DiagnosticKind::DecryptFailed,
                    message: format!("chunk {expected_seqnr}: {e}"),
                    retryable: None,
                },
                fatal_for_batch: false,
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
/// Under `--update` (`overwrite_stale`) a pre-existing file at the
/// path is stale by definition — the freshness check already skipped
/// the fresh ones — so it is unlinked first; the O_EXCL create is
/// kept (rather than O_TRUNC) so the write never follows a symlink
/// planted at the path.
///
/// Parent directories implied by `name` (e.g. `config/ssh/foo` →
/// `<out_dir>/config/ssh/`) are created with mode 0o700.
fn atomic_write_0600(
    out_dir: &Path,
    name: &str,
    plaintext: &[u8],
    overwrite_stale: bool,
) -> Result<PathBuf, String> {
    let out_path = out_dir.join(name);
    if overwrite_stale {
        match std::fs::remove_file(&out_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove stale {}: {e}", out_path.display())),
        }
    }
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

/// Most-recent typed failure surfaced from inside [`BatchOracle::ecdh`].
///
/// `unlock_ebox` wraps every oracle error into a flat
/// [`piggy_box::error::BoxError::UnlockFailed`], so by the time the
/// run loop sees an Err the original shape is gone. To preserve the
/// fine-grained [`DiagnosticKind`] mapping the RFC asks for, the
/// oracle stashes a typed snapshot here on every "real" failure (i.e.
/// not [`OracleError::NoKey`], which `unlock_ebox` legitimately uses
/// to fan out across parts). The run loop checks `last_failure` after
/// `unlock_ebox` returns Err and consumes it via [`take_failure`]
/// before the next decrypt attempt, so a stale failure can never
/// mislabel a later ebox.
#[derive(Debug)]
enum BatchFailure {
    PinIncorrect { retries: u32 },
    PinBlocked,
    PinCancelled(String),
    CardAbsent(String),
    Other(String),
}

impl BatchFailure {
    /// True iff this failure makes every subsequent decrypt
    /// hopeless: PIN exhaustion or card removal. Drives whether the
    /// run loop bails out or continues with the next ebox.
    fn is_fatal_for_batch(&self) -> bool {
        matches!(
            self,
            BatchFailure::PinIncorrect { .. }
                | BatchFailure::PinBlocked
                | BatchFailure::PinCancelled(_)
                | BatchFailure::CardAbsent(_)
        )
    }

    fn into_diagnostic(self) -> Diagnostic {
        match self {
            BatchFailure::PinIncorrect { retries } => Diagnostic {
                kind: DiagnosticKind::PinIncorrect,
                message: format!("wrong PIN, {retries} retries remaining"),
                retryable: Some(retries > 0),
            },
            BatchFailure::PinBlocked => Diagnostic {
                kind: DiagnosticKind::CardLocked,
                message: "PIN blocked — card requires PUK reset".into(),
                retryable: Some(false),
            },
            BatchFailure::PinCancelled(msg) => Diagnostic {
                kind: DiagnosticKind::PinCancelled,
                message: msg,
                retryable: Some(true),
            },
            BatchFailure::CardAbsent(msg) => Diagnostic {
                kind: DiagnosticKind::CardAbsent,
                message: msg,
                retryable: Some(true),
            },
            BatchFailure::Other(msg) => Diagnostic {
                kind: DiagnosticKind::DecryptFailed,
                message: msg,
                retryable: None,
            },
        }
    }
}

/// Classify a [`PivError`] from `verify_pin` or `ecdh_derive` into a
/// [`BatchFailure`]. PIN-shaped errors get the typed variants the RFC
/// asks for; transport errors that look like card removal land in
/// [`BatchFailure::CardAbsent`]; everything else degrades to
/// [`BatchFailure::Other`].
fn classify_piv_error(e: &PivError) -> BatchFailure {
    match e {
        PivError::PinIncorrect { retries } => BatchFailure::PinIncorrect { retries: *retries },
        PivError::PinBlocked => BatchFailure::PinBlocked,
        PivError::CardNotFound => BatchFailure::CardAbsent("card not found".into()),
        PivError::Pcsc(pcsc_err) => match pcsc_err {
            pcsc::Error::NoSmartcard
            | pcsc::Error::ReaderUnavailable
            | pcsc::Error::RemovedCard => BatchFailure::CardAbsent(format!("PC/SC: {pcsc_err}")),
            _ => BatchFailure::Other(format!("PC/SC: {pcsc_err}")),
        },
        other => BatchFailure::Other(format!("{other}")),
    }
}

/// Heuristic: classify an [`OracleError`] from the askpass pin
/// supplier into a [`BatchFailure`]. `askpass_pin_supplier` reports
/// "exited with..." or "spawn askpass..." via `OracleError::Other`;
/// both should surface as `PinCancelled` so consumers can offer a
/// retry. Other shapes fall through to `Other`.
fn classify_pin_supplier_error(e: OracleError) -> BatchFailure {
    match &e {
        OracleError::Other(msg) if msg.contains("askpass") || msg.contains("SSH_ASKPASS") => {
            BatchFailure::PinCancelled(msg.clone())
        }
        _ => BatchFailure::Other(format!("PIN supply failed: {e}")),
    }
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
///   the first ebox against — a `decrypt-failed` per RFC 0005
///   decision 3c, surfaced by the run loop's fallback when
///   `last_failure` is None.
/// - `target_curve` is captured at construction so we can build the
///   SSH wire blob without re-deriving from the slot every call.
/// - `pin_verified` flips to true on first successful `verify_pin`.
///   The PIN supplier runs exactly once — `unlock_ebox` may make
///   multiple `ecdh` calls per ebox if a config has multiple parts,
///   and we don't want to prompt N times.
/// - `last_failure` carries the typed shape of the most recent
///   non-NoKey error so the run loop can map it to a precise
///   [`DiagnosticKind`]. See [`BatchFailure`].
struct BatchOracle<'sess, 'tok> {
    session: &'sess mut PinSession<'tok>,
    slot_id: u8,
    self_pubkey_uncompressed: Vec<u8>,
    /// Curve of the chosen card's 9D slot. Used by
    /// [`check_curve_mismatch`] to short-circuit decrypts whose
    /// recipient curve doesn't match — produces a clearer error
    /// than letting `unlock_ebox` fail with the generic
    /// "UnlockFailed".
    target_curve: piggy_box::piv_box::EcCurve,
    pin_verified: bool,
    pin_supplier: PinSupplier,
    /// Prompt handed to `pin_supplier`. Carries the batch's request
    /// context (count + pass-names) so the askpass dialog tells the
    /// user what they are authorizing — see [`batch_pin_prompt`]
    /// (piggy#140).
    pin_prompt: String,
    last_failure: Option<BatchFailure>,
}

impl<'sess, 'tok> BatchOracle<'sess, 'tok> {
    /// Consume the most recent failure, if any. Returns `None` when
    /// the prior `unlock_ebox` call failed solely because no
    /// recipient matched (a NoKey-only path), in which case the
    /// caller should report the generic `decrypt-failed` per RFC
    /// 0005 decision 3c.
    fn take_failure(&mut self) -> Option<BatchFailure> {
        self.last_failure.take()
    }
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
            // NoKey lets `unlock_ebox` try the next part. Do NOT
            // record a failure for this — NoKey is the trait's
            // "this isn't my key" signal, not an error condition
            // worth surfacing.
            return Err(OracleError::NoKey);
        }

        if !self.pin_verified {
            let pin = match (self.pin_supplier)(&self.pin_prompt) {
                Ok(p) => p,
                Err(e) => {
                    self.last_failure = Some(classify_pin_supplier_error(e));
                    return Err(OracleError::Other("PIN supply failed".into()));
                }
            };
            if let Err(e) = self.session.verify_pin(&pin) {
                self.last_failure = Some(classify_piv_error(&e));
                return Err(piv_to_oracle_pin_error(e));
            }
            self.pin_verified = true;
        }

        let partner_point = extract_point_from_sshkey_blob(partner_pubkey_ssh_blob)?;
        let partner_uncompressed = canonicalize_uncompressed(&partner_point)?;
        match self
            .session
            .ecdh_derive(self.slot_id, &partner_uncompressed)
        {
            Ok(secret) => Ok(secret),
            Err(e) => {
                self.last_failure = Some(classify_piv_error(&e));
                Err(OracleError::Transport(format!("ecdh_derive: {e}")))
            }
        }
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
                    skipped: false,
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
                skipped: false,
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
            skipped: false,
        }));
        assert!(rendered.contains(r#""out_path":null"#), "{}", rendered);
        // retryable omitted, not null.
        assert!(!rendered.contains(r#""retryable""#), "{}", rendered);
    }

    /// `skipped` is OPTIONAL per RFC 0005 §Compatibility: present
    /// (and `true`) only on `--update` freshness skips, omitted —
    /// not `false` — on real decrypts, so pre-`--update` consumers
    /// see a byte-identical stream.
    #[test]
    fn skipped_field_omitted_unless_true() {
        use std::path::Path;

        let skipped = render(&Record::Decrypt(Decrypt {
            n: 1,
            name: "fresh".into(),
            ok: true,
            out_path: Some("/tmp/fresh".into()),
            diagnostic: None,
            skipped: true,
        }));
        assert!(skipped.contains(r#""skipped":true"#), "{}", skipped);

        let mut buf = Vec::new();
        emit_decrypt_ok(&mut buf, 1, "real", Path::new("/tmp/real")).unwrap();
        emit_decrypt_failed(
            &mut buf,
            2,
            "broken",
            Diagnostic {
                kind: DiagnosticKind::NotFound,
                message: "no ebox".into(),
                retryable: None,
            },
        )
        .unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(!rendered.contains(r#""skipped""#), "{}", rendered);

        let mut buf = Vec::new();
        emit_decrypt_skipped(&mut buf, 3, "fresh", Path::new("/tmp/fresh")).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        assert!(rendered.contains(r#""ok":true"#), "{}", rendered);
        assert!(rendered.contains(r#""skipped":true"#), "{}", rendered);
        assert!(
            rendered.contains(r#""out_path":"/tmp/fresh""#),
            "{}",
            rendered
        );
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

    /// `--names-from FILE` reads one pass-name per line, trims
    /// whitespace, and skips blank + `#`-prefixed lines.
    #[test]
    fn read_names_from_skips_blanks_and_comments() {
        let dir = std::env::temp_dir().join(format!(
            "piggy-show-batch-names-from-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("names.txt");
        std::fs::write(
            &path,
            "# header comment\n\
             config/ssh/foo\n\
             \n\
             config/ssh/bar  \n\
             # mid-file comment\n\
             \t  config/api/baz\n",
        )
        .unwrap();

        let names = super::read_names_from(&path).expect("read should succeed");
        assert_eq!(
            names,
            vec!["config/ssh/foo", "config/ssh/bar", "config/api/baz"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--update` freshness predicate: skip only when the plaintext
    /// exists and is at least as new as the ebox; every error path
    /// (missing plaintext, missing ebox) decrypts.
    #[test]
    fn plaintext_is_fresh_compares_mtimes_conservatively() {
        use std::time::{Duration, SystemTime};

        let dir = std::env::temp_dir().join(format!(
            "piggy-show-batch-fresh-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let ebox = dir.join("secret.ebox");
        let plain = dir.join("secret");
        std::fs::write(&ebox, b"ciphertext").unwrap();

        // Missing plaintext → not fresh.
        assert!(!super::plaintext_is_fresh(&ebox, &plain));

        let set_mtime = |path: &std::path::Path, t: SystemTime| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(t)
                .unwrap();
        };
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);

        // Plaintext newer than ebox → fresh.
        std::fs::write(&plain, b"plaintext").unwrap();
        set_mtime(&ebox, base);
        set_mtime(&plain, base + Duration::from_secs(60));
        assert!(super::plaintext_is_fresh(&ebox, &plain));

        // Equal mtimes → fresh (`>=`, not `>`).
        set_mtime(&plain, base);
        assert!(super::plaintext_is_fresh(&ebox, &plain));

        // Ebox newer than plaintext → stale, must decrypt.
        set_mtime(&ebox, base + Duration::from_secs(60));
        assert!(!super::plaintext_is_fresh(&ebox, &plain));

        // Missing ebox → not fresh (the read path reports not-found).
        assert!(!super::plaintext_is_fresh(&dir.join("absent.ebox"), &plain));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--update` overwrites a stale plaintext (unlink + O_EXCL
    /// recreate); without it an existing path still fails the write.
    #[test]
    fn atomic_write_overwrite_stale_replaces_existing_file() {
        let dir = std::env::temp_dir().join(format!(
            "piggy-show-batch-overwrite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret"), b"old plaintext").unwrap();

        // Default no-clobber posture is unchanged.
        let err = super::atomic_write_0600(&dir, "secret", b"new plaintext", false)
            .expect_err("existing path without overwrite_stale must fail");
        assert!(err.contains("secret"), "{err}");

        let out = super::atomic_write_0600(&dir, "secret", b"new plaintext", true)
            .expect("overwrite_stale should replace the existing file");
        assert_eq!(std::fs::read(&out).unwrap(), b"new plaintext");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "rewritten plaintext must be 0600");
        }

        // overwrite_stale with no pre-existing file is a plain create.
        let out = super::atomic_write_0600(&dir, "secret2", b"v1", true)
            .expect("overwrite_stale on a fresh path should create");
        assert_eq!(std::fs::read(&out).unwrap(), b"v1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Canonical pass-name strips leading `/` and trailing `.ebox`
    /// per RFC 0005 §Decrypt Record. Names that already match the
    /// canonical form pass through unchanged.
    #[test]
    fn canonicalize_pass_name_strips_prefix_and_suffix() {
        assert_eq!(
            super::canonicalize_pass_name("config/ssh/foo"),
            "config/ssh/foo"
        );
        assert_eq!(
            super::canonicalize_pass_name("/config/ssh/foo"),
            "config/ssh/foo"
        );
        assert_eq!(
            super::canonicalize_pass_name("config/ssh/foo.ebox"),
            "config/ssh/foo"
        );
        assert_eq!(
            super::canonicalize_pass_name("/config/ssh/foo.ebox"),
            "config/ssh/foo"
        );
        // Only the trailing `.ebox` is stripped; embedded `.ebox`
        // mid-path is preserved.
        assert_eq!(
            super::canonicalize_pass_name("config/.ebox/foo"),
            "config/.ebox/foo"
        );
    }

    /// piggy#140: the show-batch askpass prompt must carry request
    /// context (how many secrets, which ones) so the SSH_ASKPASS dialog
    /// tells the user what they are authorizing instead of a bare
    /// "PIV PIN". Names are shown canonically (no leading `/`, no
    /// trailing `.ebox`).
    #[test]
    fn batch_pin_prompt_includes_count_and_canonical_names() {
        let names = vec!["deploy/db".to_string(), "/deploy/api.ebox".to_string()];
        let prompt = super::batch_pin_prompt(&names);
        assert!(
            prompt.contains('2'),
            "prompt should state the count: {prompt}"
        );
        assert!(
            prompt.contains("deploy/db"),
            "prompt should list the requested names: {prompt}"
        );
        assert!(
            prompt.contains("deploy/api"),
            "prompt should canonicalize names: {prompt}"
        );
        assert!(
            !prompt.contains(".ebox"),
            "names should be canonical (no .ebox suffix): {prompt}"
        );
    }

    /// A single secret uses the singular noun.
    #[test]
    fn batch_pin_prompt_singular_for_one_secret() {
        let prompt = super::batch_pin_prompt(&["solo".to_string()]);
        assert!(prompt.contains("1 secret"), "expected singular: {prompt}");
        assert!(
            !prompt.contains("secrets"),
            "one secret must not pluralize: {prompt}"
        );
    }

    /// Long batches cap the listed names so the dialog title stays
    /// bounded; the elided remainder is summarized as "+N more".
    #[test]
    fn batch_pin_prompt_caps_long_name_list() {
        let names: Vec<String> = (0..10).map(|i| format!("secret-{i}")).collect();
        let prompt = super::batch_pin_prompt(&names);
        assert!(prompt.contains("10 secrets"), "expected count: {prompt}");
        assert!(
            prompt.contains("+7 more"),
            "expected elision summary: {prompt}"
        );
        assert!(
            !prompt.contains("secret-9"),
            "must not list every name: {prompt}"
        );
    }

    /// PIN/card failures bail the whole batch; per-ebox decrypt
    /// errors do not. This drives whether the run loop emits a
    /// `bail-out` or keeps going after a `decrypt-failed`.
    #[test]
    fn batch_failure_fatal_for_batch() {
        use super::BatchFailure;
        assert!(BatchFailure::PinIncorrect { retries: 2 }.is_fatal_for_batch());
        assert!(BatchFailure::PinBlocked.is_fatal_for_batch());
        assert!(BatchFailure::PinCancelled("user hit Cancel".into()).is_fatal_for_batch());
        assert!(BatchFailure::CardAbsent("card removed".into()).is_fatal_for_batch());
        assert!(!BatchFailure::Other("transient PCSC blip".into()).is_fatal_for_batch());
    }

    /// PivError → BatchFailure classification (the inverse map back
    /// to RFC 0005's `DiagnosticKind`).
    #[test]
    fn classify_piv_error_maps_to_expected_failure() {
        use super::{BatchFailure, classify_piv_error};
        use piggy_piv::PivError;

        assert!(matches!(
            classify_piv_error(&PivError::PinIncorrect { retries: 3 }),
            BatchFailure::PinIncorrect { retries: 3 }
        ));
        assert!(matches!(
            classify_piv_error(&PivError::PinBlocked),
            BatchFailure::PinBlocked
        ));
        assert!(matches!(
            classify_piv_error(&PivError::CardNotFound),
            BatchFailure::CardAbsent(_)
        ));
        // PivError::Other → BatchFailure::Other (catch-all path)
        assert!(matches!(
            classify_piv_error(&PivError::Other("weird APDU".into())),
            BatchFailure::Other(_)
        ));
    }

    /// askpass cancel/failure messages map to PinCancelled so the
    /// RFC 0005 consumer can offer a retry, rather than treating
    /// them as opaque internal errors.
    #[test]
    fn classify_pin_supplier_error_recognizes_askpass_cancel() {
        use super::{BatchFailure, classify_pin_supplier_error};
        use piggy_box::oracle::OracleError;

        assert!(matches!(
            classify_pin_supplier_error(OracleError::Other("askpass exited with status 1".into())),
            BatchFailure::PinCancelled(_)
        ));
        assert!(matches!(
            classify_pin_supplier_error(OracleError::Other(
                "no PIN source: SSH_ASKPASS_REQUIRE=force but SSH_ASKPASS not set".into()
            )),
            BatchFailure::PinCancelled(_)
        ));
        // Unrelated OracleError shapes fall through to Other.
        assert!(matches!(
            classify_pin_supplier_error(OracleError::Transport("socket eof".into())),
            BatchFailure::Other(_)
        ));
    }

    /// BatchFailure::into_diagnostic produces the right kind +
    /// retryable hint for each shape.
    #[test]
    fn batch_failure_into_diagnostic_kinds() {
        use super::BatchFailure;
        use super::ndjson::DiagnosticKind;

        let d = BatchFailure::PinIncorrect { retries: 2 }.into_diagnostic();
        assert!(matches!(d.kind, DiagnosticKind::PinIncorrect));
        assert_eq!(d.retryable, Some(true));

        let d = BatchFailure::PinIncorrect { retries: 0 }.into_diagnostic();
        assert_eq!(d.retryable, Some(false));

        let d = BatchFailure::PinBlocked.into_diagnostic();
        assert!(matches!(d.kind, DiagnosticKind::CardLocked));
        assert_eq!(d.retryable, Some(false));

        let d = BatchFailure::PinCancelled("x".into()).into_diagnostic();
        assert!(matches!(d.kind, DiagnosticKind::PinCancelled));
        assert_eq!(d.retryable, Some(true));

        let d = BatchFailure::CardAbsent("x".into()).into_diagnostic();
        assert!(matches!(d.kind, DiagnosticKind::CardAbsent));
        assert_eq!(d.retryable, Some(true));

        let d = BatchFailure::Other("x".into()).into_diagnostic();
        assert!(matches!(d.kind, DiagnosticKind::DecryptFailed));
        assert_eq!(d.retryable, None);
    }

    /// Construct an EboxStream sealed to a freshly-generated EC
    /// keypair on the given curve, for use in curve-mismatch tests.
    /// Mirrors the `seed_tpl_and_priv` helper in
    /// `crates/piggy-box/src/unlock.rs::tests` — we need a real
    /// `Ebox::create` because the `Ebox.key` field is private and the
    /// struct can't be built directly.
    fn make_stream_for_curve(curve: piggy_box::piv_box::EcCurve) -> piggy_box::stream::EboxStream {
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        use piggy_box::stream::EboxStream;
        use piggy_box::template::{DEFAULT_SLOT, EboxTplConfig, EboxTplPart};
        use piggy_box::{EboxConfigType, EboxTemplate};

        let group = EcGroup::from_curve_name(curve.nid()).unwrap();
        let priv_key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let pubkey = priv_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();

        let tpl = EboxTemplate {
            version: 1,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![EboxTplPart {
                    guid: None,
                    slot: DEFAULT_SLOT,
                    name: Some("piggy-test:curve-mismatch".into()),
                    pubkey,
                    pubkey_curve: curve,
                    cak: None,
                }],
            }],
        };
        EboxStream::new(&tpl).expect("stream creation should succeed")
    }

    /// `check_curve_mismatch` returns Some(...) when the ebox's
    /// recipient curve differs from the chosen card's slot curve.
    #[test]
    fn curve_mismatch_p256_recipient_p384_card() {
        use piggy_box::piv_box::EcCurve;

        let stream = make_stream_for_curve(EcCurve::NistP256);
        let result = super::check_curve_mismatch(&stream, EcCurve::NistP384);
        let msg = result.expect("mismatch should be detected");
        assert!(msg.contains("nistp256"), "got: {msg}");
        assert!(msg.contains("nistp384"), "got: {msg}");
        assert!(
            msg.contains("heterogeneous batch"),
            "should mention heterogeneous batch — got: {msg}"
        );
    }

    /// Same-curve case is a no-op (returns None).
    #[test]
    fn curve_mismatch_returns_none_for_matching_curve() {
        use piggy_box::piv_box::EcCurve;

        let stream = make_stream_for_curve(EcCurve::NistP256);
        assert!(super::check_curve_mismatch(&stream, EcCurve::NistP256).is_none());

        let stream = make_stream_for_curve(EcCurve::NistP384);
        assert!(super::check_curve_mismatch(&stream, EcCurve::NistP384).is_none());
    }

    /// Build a PRIMARY config with two parts on the two given curves
    /// (one recipient each). Used to test that card-selection /
    /// curve-checks consider EVERY part, not just part[0] (piggy #153).
    fn make_two_part_stream(
        c0: piggy_box::piv_box::EcCurve,
        c1: piggy_box::piv_box::EcCurve,
    ) -> piggy_box::stream::EboxStream {
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        use piggy_box::stream::EboxStream;
        use piggy_box::template::{DEFAULT_SLOT, EboxTplConfig, EboxTplPart};
        use piggy_box::{EboxConfigType, EboxTemplate};

        let mk_part = |curve: piggy_box::piv_box::EcCurve, name: &str| {
            let group = EcGroup::from_curve_name(curve.nid()).unwrap();
            let priv_key = EcKey::generate(&group).unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            let pubkey = priv_key
                .public_key()
                .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
                .unwrap();
            EboxTplPart {
                guid: None,
                slot: DEFAULT_SLOT,
                name: Some(name.into()),
                pubkey,
                pubkey_curve: curve,
                cak: None,
            }
        };

        let tpl = EboxTemplate {
            version: 1,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![
                    mk_part(c0, "piggy-test:two-part-0"),
                    mk_part(c1, "piggy-test:two-part-1"),
                ],
            }],
        };
        EboxStream::new(&tpl).expect("stream creation should succeed")
    }

    /// #153: a multi-recipient box is NOT a curve mismatch when the
    /// chosen card's curve matches ANY part — even if part[0]'s curve
    /// differs. Pre-fix this returned Some(...) because it only looked
    /// at part[0].
    #[test]
    fn curve_mismatch_considers_all_parts_not_just_part0() {
        use piggy_box::piv_box::EcCurve;

        // part0 = P-256, part1 = P-384.
        let stream = make_two_part_stream(EcCurve::NistP256, EcCurve::NistP384);
        // A P-384 card matches part1 → no mismatch (the bug would flag
        // it because part0 is P-256).
        assert!(
            super::check_curve_mismatch(&stream, EcCurve::NistP384).is_none(),
            "P-384 card should match part1, not be reported as a mismatch"
        );
        // A P-256 card matches part0 → no mismatch.
        assert!(super::check_curve_mismatch(&stream, EcCurve::NistP256).is_none());
    }

    /// A real mismatch (no part matches the card's curve) still reports.
    #[test]
    fn curve_mismatch_reports_when_no_part_matches() {
        use piggy_box::piv_box::EcCurve;

        // Both parts P-256; a P-384 card matches neither.
        let stream = make_two_part_stream(EcCurve::NistP256, EcCurve::NistP256);
        let msg = super::check_curve_mismatch(&stream, EcCurve::NistP384)
            .expect("no part matches the P-384 card — should report mismatch");
        assert!(msg.contains("nistp384"), "got: {msg}");
    }

    /// #153: the pure card-matching predicate matches a candidate
    /// against ANY target part's recipient pubkey, by bytes.
    #[test]
    fn candidate_matches_any_finds_a_later_part() {
        use piggy_box::piv_box::EcCurve;
        let part0 = (vec![0x02u8; 33], EcCurve::NistP256);
        let part1 = (vec![0x03u8; 33], EcCurve::NistP256);
        let targets = vec![part0, part1];

        // A card whose pubkey equals part1 (not part0) still matches.
        assert!(super::candidate_matches_any(&[0x03u8; 33], &targets));
        // part0 matches too.
        assert!(super::candidate_matches_any(&[0x02u8; 33], &targets));
        // A pubkey present in neither part does not match.
        assert!(!super::candidate_matches_any(&[0x04u8; 33], &targets));
        // Empty target set never matches.
        assert!(!super::candidate_matches_any(&[0x02u8; 33], &[]));
    }
}
