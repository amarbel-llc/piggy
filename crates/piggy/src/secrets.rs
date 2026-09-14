//! `piggy secrets reconcile`: materialise ebox-backed secrets as plain files
//! from a declarative manifest (FDR 0003,
//! `docs/features/0003-declarative-ebox-secret-reconcile.md`).
//!
//! The contract, in the order `reconcile` enforces it:
//!
//! - Classification is offline: it reads each entry's ciphertext and
//!   `lstat`s its target, never PC/SC. A steady-state run opens no card and
//!   prompts for no PIN.
//! - Freshness is the ciphertext's SHA-256 plus the target's stat fingerprint,
//!   both recorded in the state file — never mtime (nix-store files all carry
//!   mtime 1). The state file holds no plaintext digest: a hash of a
//!   low-entropy token is an offline guessing oracle.
//! - Every entry that needs a write decrypts in ONE unlock session through the
//!   backend `pass show-batch` uses ([`show_batch::with_batch_unlock`]: card
//!   first, forwarded agent as fallback).
//! - Writes go temp file → fchmod → fsync → rename(2). A failure leaves the
//!   previous target untouched; nothing is deleted first.
//! - Ownership is explicit: an existing target not recorded as piggy-managed
//!   is a conflict unless the entry (or `--adopt`) says to take it over. An
//!   entry dropped from the manifest is released — its state record goes, its
//!   file stays.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use piggy::card::frontend::select::FrontendKind;
use piggy_box::stream::EboxStream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::show_batch::{self, BatchUnlocked, DecryptError};

/// Manifest schema version this binary reads (`piggy-secrets-manifest/1`).
const MANIFEST_VERSION: u32 = 1;
/// State-file schema version this binary reads and writes.
const STATE_VERSION: u32 = 1;
/// Permission bits for an entry that doesn't set `mode`.
const DEFAULT_MODE: u32 = 0o600;

/// CLI arguments for `piggy secrets reconcile`.
#[derive(Debug)]
pub struct ReconcileArgs {
    /// Manifest path; `None` means `$XDG_STATE_HOME/piggy/secrets/manifest.json`.
    pub manifest: Option<PathBuf>,
    /// Classify and report only; never decrypt or write.
    pub check: bool,
    /// Treat every entry as `adopt: true`.
    pub adopt: bool,
    /// Attach a YAML diagnostic block to every TAP point.
    pub verbose: bool,
    /// Interaction frontend for the batch PIN prompt (RFC 0006 §6).
    pub frontend: FrontendKind,
    /// `AF_UNIX` socket for the JSON-RPC frontend.
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDoc {
    version: u32,
    entries: Vec<ManifestEntryDoc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntryDoc {
    name: String,
    ebox: PathBuf,
    target: PathBuf,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    adopt: bool,
}

/// One validated manifest entry.
#[derive(Debug, Clone, PartialEq)]
struct Entry {
    name: String,
    ebox: PathBuf,
    target: PathBuf,
    mode: u32,
    adopt: bool,
}

fn parse_manifest(text: &str) -> Result<Vec<Entry>, String> {
    let doc: ManifestDoc =
        serde_json::from_str(text).map_err(|e| format!("invalid manifest JSON: {e}"))?;
    if doc.version != MANIFEST_VERSION {
        return Err(format!(
            "unsupported manifest version {} (this piggy reads version {MANIFEST_VERSION})",
            doc.version
        ));
    }
    let mut names = BTreeSet::new();
    let mut targets = BTreeSet::new();
    doc.entries
        .into_iter()
        .map(|e| {
            if !is_valid_entry_name(&e.name) {
                return Err(format!(
                    "entry name {:?} must match [A-Za-z0-9._-]+",
                    e.name
                ));
            }
            if !names.insert(e.name.clone()) {
                return Err(format!("duplicate entry name {:?}", e.name));
            }
            if !e.target.is_absolute() || e.target.file_name().is_none() {
                return Err(format!(
                    "entry {:?}: target {} must be an absolute file path",
                    e.name,
                    e.target.display()
                ));
            }
            if !targets.insert(e.target.clone()) {
                return Err(format!(
                    "entry {:?}: target {} is declared twice",
                    e.name,
                    e.target.display()
                ));
            }
            let mode = match e.mode.as_deref() {
                None => DEFAULT_MODE,
                Some(m) => parse_mode(m).ok_or_else(|| {
                    format!(
                        "entry {:?}: mode {m:?} is not an octal permission like \"0600\"",
                        e.name
                    )
                })?,
            };
            Ok(Entry {
                name: e.name,
                ebox: e.ebox,
                target: e.target,
                mode,
                adopt: e.adopt,
            })
        })
        .collect()
}

fn is_valid_entry_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parse `"0600"`, `"600"` or `"0o600"` into permission bits (at most 0o777).
fn parse_mode(mode: &str) -> Option<u32> {
    let digits = mode.strip_prefix("0o").unwrap_or(mode);
    if digits.is_empty() || digits.len() > 4 || !digits.bytes().all(|b| (b'0'..=b'7').contains(&b))
    {
        return None;
    }
    u32::from_str_radix(digits, 8).ok().filter(|m| *m <= 0o777)
}

/// What `reconcile` remembers about a target it wrote. A later run treats the
/// target as its own only while this still matches the file on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    mtime_sec: i64,
    mtime_nsec: i64,
}

impl Fingerprint {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mode: meta.mode() & 0o7777,
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StateRecord {
    name: String,
    ebox_sha256: String,
    fingerprint: Fingerprint,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct State {
    version: u32,
    /// Keyed by absolute target path.
    entries: BTreeMap<PathBuf, StateRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

fn load_state(path: &Path) -> Result<State, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(format!("read state {}: {e}", path.display())),
    };
    // A state file we can't read is never replaced with an empty one: that
    // would silently forget which targets piggy owns.
    let state: State = serde_json::from_str(&text).map_err(|e| {
        format!(
            "invalid state file {}: {e} (refusing to guess which files piggy owns)",
            path.display()
        )
    })?;
    if state.version != STATE_VERSION {
        return Err(format!(
            "unsupported state version {} in {} (this piggy reads version {STATE_VERSION})",
            state.version,
            path.display()
        ));
    }
    Ok(state)
}

fn save_state(path: &Path, state: &State) -> Result<(), String> {
    let mut json = serde_json::to_vec_pretty(state).map_err(|e| format!("serialize state: {e}"))?;
    json.push(b'\n');
    write_atomically(path, &json, 0o600).map(|_| ())
}

fn xdg_dir(var: &str, home_relative_default: &str) -> Option<PathBuf> {
    match std::env::var_os(var) {
        Some(v) if Path::new(&v).is_absolute() => Some(PathBuf::from(v)),
        _ => std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(|h| PathBuf::from(h).join(home_relative_default)),
    }
}

fn secrets_state_dir() -> Option<PathBuf> {
    xdg_dir("XDG_STATE_HOME", ".local/state").map(|d| d.join("piggy").join("secrets"))
}

/// The home-manager module keeps its manifest here as a GC-root symlink (so
/// the manifest stays out of the home generation's closure; FDR 0003).
fn default_manifest_path() -> Option<PathBuf> {
    secrets_state_dir().map(|d| d.join("manifest.json"))
}

fn default_state_path() -> Option<PathBuf> {
    secrets_state_dir().map(|d| d.join("state.json"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Absent,
    Directory,
    /// A regular file, symlink, or other non-directory.
    File {
        regular: bool,
        fingerprint: Fingerprint,
    },
}

fn inspect_target(target: &Path) -> Result<TargetKind, String> {
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.is_dir() => Ok(TargetKind::Directory),
        Ok(meta) => Ok(TargetKind::File {
            regular: meta.file_type().is_file(),
            fingerprint: Fingerprint::of(&meta),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TargetKind::Absent),
        Err(e) => Err(format!("stat {}: {e}", target.display())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteReason {
    Missing,
    Stale,
    Modified,
    Adopt,
}

impl WriteReason {
    fn label(self) -> &'static str {
        match self {
            WriteReason::Missing => "missing",
            WriteReason::Stale => "stale",
            WriteReason::Modified => "modified",
            WriteReason::Adopt => "adopt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    Fresh,
    Write(WriteReason),
    Conflict(String),
}

/// The pure ownership + freshness decision for one entry.
fn classify(
    target: TargetKind,
    record: Option<&StateRecord>,
    ebox_sha256: &str,
    adopt: bool,
) -> Plan {
    match (target, record) {
        (TargetKind::Absent, _) => Plan::Write(WriteReason::Missing),
        (TargetKind::Directory, _) => Plan::Conflict("target is a directory".into()),
        (
            TargetKind::File {
                regular,
                fingerprint,
            },
            Some(rec),
        ) => {
            if !regular || fingerprint != rec.fingerprint {
                Plan::Write(WriteReason::Modified)
            } else if rec.ebox_sha256 != ebox_sha256 {
                Plan::Write(WriteReason::Stale)
            } else {
                Plan::Fresh
            }
        }
        (TargetKind::File { .. }, None) if adopt => Plan::Write(WriteReason::Adopt),
        (TargetKind::File { .. }, None) => Plan::Conflict(
            "target exists but is not recorded as piggy-managed; set `adopt` on the entry \
             (or pass --adopt) to take it over"
                .into(),
        ),
    }
}

/// Write `contents` to `path` without ever exposing a partial or
/// wider-permission file there: temp file in the same directory (created
/// 0600), fchmod to `mode`, fsync, rename(2) over `path`. rename replaces a
/// symlink at `path` rather than following it. Missing parent directories are
/// created 0700. Returns the new file's fingerprint.
fn write_atomically(path: &Path, contents: &[u8], mode: u32) -> Result<Fingerprint, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("{} has no file name", path.display()))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".piggy-secrets-{}.tmp", std::process::id()));
    let tmp = parent.join(tmp_name);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("create {}: {e}", tmp.display()))?;
    let written = file
        .write_all(contents)
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {e}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename into {}: {e}", path.display()));
    }
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| format!("stat {}: {e}", path.display()))?;
    Ok(Fingerprint::of(&meta))
}

/// An entry classified as needing a write, carrying what the write needs.
struct Pending {
    index: usize,
    ebox_sha256: String,
    bytes: Vec<u8>,
    reason: WriteReason,
}

enum Outcome {
    UpToDate,
    Wrote(WriteReason),
    WouldWrite(WriteReason),
    Failed(String),
}

/// Decrypt every pending entry in one unlock session. Results are
/// index-aligned with `pending`. An entry whose ebox doesn't parse fails on
/// its own without reaching the card; a batch-fatal failure (PIN exhaustion,
/// card removal) marks the entries after it as not attempted.
fn decrypt_pending(
    entries: &[Entry],
    pending: &[Pending],
    args: &ReconcileArgs,
) -> Vec<Result<Zeroizing<Vec<u8>>, String>> {
    let mut results: Vec<Option<Result<Zeroizing<Vec<u8>>, String>>> =
        (0..pending.len()).map(|_| None).collect();
    let mut streams: Vec<(usize, EboxStream)> = Vec::new();
    for (k, p) in pending.iter().enumerate() {
        match EboxStream::from_bytes(&p.bytes) {
            Ok(stream) => streams.push((k, stream)),
            Err(e) => results[k] = Some(Err(format!("invalid ebox stream: {e}"))),
        }
    }

    let targets = streams
        .first()
        .map(|(_, first)| show_batch::primary_part_targets(first));
    match targets {
        None => {}
        Some(Err(diag)) => {
            for (k, _) in &streams {
                results[*k] = Some(Err(format!(
                    "cannot identify target recipient for batch: {}",
                    diag.message
                )));
            }
        }
        Some(Ok(targets)) => {
            let names: Vec<String> = streams
                .iter()
                .map(|(k, _)| entries[pending[*k].index].name.clone())
                .collect();
            let unlocked = show_batch::with_batch_unlock(
                &targets,
                &names,
                args.frontend,
                args.socket.as_deref(),
                "secrets reconcile",
                |card, agent| {
                    let (mut card, mut agent) = (card, agent);
                    let mut decrypted = Vec::with_capacity(streams.len());
                    let mut fatal: Option<String> = None;
                    for (k, stream) in streams.iter_mut() {
                        if let Some(reason) = &fatal {
                            decrypted.push((*k, Err(format!("not attempted after: {reason}"))));
                            continue;
                        }
                        match show_batch::decrypt_one(
                            stream,
                            &pending[*k].bytes,
                            card.as_deref_mut(),
                            agent.as_deref_mut(),
                        ) {
                            Ok(plain) => decrypted.push((*k, Ok(Zeroizing::new(plain)))),
                            Err(DecryptError {
                                diagnostic,
                                fatal_for_batch,
                            }) => {
                                let message = describe_diagnostic(&diagnostic);
                                if fatal_for_batch {
                                    fatal = Some(message.clone());
                                }
                                decrypted.push((*k, Err(message)));
                            }
                        }
                    }
                    decrypted
                },
            );
            match unlocked {
                Ok(BatchUnlocked {
                    result,
                    session_end_error,
                }) => {
                    if let Some(e) = session_end_error {
                        eprintln!("piggy secrets reconcile: {e}");
                    }
                    for (k, r) in result {
                        results[k] = Some(r);
                    }
                }
                Err(reason) => {
                    for (k, _) in &streams {
                        results[*k] = Some(Err(reason.clone()));
                    }
                }
            }
        }
    }

    results
        .into_iter()
        .map(|r| r.unwrap_or_else(|| Err("internal: entry was never attempted".into())))
        .collect()
}

fn describe_diagnostic(diagnostic: &show_batch::ndjson::Diagnostic) -> String {
    let kind = serde_json::to_value(&diagnostic.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "internal".into());
    format!("{kind}: {}", diagnostic.message)
}

/// TAP-14 description escaping: `\` and `#` would otherwise start an escape
/// or a directive.
fn tap_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('#', "\\#")
}

fn write_yaml_block<W: Write>(out: &mut W, fields: &[(&str, String)]) -> std::io::Result<()> {
    writeln!(out, "  ---")?;
    for (key, value) in fields {
        // A JSON string literal is a valid YAML double-quoted scalar.
        writeln!(out, "  {key}: {}", serde_json::Value::String(value.clone()))?;
    }
    writeln!(out, "  ...")
}

struct Tally {
    failures: usize,
    drift: usize,
}

fn emit_report<W: Write>(
    out: &mut W,
    entries: &[Entry],
    outcomes: Vec<Outcome>,
    orphans: &[PathBuf],
    args: &ReconcileArgs,
) -> std::io::Result<Tally> {
    let mut tally = Tally {
        failures: 0,
        drift: 0,
    };
    writeln!(out, "TAP version 14")?;
    writeln!(out, "1..{}", entries.len() + orphans.len())?;
    for (i, (entry, outcome)) in entries.iter().zip(outcomes).enumerate() {
        let n = i + 1;
        let name = tap_escape(&entry.name);
        let target = entry.target.display().to_string();
        match outcome {
            Outcome::UpToDate => {
                writeln!(out, "ok {n} - {name} # SKIP up to date")?;
                if args.verbose {
                    write_yaml_block(out, &[("target", target)])?;
                }
            }
            Outcome::Wrote(reason) => {
                writeln!(out, "ok {n} - {name}")?;
                if args.verbose {
                    write_yaml_block(
                        out,
                        &[("target", target), ("wrote", reason.label().to_string())],
                    )?;
                }
            }
            Outcome::WouldWrite(reason) => {
                tally.drift += 1;
                writeln!(out, "not ok {n} - {name}")?;
                write_yaml_block(
                    out,
                    &[
                        ("message", format!("would write ({})", reason.label())),
                        ("target", target),
                    ],
                )?;
            }
            Outcome::Failed(message) => {
                tally.failures += 1;
                writeln!(out, "not ok {n} - {name}")?;
                write_yaml_block(out, &[("message", message), ("target", target)])?;
            }
        }
    }
    let orphan_status = if args.check {
        "orphaned: reconcile will release it"
    } else {
        "orphaned: released; file kept"
    };
    for (j, orphan) in orphans.iter().enumerate() {
        let n = entries.len() + j + 1;
        writeln!(
            out,
            "ok {n} - {} # SKIP {orphan_status}",
            tap_escape(&orphan.display().to_string())
        )?;
    }
    out.flush()?;
    Ok(tally)
}

/// Reconcile `entries` against the state file at `state_path`, reporting a
/// TAP-14 stream on `out`. Returns the process exit code: 0 when every entry
/// is fresh or written, 1 on any failure (or any drift under `--check`), 2
/// when the state file is unusable.
fn reconcile<W: Write>(
    entries: Vec<Entry>,
    state_path: &Path,
    args: &ReconcileArgs,
    out: &mut W,
) -> i32 {
    let mut state = match load_state(state_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy secrets reconcile: {e}");
            return 2;
        }
    };

    let mut outcomes: Vec<Option<Outcome>> = (0..entries.len()).map(|_| None).collect();
    let mut pending: Vec<Pending> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let bytes = match std::fs::read(&entry.ebox) {
            Ok(b) => b,
            Err(e) => {
                outcomes[i] = Some(Outcome::Failed(format!(
                    "read ebox {}: {e}",
                    entry.ebox.display()
                )));
                continue;
            }
        };
        let ebox_sha256 = hex::encode(Sha256::digest(&bytes));
        let target = match inspect_target(&entry.target) {
            Ok(t) => t,
            Err(e) => {
                outcomes[i] = Some(Outcome::Failed(e));
                continue;
            }
        };
        let record = state.entries.get(&entry.target);
        match classify(target, record, &ebox_sha256, entry.adopt || args.adopt) {
            Plan::Fresh => outcomes[i] = Some(Outcome::UpToDate),
            Plan::Conflict(message) => outcomes[i] = Some(Outcome::Failed(message)),
            Plan::Write(reason) if args.check => outcomes[i] = Some(Outcome::WouldWrite(reason)),
            Plan::Write(reason) => pending.push(Pending {
                index: i,
                ebox_sha256,
                bytes,
                reason,
            }),
        }
    }

    let declared: BTreeSet<&Path> = entries.iter().map(|e| e.target.as_path()).collect();
    let orphans: Vec<PathBuf> = state
        .entries
        .keys()
        .filter(|t| !declared.contains(t.as_path()))
        .cloned()
        .collect();

    let mut state_changed = false;
    if !pending.is_empty() {
        let results = decrypt_pending(&entries, &pending, args);
        for (p, result) in pending.iter().zip(results) {
            let entry = &entries[p.index];
            outcomes[p.index] = Some(match result {
                Err(message) => Outcome::Failed(message),
                Ok(plain) => match write_atomically(&entry.target, &plain, entry.mode) {
                    Err(message) => Outcome::Failed(message),
                    Ok(fingerprint) => {
                        state.entries.insert(
                            entry.target.clone(),
                            StateRecord {
                                name: entry.name.clone(),
                                ebox_sha256: p.ebox_sha256.clone(),
                                fingerprint,
                            },
                        );
                        state_changed = true;
                        Outcome::Wrote(p.reason)
                    }
                },
            });
        }
    }

    if !args.check && !orphans.is_empty() {
        for orphan in &orphans {
            state.entries.remove(orphan);
        }
        state_changed = true;
    }

    let mut exit = 0;
    if state_changed {
        if let Err(e) = save_state(state_path, &state) {
            eprintln!(
                "piggy secrets reconcile: {e} (files written this run are not recorded; \
                 the next run will need --adopt for them)"
            );
            exit = 1;
        }
    }

    let outcomes: Vec<Outcome> = outcomes
        .into_iter()
        .map(|o| {
            o.unwrap_or_else(|| Outcome::Failed("internal: entry was never classified".into()))
        })
        .collect();
    match emit_report(out, &entries, outcomes, &orphans, args) {
        Ok(tally) if tally.failures > 0 || (args.check && tally.drift > 0) => 1,
        Ok(_) => exit,
        Err(e) => {
            eprintln!("piggy secrets reconcile: stdout write failed: {e}");
            1
        }
    }
}

/// Entry point for `piggy secrets reconcile`. See the module docs.
pub fn run(args: ReconcileArgs) -> i32 {
    let Some(manifest_path) = args.manifest.clone().or_else(default_manifest_path) else {
        eprintln!(
            "piggy secrets reconcile: no --manifest given and neither XDG_STATE_HOME nor HOME is set"
        );
        return 2;
    };
    let text = match std::fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "piggy secrets reconcile: read manifest {}: {e}",
                manifest_path.display()
            );
            return 2;
        }
    };
    let entries = match parse_manifest(&text) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("piggy secrets reconcile: {}: {e}", manifest_path.display());
            return 2;
        }
    };
    let Some(state_path) = default_state_path() else {
        eprintln!("piggy secrets reconcile: neither XDG_STATE_HOME nor HOME is set");
        return 2;
    };
    reconcile(entries, &state_path, &args, &mut std::io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "piggy-secrets-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn args(check: bool) -> ReconcileArgs {
        ReconcileArgs {
            manifest: None,
            check,
            adopt: false,
            verbose: false,
            frontend: FrontendKind::Tty,
            socket: None,
        }
    }

    fn entry(name: &str, ebox: &Path, target: &Path) -> Entry {
        Entry {
            name: name.into(),
            ebox: ebox.into(),
            target: target.into(),
            mode: DEFAULT_MODE,
            adopt: false,
        }
    }

    fn run_reconcile(
        entries: Vec<Entry>,
        state_path: &Path,
        args: &ReconcileArgs,
    ) -> (i32, String) {
        let mut out = Vec::new();
        let code = reconcile(entries, state_path, args, &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    fn record_for(target: &Path, ebox_bytes: &[u8]) -> StateRecord {
        StateRecord {
            name: "alpha".into(),
            ebox_sha256: hex::encode(Sha256::digest(ebox_bytes)),
            fingerprint: Fingerprint::of(&std::fs::symlink_metadata(target).unwrap()),
        }
    }

    fn file_kind(regular: bool, fingerprint: Fingerprint) -> TargetKind {
        TargetKind::File {
            regular,
            fingerprint,
        }
    }

    const FP: Fingerprint = Fingerprint {
        dev: 1,
        ino: 2,
        size: 3,
        mode: 0o600,
        mtime_sec: 4,
        mtime_nsec: 5,
    };

    #[test]
    fn parse_manifest_applies_defaults() {
        let entries = parse_manifest(
            r#"{"version":1,"entries":[{"name":"a","ebox":"/nix/store/x-a.ebox","target":"/home/u/.a"}]}"#,
        )
        .unwrap();
        assert_eq!(
            entries,
            vec![Entry {
                name: "a".into(),
                ebox: "/nix/store/x-a.ebox".into(),
                target: "/home/u/.a".into(),
                mode: 0o600,
                adopt: false,
            }]
        );
    }

    #[test]
    fn parse_manifest_rejects_invalid_documents() {
        for (doc, needle) in [
            (
                r#"{"version":2,"entries":[]}"#,
                "unsupported manifest version",
            ),
            (
                r#"{"version":1,"entries":[{"name":"a","ebox":"/e","target":"rel/a"}]}"#,
                "absolute",
            ),
            (
                r#"{"version":1,"entries":[{"name":"a b","ebox":"/e","target":"/a"}]}"#,
                "must match",
            ),
            (
                r#"{"version":1,"entries":[{"name":"a","ebox":"/e","target":"/a"},{"name":"a","ebox":"/e","target":"/b"}]}"#,
                "duplicate entry name",
            ),
            (
                r#"{"version":1,"entries":[{"name":"a","ebox":"/e","target":"/a"},{"name":"b","ebox":"/e","target":"/a"}]}"#,
                "declared twice",
            ),
            (
                r#"{"version":1,"entries":[{"name":"a","ebox":"/e","target":"/a","mode":"0999"}]}"#,
                "octal permission",
            ),
            (
                r#"{"version":1,"entries":[{"name":"a","ebox":"/e","target":"/a","owner":"root"}]}"#,
                "invalid manifest JSON",
            ),
        ] {
            let err = parse_manifest(doc).unwrap_err();
            assert!(
                err.contains(needle),
                "{doc}: expected {needle:?} in {err:?}"
            );
        }
    }

    #[test]
    fn parse_mode_accepts_octal_spellings_only() {
        assert_eq!(parse_mode("0600"), Some(0o600));
        assert_eq!(parse_mode("640"), Some(0o640));
        assert_eq!(parse_mode("0o400"), Some(0o400));
        assert_eq!(parse_mode(""), None);
        assert_eq!(parse_mode("0800"), None);
        assert_eq!(parse_mode("4777"), None);
        assert_eq!(parse_mode("rw-------"), None);
    }

    #[test]
    fn classify_covers_ownership_and_freshness() {
        let rec = StateRecord {
            name: "a".into(),
            ebox_sha256: "aa".into(),
            fingerprint: FP,
        };
        assert_eq!(
            classify(TargetKind::Absent, Some(&rec), "aa", false),
            Plan::Write(WriteReason::Missing)
        );
        assert!(matches!(
            classify(TargetKind::Directory, Some(&rec), "aa", true),
            Plan::Conflict(_)
        ));
        assert_eq!(
            classify(file_kind(true, FP), Some(&rec), "aa", false),
            Plan::Fresh
        );
        assert_eq!(
            classify(file_kind(true, FP), Some(&rec), "bb", false),
            Plan::Write(WriteReason::Stale)
        );
        let edited = Fingerprint { size: 9, ..FP };
        assert_eq!(
            classify(file_kind(true, edited), Some(&rec), "aa", false),
            Plan::Write(WriteReason::Modified)
        );
        assert_eq!(
            classify(file_kind(false, FP), Some(&rec), "aa", false),
            Plan::Write(WriteReason::Modified)
        );
        assert!(matches!(
            classify(file_kind(true, FP), None, "aa", false),
            Plan::Conflict(_)
        ));
        assert_eq!(
            classify(file_kind(false, FP), None, "aa", true),
            Plan::Write(WriteReason::Adopt)
        );
    }

    #[test]
    fn write_atomically_applies_mode_and_replaces_symlink_without_following() {
        let dir = scratch_dir("write");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"do not touch").unwrap();
        let target = dir.join("nested/secret");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        write_atomically(&target, b"plaintext", 0o640).unwrap();

        let meta = std::fs::symlink_metadata(&target).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.mode() & 0o777, 0o640);
        assert_eq!(std::fs::read(&target).unwrap(), b"plaintext");
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
        let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_round_trips_through_disk() {
        let dir = scratch_dir("state");
        let path = dir.join("state/state.json");
        assert_eq!(load_state(&path).unwrap(), State::default());
        let mut state = State::default();
        state.entries.insert(
            "/home/u/.a".into(),
            StateRecord {
                name: "a".into(),
                ebox_sha256: "aa".into(),
                fingerprint: FP,
            },
        );
        save_state(&path, &state).unwrap();
        assert_eq!(load_state(&path).unwrap(), state);
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_state(&path).unwrap_err().contains("refusing to guess"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_reports_missing_target_without_writing() {
        let dir = scratch_dir("check");
        let ebox = dir.join("a.ebox");
        std::fs::write(&ebox, b"ciphertext").unwrap();
        let target = dir.join("home/.a");
        let state_path = dir.join("state.json");

        let (code, out) = run_reconcile(
            vec![entry("alpha", &ebox, &target)],
            &state_path,
            &args(true),
        );

        assert_eq!(code, 1);
        assert!(out.contains("not ok 1 - alpha"), "{out}");
        assert!(out.contains("would write (missing)"), "{out}");
        assert!(!target.exists());
        assert!(!state_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn steady_state_skips_without_parsing_the_ebox() {
        let dir = scratch_dir("fresh");
        // Not a valid ebox: a decrypt attempt would fail, so success proves
        // the fresh path never reaches the unlock backend.
        let ebox = dir.join("a.ebox");
        std::fs::write(&ebox, b"not an ebox").unwrap();
        let target = dir.join(".a");
        std::fs::write(&target, b"plaintext").unwrap();
        let state_path = dir.join("state.json");
        let mut state = State::default();
        state
            .entries
            .insert(target.clone(), record_for(&target, b"not an ebox"));
        save_state(&state_path, &state).unwrap();

        let (code, out) = run_reconcile(
            vec![entry("alpha", &ebox, &target)],
            &state_path,
            &args(false),
        );

        assert_eq!(code, 0, "{out}");
        assert!(out.contains("ok 1 - alpha # SKIP up to date"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrecorded_target_is_a_conflict_and_left_untouched() {
        let dir = scratch_dir("conflict");
        let ebox = dir.join("a.ebox");
        std::fs::write(&ebox, b"not an ebox").unwrap();
        let target = dir.join(".a");
        std::fs::write(&target, b"hand-written").unwrap();
        let state_path = dir.join("state.json");

        let (code, out) = run_reconcile(
            vec![entry("alpha", &ebox, &target)],
            &state_path,
            &args(false),
        );

        assert_eq!(code, 1);
        assert!(out.contains("not ok 1 - alpha"), "{out}");
        assert!(out.contains("not recorded as piggy-managed"), "{out}");
        assert_eq!(std::fs::read(&target).unwrap(), b"hand-written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_decrypt_keeps_the_previous_output() {
        let dir = scratch_dir("stale");
        let target = dir.join(".a");
        std::fs::write(&target, b"old plaintext").unwrap();
        let state_path = dir.join("state.json");
        let mut state = State::default();
        state
            .entries
            .insert(target.clone(), record_for(&target, b"previous ciphertext"));
        save_state(&state_path, &state).unwrap();
        // The ebox changed (stale) but doesn't parse, so it fails before any
        // card session and the old output must survive.
        let ebox = dir.join("a.ebox");
        std::fs::write(&ebox, b"rotated but corrupt").unwrap();

        let (code, out) = run_reconcile(
            vec![entry("alpha", &ebox, &target)],
            &state_path,
            &args(false),
        );

        assert_eq!(code, 1);
        assert!(out.contains("invalid ebox stream"), "{out}");
        assert_eq!(std::fs::read(&target).unwrap(), b"old plaintext");
        assert_eq!(load_state(&state_path).unwrap(), state);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dropped_entry_is_released_but_its_file_kept() {
        let dir = scratch_dir("orphan");
        let target = dir.join(".gone");
        std::fs::write(&target, b"plaintext").unwrap();
        let state_path = dir.join("state.json");
        let mut state = State::default();
        state
            .entries
            .insert(target.clone(), record_for(&target, b"ciphertext"));
        save_state(&state_path, &state).unwrap();

        let (code, out) = run_reconcile(vec![], &state_path, &args(false));

        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("# SKIP orphaned: released; file kept"),
            "{out}"
        );
        assert!(target.exists());
        assert!(load_state(&state_path).unwrap().entries.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tap_escape_neutralises_directive_characters() {
        assert_eq!(tap_escape(r"a#b\c"), r"a\#b\\c");
    }
}
