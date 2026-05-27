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

/// Exit code conventions:
/// - 0: every ebox in the batch decrypted successfully.
/// - 1: at least one ebox failed, or the batch was bailed out.
/// - 2: usage error (e.g. neither positional names nor `--names-from`
///   yielded any pass-names, conflicting flags, unreadable
///   `--names-from`).
pub fn run(_args: ShowBatchArgs) -> i32 {
    // TODO(#121): implementation lands in a follow-up commit. Wire-up
    // skeleton only here so the clap dispatch tree compiles.
    eprintln!("piggy pass show-batch: not yet implemented (see piggy#121)");
    2
}
