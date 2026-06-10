//! `piggy pass recipients` — full Rust port.
//!
//! All recipients subcommands are now in Rust: `list`, `add` (both the
//! explicit-recipients form and the `-A`/`--all-attached` interactive
//! card-detection path), `remove`, and `sync`. `list-available` is
//! dispatched directly through `exec::exec_piggy_ids` from main.rs
//! (no module wiring needed). No recipients path reaches `piggy.sh`
//! anymore (#96 step 6 retired the last bash recipients function).
//!
//! `list` mirrors the former `cmd_pass_recipients_list` in
//! `src/piggy.sh`; `add`, `remove`, and `sync` mirror the former
//! `cmd_pass_recipients_{add,remove,sync}`; `add_all_attached` mirrors
//! `_cmd_pass_recipients_add_all_attached`. The canonicalize / validate
//! / diff / detect-all-pubkeys steps shell to the `piggy-ids` binary
//! (located via `PIGGY_IDS_PATH`, same as `reencrypt.rs`) so the bats
//! mock — which intercepts `encrypt` / `detect-all-pubkeys` but
//! delegates the rest to the real binary — exercises the same logic the
//! bash original did.

use std::ffi::OsString;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git_ops;
use crate::reencrypt;
use crate::store::{find_piggy_ids, resolve_target, store_root};

/// Exit code conventions:
/// - 0: piggy-ids found and printed
/// - 1: usage error or no piggy-ids in the walk chain
/// - 2: IO error while reading the file
pub fn list(args: &[String]) -> i32 {
    let subfolder = match parse_subfolder(args) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("piggy pass recipients list: {msg}");
            return 1;
        }
    };

    let root = store_root();
    let ids_path = match find_piggy_ids(&root, &subfolder) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("piggy pass recipients list: {msg}");
            return 1;
        }
    };

    let contents = match std::fs::read(&ids_path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!(
                "piggy pass recipients list: read {}: {}",
                ids_path.display(),
                err
            );
            return 2;
        }
    };

    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_all(&contents) {
        eprintln!("piggy pass recipients list: write stdout: {err}");
        return 2;
    }
    0
}

/// `piggy pass recipients add <markl-id>... [-p subfolder]`.
///
/// Mirrors `cmd_pass_recipients_add` in `src/piggy.sh`. The
/// `-A`/`--all-attached` interactive card-detection path is handled by
/// [`add_all_attached`] (mirrors `_cmd_pass_recipients_add_all_attached`).
pub fn add(args: &[String]) -> i32 {
    let parsed = match parse_add(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if parsed.all_attached {
        return add_all_attached(&parsed.subfolder, parsed.assume_yes);
    }

    if parsed.ids.is_empty() {
        eprintln!(
            "Usage: piggy pass recipients add <markl-id>... [-p subfolder]\n       piggy pass recipients add -A | --all-attached [--yes] [-p subfolder]"
        );
        return 1;
    }

    let root = store_root();
    let piggy_ids = match find_piggy_ids(&root, &parsed.subfolder) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return 1;
        }
    };

    // Build candidate in a tempfile, validate via canonicalize, then
    // atomically install — mirrors the bash append-before-validate
    // guard that keeps a malformed input from corrupting the live file.
    let tmp = tmp_sibling(&piggy_ids);
    if let Err(err) = std::fs::copy(&piggy_ids, &tmp) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to stage candidate piggy-ids: {err}");
        return 1;
    }
    if let Err(err) = append_ids(&tmp, &parsed.ids) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to stage candidate piggy-ids: {err}");
        return 1;
    }
    if !piggy_ids_ok(&["canonicalize", &tmp.to_string_lossy()]) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: invalid recipient(s); aborting.");
        return 1;
    }
    if let Err(err) = std::fs::rename(&tmp, &piggy_ids) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to install candidate piggy-ids: {err}");
        return 1;
    }

    let id_dir = piggy_ids_dir(&piggy_ids);
    commit_and_reencrypt(
        &root,
        &piggy_ids,
        id_dir,
        "Add recipient(s) to piggy-ids.",
        "Reencrypt password store after adding recipient(s).",
        false,
    )
}

/// `piggy pass recipients add -A | --all-attached [--yes] [-p subfolder]`.
///
/// Mirrors `_cmd_pass_recipients_add_all_attached` in `src/piggy.sh`:
/// enumerate every attached PIV card via `piggy-ids detect-all-pubkeys`,
/// partition the supported ones into already-present vs to-add, gate on
/// any unsupported cards, then reuse the add-path tail (atomic tempfile
/// add + canonicalize + install + commit + reencrypt + commit) for the
/// survivors.
fn add_all_attached(subfolder: &str, assume_yes: bool) -> i32 {
    let root = store_root();
    let piggy_ids = match find_piggy_ids(&root, subfolder) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return 1;
        }
    };

    let helper_out = match piggy_ids_output(&["detect-all-pubkeys"]) {
        Some(out) => out,
        None => {
            eprintln!("Error: detect-all-pubkeys failed; see stderr.");
            return 1;
        }
    };

    let detected = match parse_detect_all_pubkeys(&helper_out) {
        Ok(d) => d,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if detected.supported.is_empty() && detected.unsupported.is_empty() {
        eprintln!("Error: no PIV cards detected.");
        return 1;
    }

    // Canonicalize current piggy-ids so equality below is byte-equality
    // on the markl-ID column. canonicalize is idempotent.
    if !piggy_ids_ok(&["canonicalize", &piggy_ids.to_string_lossy()]) {
        eprintln!("Error: existing piggy-ids invalid.");
        return 1;
    }

    let current = match std::fs::read_to_string(&piggy_ids) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Error: failed to read {}: {err}", piggy_ids.display());
            return 1;
        }
    };
    let current_set = current_markl_ids(&current);

    // Partition supported cards into to_add vs already-present.
    let mut to_add: Vec<String> = Vec::new();
    for card in &detected.supported {
        if current_set.contains(card.id.as_str()) {
            println!("already a recipient: {}  # GUID {}", card.id, card.guid);
        } else {
            to_add.push(card.id.clone());
        }
    }

    if !detected.unsupported.is_empty() {
        eprintln!(
            "Cannot encrypt to {} attached card(s) (slot 9D is not P-256 ECDH):",
            detected.unsupported.len()
        );
        for card in &detected.unsupported {
            eprintln!("  {}: {}", card.guid, card.reason);
        }

        if !assume_yes {
            if std::io::stdin().is_terminal() {
                eprint!(
                    "Continue and add the {} supported card(s)? [y/N] ",
                    to_add.len()
                );
                let _ = std::io::stderr().flush();
                let reply = read_tty_line();
                match reply.as_str() {
                    "y" | "Y" | "yes" | "Yes" | "YES" => {}
                    _ => {
                        eprintln!("aborted");
                        return 1;
                    }
                }
            } else {
                eprintln!(
                    "aborted: unsupported cards detected and stdin is not a TTY; pass --yes to proceed"
                );
                return 1;
            }
        }
    }

    if to_add.is_empty() {
        eprintln!("nothing to add");
        return 0;
    }

    let count = to_add.len();
    let tmp = tmp_sibling(&piggy_ids);
    if let Err(err) = std::fs::copy(&piggy_ids, &tmp) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to stage candidate piggy-ids: {err}");
        return 1;
    }
    if let Err(err) = append_ids(&tmp, &to_add) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to stage candidate piggy-ids: {err}");
        return 1;
    }
    if !piggy_ids_ok(&["canonicalize", &tmp.to_string_lossy()]) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: invalid recipient(s); aborting.");
        return 1;
    }
    if let Err(err) = std::fs::rename(&tmp, &piggy_ids) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to install candidate piggy-ids: {err}");
        return 1;
    }

    let id_dir = piggy_ids_dir(&piggy_ids);
    commit_and_reencrypt(
        &root,
        &piggy_ids,
        id_dir,
        &format!("Add {count} attached card(s) to piggy-ids."),
        &format!("Reencrypt password store after adding {count} attached card(s)."),
        false,
    )
}

/// `piggy pass recipients remove <markl-id>... [-p subfolder]`.
///
/// Mirrors `cmd_pass_recipients_remove` in `src/piggy.sh`: canonicalise
/// the live file so user-supplied (possibly bare-format) IDs match the
/// on-disk form, filter out matching IDs into a tempfile, and only
/// install + commit when something actually changed.
pub fn remove(args: &[String]) -> i32 {
    let parsed = parse_subfolder_and_ids(args);

    if parsed.ids.is_empty() {
        eprintln!("Usage: piggy pass recipients remove <markl-id>... [-p subfolder]");
        return 1;
    }

    let root = store_root();
    let piggy_ids = match find_piggy_ids(&root, &parsed.subfolder) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return 1;
        }
    };

    if !piggy_ids_ok(&["canonicalize", &piggy_ids.to_string_lossy()]) {
        eprintln!("Error: existing piggy-ids invalid.");
        return 1;
    }

    let original = match std::fs::read_to_string(&piggy_ids) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Error: failed to read {}: {err}", piggy_ids.display());
            return 1;
        }
    };
    let filtered = filter_out_recipients(&original, &parsed.ids);

    if filtered == original {
        println!("No matching recipients in {}.", piggy_ids.display());
        return 0;
    }

    let tmp = tmp_sibling(&piggy_ids);
    if let Err(err) = std::fs::write(&tmp, filtered.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to stage candidate piggy-ids: {err}");
        return 1;
    }
    if let Err(err) = std::fs::rename(&tmp, &piggy_ids) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to install candidate piggy-ids: {err}");
        return 1;
    }

    let id_dir = piggy_ids_dir(&piggy_ids);
    commit_and_reencrypt(
        &root,
        &piggy_ids,
        id_dir,
        "Remove recipient(s) from piggy-ids.",
        "Reencrypt password store after removing recipient(s).",
        false,
    )
}

/// `piggy pass recipients sync [<file>] [-p subfolder]`.
///
/// Two forms:
///
/// - With `<file>`: mirrors `cmd_pass_recipients_sync` in `src/piggy.sh` —
///   validate the declared file, no-op when it already matches the live
///   recipients (the `diff` idempotency check), otherwise copy it over the
///   live file, canonicalise in place, and commit + reencrypt.
/// - Without `<file>`: re-encrypt every ebox to the recipients already
///   declared in the `piggy-ids` file(s), then commit. Bare `sync` walks the
///   whole store; `sync -p <subfolder>` scopes the walk to that subtree. Each
///   ebox still picks up its *nearest* `piggy-ids`. This is the ergonomic
///   front-end to the otherwise-hidden `internal-reencrypt-path` command.
pub fn sync(args: &[String]) -> i32 {
    let parsed = match parse_sync(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    let root = store_root();

    // No <file>: re-encrypt the existing store (whole store, or the
    // `-p <subfolder>` subtree) to the recipients already declared in the
    // piggy-ids file(s), then commit. No piggy-ids edit happens here, so
    // unlike the <file> path there is nothing to validate/canonicalize.
    let Some(file) = parsed.file else {
        let scope = (!parsed.subfolder.is_empty()).then_some(parsed.subfolder.as_str());
        let target = match resolve_target(&root, scope) {
            Ok(t) => t,
            Err(msg) => {
                eprintln!("Error: {msg}");
                return 1;
            }
        };
        return reencrypt_and_commit(&target, parsed.verbose);
    };

    if !Path::new(&file).is_file() {
        eprintln!("Error: file not found: {file}");
        return 1;
    }

    let piggy_ids = match find_piggy_ids(&root, &parsed.subfolder) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return 1;
        }
    };

    if !piggy_ids_ok(&["validate", &file]) {
        eprintln!("Error: {file} failed validation.");
        return 1;
    }

    // Idempotency: if no diff, no commit, no reencryption.
    if piggy_ids_ok(&["diff", &piggy_ids.to_string_lossy(), &file]) {
        return 0;
    }

    if let Err(err) = std::fs::copy(&file, &piggy_ids) {
        eprintln!(
            "Error: failed to copy {file} → {}: {err}",
            piggy_ids.display()
        );
        return 1;
    }
    if !piggy_ids_ok(&["canonicalize", &piggy_ids.to_string_lossy()]) {
        eprintln!("Error: post-copy canonicalize failed.");
        return 1;
    }

    let id_dir = piggy_ids_dir(&piggy_ids);
    commit_and_reencrypt(
        &root,
        &piggy_ids,
        id_dir,
        "Sync recipients in piggy-ids.",
        "Reencrypt password store after syncing recipients.",
        parsed.verbose,
    )
}

#[derive(Debug)]
struct AddArgs {
    subfolder: String,
    all_attached: bool,
    assume_yes: bool,
    ids: Vec<String>,
}

/// Parse the `add` argv: `-p <subfolder>`, `-A`/`--all-attached`,
/// `--yes`, and positional markl IDs. `--yes` only affects the `-A`
/// path (it accepts the "unsupported cards detected" prompt
/// non-interactively); it is harmless on the explicit-IDs path. An
/// unknown `-flag` is a usage error, matching the bash `-*) die` arm.
fn parse_add(args: &[String]) -> Result<AddArgs, String> {
    let mut subfolder = String::new();
    let mut all_attached = false;
    let mut assume_yes = false;
    let mut ids = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-p" => match iter.next() {
                Some(v) => subfolder = v.clone(),
                None => return Err("Error: -p requires a subfolder argument".into()),
            },
            "-A" | "--all-attached" => all_attached = true,
            "--yes" => assume_yes = true,
            other if other.starts_with('-') => {
                return Err(format!("Error: unknown flag: {other}"));
            }
            other => ids.push(other.to_string()),
        }
    }

    if all_attached && !ids.is_empty() {
        return Err("Error: --all-attached and explicit markl IDs are mutually exclusive.".into());
    }

    Ok(AddArgs {
        subfolder,
        all_attached,
        assume_yes,
        ids,
    })
}

struct SubfolderAndIds {
    subfolder: String,
    ids: Vec<String>,
}

/// Parse the `remove` argv: `-p <subfolder>` plus positional IDs.
/// Mirrors the bash loop, which treats every non-`-p` token (including
/// `-`-prefixed ones) as an ID.
fn parse_subfolder_and_ids(args: &[String]) -> SubfolderAndIds {
    let mut subfolder = String::new();
    let mut ids = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-p" {
            if let Some(v) = iter.next() {
                subfolder = v.clone();
            }
        } else {
            ids.push(arg.clone());
        }
    }
    SubfolderAndIds { subfolder, ids }
}

#[derive(Debug)]
struct SyncArgs {
    subfolder: String,
    file: Option<String>,
    verbose: bool,
}

/// Parse the `sync` argv: `-p <subfolder>`, `-v`/`--verbose` (TAP YAML
/// diagnostics on every point, not just failures), plus exactly one
/// positional `<file>`. A second positional is a usage error, matching
/// the bash `[[ -z $file ]] || die` guard.
fn parse_sync(args: &[String]) -> Result<SyncArgs, String> {
    let mut subfolder = String::new();
    let mut file: Option<String> = None;
    let mut verbose = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-p" => {
                if let Some(v) = iter.next() {
                    subfolder = v.clone();
                }
            }
            "-v" | "--verbose" => verbose = true,
            _ if file.is_some() => {
                return Err("Error: only one <file> argument permitted.".into());
            }
            _ => file = Some(arg.clone()),
        }
    }
    Ok(SyncArgs {
        subfolder,
        file,
        verbose,
    })
}

/// Append each markl ID as its own line to `path`, mirroring the bash
/// `echo "$id" >>"$tmp"` loop.
fn append_ids(path: &Path, ids: &[String]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    for id in ids {
        writeln!(file, "{id}")?;
    }
    Ok(())
}

/// Drop every line whose markl ID (the text before a `  # ...` comment,
/// stripped of surrounding whitespace) is in `targets`. Comment-only
/// and blank lines are passed through verbatim. Mirrors the awk filter
/// in `cmd_pass_recipients_remove`.
fn filter_out_recipients(contents: &str, targets: &[String]) -> String {
    let want: std::collections::HashSet<&str> = targets
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();

    let mut out = String::new();
    for line in contents.split_inclusive('\n') {
        let (body, newline) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        if is_comment_or_blank(body) {
            out.push_str(line);
            continue;
        }
        let id = recipient_id_of_line(body);
        if !want.contains(id) {
            out.push_str(body);
            out.push_str(newline);
        }
    }
    out
}

/// True for lines that are blank or whose first non-whitespace
/// character is `#` — the awk `/^[[:space:]]*#/ || /^[[:space:]]*$/`
/// passthrough arm.
fn is_comment_or_blank(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Extract the markl ID from a recipient line: strip a trailing
/// `[[:space:]]+#...` comment, then trim leading/trailing whitespace.
/// Mirrors the three awk `sub()` calls.
fn recipient_id_of_line(line: &str) -> &str {
    let without_comment = match find_comment_start(line) {
        Some(idx) => &line[..idx],
        None => line,
    };
    without_comment.trim()
}

/// Find the byte index of the whitespace that precedes an inline `#`
/// comment, matching awk's `[[:space:]]+#.*$`. Returns the index of the
/// first whitespace character of the run; `None` when there is no
/// whitespace-preceded `#`.
fn find_comment_start(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' && i > 0 && bytes[i - 1].is_ascii_whitespace() {
            let mut start = i - 1;
            while start > 0 && bytes[start - 1].is_ascii_whitespace() {
                start -= 1;
            }
            return Some(start);
        }
        i += 1;
    }
    None
}

/// A supported PIV card: its canonical markl ID and GUID hex.
#[derive(Debug, PartialEq, Eq)]
struct SupportedCard {
    id: String,
    guid: String,
}

/// An unsupported PIV card: its GUID hex and the reason slot 9D can't
/// be used as a recipient.
#[derive(Debug, PartialEq, Eq)]
struct UnsupportedCard {
    guid: String,
    reason: String,
}

#[derive(Debug, PartialEq, Eq, Default)]
struct DetectedCards {
    supported: Vec<SupportedCard>,
    unsupported: Vec<UnsupportedCard>,
}

/// Parse the TSV stdout of `piggy-ids detect-all-pubkeys`. Each line is
/// either `supported\t<markl-id>\t<guid>` or
/// `unsupported\t<guid>\t<reason>`. Blank lines are skipped; any other
/// shape is a malformed-line error. Mirrors the bash `while IFS=$'\t'
/// read -r status f1 f2` loop and its `die` messages.
fn parse_detect_all_pubkeys(output: &str) -> Result<DetectedCards, String> {
    let mut detected = DetectedCards::default();
    for line in output.lines() {
        let mut fields = line.splitn(3, '\t');
        let status = fields.next().unwrap_or("");
        if status.is_empty() {
            continue;
        }
        let f1 = fields.next().unwrap_or("");
        let f2 = fields.next().unwrap_or("");
        match status {
            "supported" => {
                if f1.is_empty() || f2.is_empty() {
                    return Err(format!(
                        "Error: malformed supported line from detect-all-pubkeys: id=[{f1}] guid=[{f2}]"
                    ));
                }
                detected.supported.push(SupportedCard {
                    id: f1.to_string(),
                    guid: f2.to_string(),
                });
            }
            "unsupported" => {
                if f1.is_empty() || f2.is_empty() {
                    return Err(format!(
                        "Error: malformed unsupported line from detect-all-pubkeys: guid=[{f1}] reason=[{f2}]"
                    ));
                }
                detected.unsupported.push(UnsupportedCard {
                    guid: f1.to_string(),
                    reason: f2.to_string(),
                });
            }
            other => {
                return Err(format!(
                    "Error: malformed line from piggy-ids detect-all-pubkeys: status=[{other}]"
                ));
            }
        }
    }
    Ok(detected)
}

/// Build the set of markl IDs currently present in a canonical
/// piggy-ids file: skip `#`-prefixed and blank lines, strip a `  #`
/// (TWO ASCII spaces before `#`) inline comment, then trim.
///
/// piggy-ids canonical form (RFC 0003) uses exactly two ASCII spaces
/// between the markl ID and any inline `#` comment. The caller
/// canonicalizes first, so the two-space strip is correct here. Do NOT
/// relax to "one or more spaces" — that would also strip a single space
/// accidentally present in a markl ID's blech32 (impossible by grammar,
/// but the relaxed pattern still risks future drift). markl IDs contain
/// no internal whitespace (RFC 0003), so a plain trim cleans the edges.
fn current_markl_ids(contents: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for line in contents.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let id = match line.find("  #") {
            Some(idx) => &line[..idx],
            None => line,
        };
        let id = id.trim();
        if !id.is_empty() {
            set.insert(id.to_string());
        }
    }
    set
}

/// `${PIGGY_IDS}.tmp.$$` — a sibling temp path. The bash uses the PID;
/// any unique-enough sibling works since the file is always renamed or
/// removed before returning.
fn tmp_sibling(piggy_ids: &Path) -> PathBuf {
    let mut name = piggy_ids
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| OsString::from("piggy-ids"));
    name.push(format!(".tmp.{}", std::process::id()));
    piggy_ids.with_file_name(name)
}

/// `${PIGGY_IDS%/piggy-ids}` — the directory holding the piggy-ids
/// file, used as the reencrypt target and the git-add path.
fn piggy_ids_dir(piggy_ids: &Path) -> &Path {
    piggy_ids.parent().unwrap_or(piggy_ids)
}

/// Run `piggy-ids <args...>` (binary located via `PIGGY_IDS_PATH`, same
/// resolution as `reencrypt.rs`) and return whether it exited 0. Stderr
/// is inherited so the binary's own diagnostics reach the user, exactly
/// as the bash invocation did.
fn piggy_ids_ok(args: &[&str]) -> bool {
    let binary: OsString =
        std::env::var_os("PIGGY_IDS_PATH").unwrap_or_else(|| OsString::from("piggy-ids"));
    matches!(
        Command::new(&binary).args(args).status(),
        Ok(status) if status.success()
    )
}

/// Like [`piggy_ids_ok`] but captures stdout, mirroring the bash
/// `helper_out="$(... detect-all-pubkeys)"` command substitution.
/// Stderr is inherited so the binary's own diagnostics reach the user.
/// Returns `None` when the binary fails to spawn or exits non-zero
/// (the bash `|| die` arm).
pub(crate) fn piggy_ids_output(args: &[&str]) -> Option<String> {
    let binary: OsString =
        std::env::var_os("PIGGY_IDS_PATH").unwrap_or_else(|| OsString::from("piggy-ids"));
    let out = Command::new(&binary)
        .args(args)
        .stderr(std::process::Stdio::inherit())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Read one line from `/dev/tty`, matching the bash `read -r reply
/// </dev/tty`. The trailing newline is stripped; a read failure yields
/// an empty reply (the bash `|| reply=""`).
fn read_tty_line() -> String {
    use std::io::BufRead as _;
    let Ok(tty) = std::fs::File::open("/dev/tty") else {
        return String::new();
    };
    let mut reader = std::io::BufReader::new(tty);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(_) => line.trim_end_matches(['\n', '\r']).to_string(),
        Err(_) => String::new(),
    }
}

/// The shared tail of all three flows: commit the piggy-ids change,
/// re-encrypt the affected subtree, then commit the re-encryption.
/// Mirrors the `set_git "$PIGGY_IDS"; git_add_file … reencrypt_path …
/// git_add_file …` sequence at the bottom of each bash handler. The
/// work tree is resolved once from `$PIGGY_IDS` (matching the single
/// bash `set_git` call) and reused for both commits; the
/// commit-only-if-changed guard lives in `git_ops`.
fn commit_and_reencrypt(
    root: &Path,
    piggy_ids: &Path,
    id_dir: &Path,
    ids_message: &str,
    reencrypt_message: &str,
    verbose: bool,
) -> i32 {
    let work_tree = git_ops::find_inner_git_dir(piggy_ids, root);
    if let Some(work_tree) = &work_tree {
        let _ = git_ops::add_and_commit(work_tree, piggy_ids, ids_message);
    }
    let code = reencrypt::run(id_dir, verbose);
    if let Some(work_tree) = &work_tree {
        let _ = git_ops::add_and_commit(work_tree, id_dir, reencrypt_message);
    }
    code
}

/// Re-encrypt every ebox under `target` to its nearest `piggy-ids`, then
/// commit the resulting ciphertext changes. This is the no-file `recipients
/// sync` path: unlike [`commit_and_reencrypt`] there is no `piggy-ids` edit to
/// commit first — it just refreshes ciphertext against the recipients already
/// on disk.
///
/// The work-tree is resolved as `target` itself rather than via
/// [`git_ops::find_inner_git_dir`] (which walks up from the *parent* and would
/// miss the store-root case): any directory inside the work tree answers
/// `--is-inside-work-tree` true, and `git -C <target> add <target>` stages
/// exactly the walked subtree. The commit-only-if-changed guard in
/// `git_ops::add_and_commit` means a bit-identical re-encrypt (e.g. the base64
/// bats mock) produces no commit.
fn reencrypt_and_commit(target: &Path, verbose: bool) -> i32 {
    let code = reencrypt::run(target, verbose);
    if git_ops::is_inside_work_tree(target) {
        let _ = git_ops::add_and_commit(target, target, "Reencrypt password store.");
    }
    code
}

/// Parse `-p <subfolder>`. Everything else is a usage error — mirrors
/// the bash `case ... *) die "unexpected argument" ;;` arm.
fn parse_subfolder(args: &[String]) -> Result<String, String> {
    let mut subfolder = String::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-p" => match iter.next() {
                Some(v) => subfolder = v.clone(),
                None => return Err("-p requires a subfolder argument".into()),
            },
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(subfolder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subfolder_empty_args() {
        assert_eq!(parse_subfolder(&[]).unwrap(), "");
    }

    #[test]
    fn parse_subfolder_with_p_flag() {
        let v = vec!["-p".to_string(), "work".to_string()];
        assert_eq!(parse_subfolder(&v).unwrap(), "work");
    }

    #[test]
    fn parse_subfolder_p_without_value_errors() {
        let v = vec!["-p".to_string()];
        let err = parse_subfolder(&v).unwrap_err();
        assert!(err.contains("-p"), "got: {err}");
    }

    #[test]
    fn parse_subfolder_unexpected_argument_errors() {
        let v = vec!["bogus".to_string()];
        let err = parse_subfolder(&v).unwrap_err();
        assert!(err.contains("unexpected"), "got: {err}");
    }

    #[test]
    fn parse_subfolder_positional_after_p_errors() {
        let v = vec!["-p".to_string(), "work".to_string(), "extra".to_string()];
        let err = parse_subfolder(&v).unwrap_err();
        assert!(err.contains("unexpected"), "got: {err}");
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_add_collects_ids_and_subfolder() {
        let parsed = parse_add(&strings(&["id1", "-p", "work", "id2"])).unwrap();
        assert_eq!(parsed.subfolder, "work");
        assert!(!parsed.all_attached);
        assert_eq!(parsed.ids, strings(&["id1", "id2"]));
    }

    #[test]
    fn parse_add_yes_is_consumed_and_ignored() {
        let parsed = parse_add(&strings(&["--yes", "id1"])).unwrap();
        assert!(!parsed.all_attached);
        assert_eq!(parsed.ids, strings(&["id1"]));
    }

    #[test]
    fn parse_add_all_attached_sets_flag() {
        let parsed = parse_add(&strings(&["-A"])).unwrap();
        assert!(parsed.all_attached);
        assert!(parsed.ids.is_empty());
        let parsed = parse_add(&strings(&["--all-attached"])).unwrap();
        assert!(parsed.all_attached);
    }

    #[test]
    fn parse_add_all_attached_with_ids_errors() {
        let err = parse_add(&strings(&["-A", "id1"])).unwrap_err();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn parse_add_unknown_flag_errors() {
        let err = parse_add(&strings(&["--bogus"])).unwrap_err();
        assert!(err.contains("unknown flag"), "got: {err}");
    }

    #[test]
    fn parse_add_p_without_value_errors() {
        let err = parse_add(&strings(&["-p"])).unwrap_err();
        assert!(err.contains("-p"), "got: {err}");
    }

    #[test]
    fn parse_remove_treats_dash_prefixed_tokens_as_ids() {
        // Bash's remove loop has no `-*) die` arm, so a `-`-prefixed
        // token that isn't `-p` is collected as an ID verbatim.
        let parsed = parse_subfolder_and_ids(&strings(&["-p", "work", "-weird", "id"]));
        assert_eq!(parsed.subfolder, "work");
        assert_eq!(parsed.ids, strings(&["-weird", "id"]));
    }

    #[test]
    fn parse_sync_requires_single_file() {
        let parsed = parse_sync(&strings(&["a.txt", "-p", "work"])).unwrap();
        assert_eq!(parsed.subfolder, "work");
        assert_eq!(parsed.file.as_deref(), Some("a.txt"));

        let err = parse_sync(&strings(&["a.txt", "b.txt"])).unwrap_err();
        assert!(err.contains("only one"), "got: {err}");
    }

    #[test]
    fn parse_sync_accepts_no_file() {
        // No positional → the no-file re-encrypt form: file is None, and any
        // `-p` is still captured to scope the walk.
        let bare = parse_sync(&[]).unwrap();
        assert!(bare.file.is_none());
        assert_eq!(bare.subfolder, "");

        let scoped = parse_sync(&strings(&["-p", "work"])).unwrap();
        assert!(scoped.file.is_none());
        assert_eq!(scoped.subfolder, "work");
    }

    #[test]
    fn filter_out_recipients_drops_matching_ids() {
        let contents = "# header\nID_A  # primary\nID_B\n\nID_C  # backup\n";
        let filtered = filter_out_recipients(contents, &strings(&["ID_B"]));
        assert_eq!(filtered, "# header\nID_A  # primary\n\nID_C  # backup\n");
    }

    #[test]
    fn filter_out_recipients_strips_comment_and_whitespace_before_match() {
        // The on-disk form is canonical (two-space-then-#), but the awk
        // strips a whitespace-preceded comment plus surrounding ws, so
        // verify a match against the bare ID still fires.
        let contents = "ID_A  # a comment with spaces\n";
        let filtered = filter_out_recipients(contents, &strings(&["ID_A"]));
        assert_eq!(filtered, "");
    }

    #[test]
    fn filter_out_recipients_no_match_is_identity() {
        let contents = "# header\nID_A\nID_B\n";
        let filtered = filter_out_recipients(contents, &strings(&["ID_Z"]));
        assert_eq!(filtered, contents);
    }

    #[test]
    fn filter_out_recipients_ignores_empty_targets() {
        // The awk BEGIN block skips empty target entries; an empty
        // string must never match a (non-empty) recipient line.
        let contents = "ID_A\n";
        let filtered = filter_out_recipients(contents, &strings(&["", "ID_Z"]));
        assert_eq!(filtered, contents);
    }

    #[test]
    fn find_comment_start_requires_preceding_whitespace() {
        // `#` not preceded by whitespace is part of the token, not a
        // comment delimiter (mirrors awk `[[:space:]]+#`).
        assert_eq!(find_comment_start("id#notacomment"), None);
        assert_eq!(recipient_id_of_line("id#notacomment"), "id#notacomment");
        assert!(find_comment_start("id  # comment").is_some());
        assert_eq!(recipient_id_of_line("id  # comment"), "id");
    }

    #[test]
    fn tmp_sibling_is_in_same_dir() {
        let tmp = tmp_sibling(Path::new("/store/work/piggy-ids"));
        assert_eq!(tmp.parent(), Some(Path::new("/store/work")));
        assert!(
            tmp.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("piggy-ids.tmp.")),
            "unexpected tmp name: {:?}",
            tmp.file_name()
        );
    }

    #[test]
    fn piggy_ids_dir_is_parent() {
        assert_eq!(
            piggy_ids_dir(Path::new("/store/work/piggy-ids")),
            Path::new("/store/work")
        );
    }

    #[test]
    fn parse_add_yes_sets_assume_yes_on_all_attached() {
        let parsed = parse_add(&strings(&["-A", "--yes"])).unwrap();
        assert!(parsed.all_attached);
        assert!(parsed.assume_yes);
    }

    #[test]
    fn parse_detect_supported_and_unsupported() {
        let out = "supported\tID_A\tGUID1\nunsupported\tGUID2\tslot 9D is Rsa2048\n";
        let detected = parse_detect_all_pubkeys(out).unwrap();
        assert_eq!(
            detected.supported,
            vec![SupportedCard {
                id: "ID_A".into(),
                guid: "GUID1".into()
            }]
        );
        assert_eq!(
            detected.unsupported,
            vec![UnsupportedCard {
                guid: "GUID2".into(),
                reason: "slot 9D is Rsa2048".into()
            }]
        );
    }

    #[test]
    fn parse_detect_skips_blank_lines() {
        let out = "\nsupported\tID_A\tGUID1\n\n";
        let detected = parse_detect_all_pubkeys(out).unwrap();
        assert_eq!(detected.supported.len(), 1);
        assert!(detected.unsupported.is_empty());
    }

    #[test]
    fn parse_detect_empty_output_is_empty() {
        let detected = parse_detect_all_pubkeys("").unwrap();
        assert_eq!(detected, DetectedCards::default());
    }

    #[test]
    fn parse_detect_reason_keeps_embedded_whitespace() {
        // Only the first two tabs split fields; the reason column keeps
        // any internal spaces or tabs verbatim (splitn(3)).
        let out = "unsupported\tGUID2\tslot 9D unreadable: bad\tapdu\n";
        let detected = parse_detect_all_pubkeys(out).unwrap();
        assert_eq!(
            detected.unsupported[0].reason,
            "slot 9D unreadable: bad\tapdu"
        );
    }

    #[test]
    fn parse_detect_malformed_supported_errors() {
        let err = parse_detect_all_pubkeys("supported\tID_A\t").unwrap_err();
        assert!(err.contains("malformed supported line"), "got: {err}");
        let err = parse_detect_all_pubkeys("supported\t\tGUID1").unwrap_err();
        assert!(err.contains("malformed supported line"), "got: {err}");
    }

    #[test]
    fn parse_detect_malformed_unsupported_errors() {
        let err = parse_detect_all_pubkeys("unsupported\tGUID2\t").unwrap_err();
        assert!(err.contains("malformed unsupported line"), "got: {err}");
    }

    #[test]
    fn parse_detect_unknown_status_errors() {
        let err = parse_detect_all_pubkeys("bogus\tx\ty").unwrap_err();
        assert!(err.contains("status=[bogus]"), "got: {err}");
    }

    #[test]
    fn current_markl_ids_collects_bare_and_commented() {
        let contents = "# header\nID_A\nID_B  # primary card\n\n";
        let set = current_markl_ids(contents);
        assert!(set.contains("ID_A"));
        assert!(set.contains("ID_B"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn current_markl_ids_two_space_strip_only() {
        // A single space before `#` is NOT a comment delimiter in the
        // canonical form; the whole `ID #x` would be the token (and trim
        // leaves it intact). Two spaces strip the comment.
        let one_space = current_markl_ids("ID_A #c\n");
        assert!(one_space.contains("ID_A #c"));
        let two_space = current_markl_ids("ID_A  #c\n");
        assert!(two_space.contains("ID_A"));
        assert!(!two_space.contains("ID_A  #c"));
    }
}
