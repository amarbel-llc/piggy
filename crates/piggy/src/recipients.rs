//! `piggy pass recipients` — partial Rust port.
//!
//! Currently in Rust: `list`, `add` (explicit recipients only),
//! `remove`, `sync`. `list-available` is dispatched directly through
//! `fallback::exec_piggy_ids` from main.rs (no module wiring needed).
//! `add --all-attached` (the `-A` interactive card-detection path) is
//! still in bash (#96 step 6); the Rust `add` handler defers to the
//! bash path when it sees `-A`/`--all-attached`.
//!
//! `list` mirrors `cmd_pass_recipients_list` in `src/piggy.sh`; `add`,
//! `remove`, and `sync` mirror `cmd_pass_recipients_{add,remove,sync}`.
//! The canonicalize/validate/diff steps shell to the `piggy-ids`
//! binary (located via `PIGGY_IDS_PATH`, same as `reencrypt.rs`) so the
//! bats mock — which intercepts `encrypt` but delegates those three to
//! the real binary — exercises the same logic the bash original did.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git_ops;
use crate::reencrypt;
use crate::store::{find_piggy_ids, store_root};

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
/// `-A`/`--all-attached` interactive card-detection path is NOT ported
/// here (#96 step 6); when either flag appears we defer to the bash
/// handler with the original argv via `fallback::exec_bash_subcmds`
/// (which never returns).
pub fn add(args: &[String]) -> i32 {
    let parsed = match parse_add(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if parsed.all_attached {
        // Card detection stays in bash for now. Re-feed the original
        // argv so getopt sees exactly what the user typed.
        crate::fallback::exec_bash_subcmds("recipients", "add", args);
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
    );
    0
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
    );
    0
}

/// `piggy pass recipients sync <file> [-p subfolder]`.
///
/// Mirrors `cmd_pass_recipients_sync` in `src/piggy.sh`: validate the
/// declared file, no-op when it already matches the live recipients
/// (the `diff` idempotency check), otherwise copy it over the live file,
/// canonicalise in place, and commit + reencrypt.
pub fn sync(args: &[String]) -> i32 {
    let parsed = match parse_sync(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };
    let Some(file) = parsed.file else {
        eprintln!("Usage: piggy pass recipients sync <file> [-p subfolder]");
        return 1;
    };
    if !Path::new(&file).is_file() {
        eprintln!("Error: file not found: {file}");
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
    );
    0
}

#[derive(Debug)]
struct AddArgs {
    subfolder: String,
    all_attached: bool,
    ids: Vec<String>,
}

/// Parse the `add` argv: `-p <subfolder>`, `-A`/`--all-attached`,
/// `--yes`, and positional markl IDs. `--yes` is consumed but ignored
/// (it only affects the deferred `-A` path; we re-feed the original
/// argv to bash there). An unknown `-flag` is a usage error, matching
/// the bash `-*) die` arm.
fn parse_add(args: &[String]) -> Result<AddArgs, String> {
    let mut subfolder = String::new();
    let mut all_attached = false;
    let mut ids = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-p" => match iter.next() {
                Some(v) => subfolder = v.clone(),
                None => return Err("Error: -p requires a subfolder argument".into()),
            },
            "-A" | "--all-attached" => all_attached = true,
            "--yes" => {}
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
}

/// Parse the `sync` argv: `-p <subfolder>` plus exactly one positional
/// `<file>`. A second positional is a usage error, matching the bash
/// `[[ -z $file ]] || die` guard.
fn parse_sync(args: &[String]) -> Result<SyncArgs, String> {
    let mut subfolder = String::new();
    let mut file: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-p" {
            if let Some(v) = iter.next() {
                subfolder = v.clone();
            }
        } else if file.is_some() {
            return Err("Error: only one <file> argument permitted.".into());
        } else {
            file = Some(arg.clone());
        }
    }
    Ok(SyncArgs { subfolder, file })
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
) {
    let work_tree = git_ops::find_inner_git_dir(piggy_ids, root);
    if let Some(work_tree) = &work_tree {
        let _ = git_ops::add_and_commit(work_tree, piggy_ids, ids_message);
    }
    reencrypt::run(id_dir);
    if let Some(work_tree) = &work_tree {
        let _ = git_ops::add_and_commit(work_tree, id_dir, reencrypt_message);
    }
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
}
