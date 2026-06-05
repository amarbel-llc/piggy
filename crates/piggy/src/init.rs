//! `piggy pass init [-p subfolder] [-k <markl-id> | -g <guid>]` —
//! native Rust port of `cmd_init` in `src/piggy.sh`.
//!
//! Writes a piggy-owned `piggy-ids` text file (RFC 0003) carrying the
//! `piggy-recipient-v1` purpose for a markl ID of format
//! `pivy_ecdh_p256_pub`. Modes:
//!
//! - `-k <markl-id>` — declarative; user supplies the recipient.
//! - no `-k` — auto-detect; shells to `piggy-ids detect-pubkey` to read
//!   slot 9D of the attached PIV card. `-g <guid>` is forwarded as
//!   `--guid` for multi-card setups.
//!
//! `-k` and `-g` are mutually exclusive (the bash dies; we mirror).
//!
//! After staging the markl ID in a tempfile (`${piggy_ids}.tmp.$$`) and
//! atomic-renaming into place, the writer commits the new piggy-ids,
//! invokes `reencrypt::run` over the target directory (no-op on fresh
//! init; re-encrypts existing entries on re-init), and commits the
//! re-encryption.
//!
//! The `-k` markl-ID prefix check (`pivy_ecdh_p256_pub-` or
//! `piggy-recipient-v1@pivy_ecdh_p256_pub-`) is preserved verbatim
//! from the bash. Broadening it for age markl IDs is tracked by #99
//! and explicitly out of scope here.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::git_ops;
use crate::recipients::piggy_ids_output;
use crate::reencrypt;
use crate::store::store_root;

/// Exit code conventions:
/// - 0: init succeeded
/// - 1: usage / sneaky-path / detect-pubkey / format / IO failure
pub fn run(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if !opts.key.is_empty() && !opts.guid.is_empty() {
        eprintln!("Error: -k and -g are mutually exclusive (-g only applies to auto-detect).");
        return 1;
    }

    if !opts.id_path.is_empty() {
        if let Some(reason) = sneaky_path_reason(&opts.id_path) {
            eprintln!(
                "Error: You've attempted to pass a sneaky path to piggy ({reason}). Go home."
            );
            return 1;
        }
    }

    let root = store_root();
    let tpl_dir = if opts.id_path.is_empty() {
        root.clone()
    } else {
        root.join(&opts.id_path)
    };

    // Reject a non-directory at the target path; mirrors the bash
    // `[[ -n $id_path && ! -d $PREFIX/$id_path && -e $PREFIX/$id_path ]]`
    // guard. The `id_path.is_empty()` short-circuit matches the bash
    // (the check only runs when `-p` was supplied).
    if !opts.id_path.is_empty() && tpl_dir.exists() && !tpl_dir.is_dir() {
        eprintln!(
            "Error: {} exists but is not a directory.",
            tpl_dir.display()
        );
        return 1;
    }

    let piggy_ids = tpl_dir.join("piggy-ids");

    // Resolve the inner git work tree before mkdir, mirroring the bash
    // `set_git "$piggy_ids"`. The find_inner_git_dir walks up from the
    // piggy-ids path's parent, so it works regardless of whether the
    // directory exists yet (parent may climb above the missing tpl_dir
    // before hitting an existing work tree).
    if let Err(err) = mkdir_p_verbose(&tpl_dir) {
        eprintln!("Error: failed to create {}: {err}", tpl_dir.display());
        return 1;
    }

    let mut key = opts.key.clone();
    if key.is_empty() {
        // Auto-detect path: shell to `piggy-ids detect-pubkey
        // [--guid <guid>]`. Captures stdout; bash's `|| die` is
        // mirrored by `piggy_ids_output` returning `None`.
        let mut detect_args: Vec<&str> = vec!["detect-pubkey"];
        if !opts.guid.is_empty() {
            detect_args.push("--guid");
            detect_args.push(&opts.guid);
        }
        match piggy_ids_output(&detect_args) {
            Some(out) => key = out.trim_end_matches(['\n', '\r']).to_string(),
            None => {
                eprintln!(
                    "Error: piggy-ids detect-pubkey failed; pass -k <markl-id> if no PIV card is attached."
                );
                return 1;
            }
        }
    }

    // Validate the markl-ID has the piggy 2.x recipient shape. This
    // prefix check is load-bearing: broadening it to accept age markl
    // IDs is tracked by piggy#99 and explicitly out of scope here.
    if !is_piggy_recipient_markl_id(&key) {
        let prefix = key.split('-').next().unwrap_or(&key);
        eprintln!(
            "Error: -k value must be a markl ID with format=pivy_ecdh_p256_pub (got: {prefix}...)."
        );
        return 1;
    }

    // Atomic write: build a tempfile and rename over the live file.
    let tmp = tmp_sibling(&piggy_ids);
    if let Err(err) = write_piggy_ids(&tmp, &key) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("Error: failed to write {}: {err}", piggy_ids.display());
        return 1;
    }
    if let Err(err) = std::fs::rename(&tmp, &piggy_ids) {
        let _ = std::fs::remove_file(&tmp);
        eprintln!(
            "Error: failed to write {}: rename: {err}",
            piggy_ids.display()
        );
        return 1;
    }

    let suffix = if opts.id_path.is_empty() {
        String::new()
    } else {
        format!(" ({})", opts.id_path)
    };
    println!("Password store initialized{suffix}");

    let work_tree = git_ops::find_inner_git_dir(&piggy_ids, &root);
    if let Some(work_tree) = &work_tree {
        let _ = git_ops::add_and_commit(
            work_tree,
            &piggy_ids,
            &format!("Set piggy recipients{suffix}."),
        );
    }

    // Re-encrypt emits a TAP-14 stream; a fresh store has no eboxes so
    // this is normally a `1..0` no-op. Surface a non-zero walk result as
    // the init exit code while still committing whatever succeeded.
    let reencrypt_code = reencrypt::run(&tpl_dir, false);

    if let Some(work_tree) = &work_tree {
        let _ = git_ops::add_and_commit(
            work_tree,
            &tpl_dir,
            &format!("Reencrypt password store using new piggy recipients{suffix}."),
        );
    }

    reencrypt_code
}

#[derive(Debug)]
struct InitOpts {
    id_path: String,
    key: String,
    guid: String,
}

/// Parse the `init` argv: `-p|--path <subfolder>`, `-k|--key <markl-id>`,
/// `-g|--guid <guid>`. Mirrors the bash `getopt -o p:k:g: -l
/// path:,key:,guid:` block. Any other token is a usage error (the bash
/// getopt rejects it with `Usage: …`).
fn parse_args(args: &[String]) -> Result<InitOpts, String> {
    let mut id_path = String::new();
    let mut key = String::new();
    let mut guid = String::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-p" | "--path" => match iter.next() {
                Some(v) => id_path = v.clone(),
                None => return Err(usage_error()),
            },
            "-k" | "--key" => match iter.next() {
                Some(v) => key = v.clone(),
                None => return Err(usage_error()),
            },
            "-g" | "--guid" => match iter.next() {
                Some(v) => guid = v.clone(),
                None => return Err(usage_error()),
            },
            "--" => break,
            _ => return Err(usage_error()),
        }
    }
    Ok(InitOpts { id_path, key, guid })
}

fn usage_error() -> String {
    "Usage: piggy pass init [-p subfolder] [-k <markl-id> | -g <guid>]".to_string()
}

/// Reject `..` as a path component, mirroring bash `check_sneaky_paths`.
/// A bare-substring `..` (e.g. `a..b`) is not rejected.
fn sneaky_path_reason(path: &str) -> Option<&'static str> {
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Some("`..` component");
        }
    }
    None
}

/// True iff `key` starts with one of the two accepted markl-ID prefixes.
/// See piggy#99 — broadening this to accept age markl IDs is tracked
/// separately and intentionally out of scope here.
fn is_piggy_recipient_markl_id(key: &str) -> bool {
    key.starts_with("pivy_ecdh_p256_pub-")
        || key.starts_with("piggy-recipient-v1@pivy_ecdh_p256_pub-")
}

/// `mkdir -p -v <dir>` — create `dir` and any missing parents, then
/// print one `mkdir: created directory '<dir>'` line per *new* directory.
/// Existing directories are silent (matches GNU coreutils `mkdir -v`).
fn mkdir_p_verbose(dir: &Path) -> std::io::Result<()> {
    let mut to_create: Vec<PathBuf> = Vec::new();
    let mut current = dir.to_path_buf();
    loop {
        if current.exists() {
            break;
        }
        to_create.push(current.clone());
        match current.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => current = parent.to_path_buf(),
            _ => break,
        }
    }
    std::fs::create_dir_all(dir)?;
    for created in to_create.iter().rev() {
        println!("mkdir: created directory '{}'", created.display());
    }
    Ok(())
}

/// `${piggy_ids}.tmp.$$` — sibling temp path that the live file is
/// renamed over (or deleted from on failure).
fn tmp_sibling(piggy_ids: &Path) -> PathBuf {
    let mut name = piggy_ids
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_else(|| std::ffi::OsString::from("piggy-ids"));
    name.push(format!(".tmp.{}", std::process::id()));
    piggy_ids.with_file_name(name)
}

/// Write the three lines of a fresh piggy-ids file. Header text is
/// EXACT — these two `#` lines are part of the RFC 0003 template
/// emitted by `cmd_init`; bats `t0002` asserts on them indirectly via
/// the recipient-line round-trip.
fn write_piggy_ids(path: &Path, key: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    writeln!(file, "# piggy-ids — piggy 2.x recipient template")?;
    writeln!(
        file,
        "# format: piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # optional comment"
    )?;
    writeln!(file, "{key}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_empty() {
        let o = parse_args(&[]).unwrap();
        assert!(o.id_path.is_empty());
        assert!(o.key.is_empty());
        assert!(o.guid.is_empty());
    }

    #[test]
    fn parse_args_short_flags() {
        let o = parse_args(&strings(&[
            "-p",
            "team-a",
            "-k",
            "pivy_ecdh_p256_pub-xxx",
            "-g",
            "GUIDHEX",
        ]))
        .unwrap();
        assert_eq!(o.id_path, "team-a");
        assert_eq!(o.key, "pivy_ecdh_p256_pub-xxx");
        assert_eq!(o.guid, "GUIDHEX");
    }

    #[test]
    fn parse_args_long_flags() {
        let o = parse_args(&strings(&[
            "--path",
            "team-a",
            "--key",
            "pivy_ecdh_p256_pub-xxx",
            "--guid",
            "GUIDHEX",
        ]))
        .unwrap();
        assert_eq!(o.id_path, "team-a");
        assert_eq!(o.key, "pivy_ecdh_p256_pub-xxx");
        assert_eq!(o.guid, "GUIDHEX");
    }

    #[test]
    fn parse_args_flag_without_value_errors() {
        assert!(parse_args(&strings(&["-p"])).is_err());
        assert!(parse_args(&strings(&["-k"])).is_err());
        assert!(parse_args(&strings(&["-g"])).is_err());
    }

    #[test]
    fn parse_args_unknown_token_errors() {
        let err = parse_args(&strings(&["bogus"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
        let err = parse_args(&strings(&["--unknown"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn parse_args_dashdash_terminates() {
        // Bash's getopt eats `--` and stops; we mirror by breaking
        // without scanning trailing tokens. No positionals are
        // expected, so trailing tokens are ignored.
        let o = parse_args(&strings(&["-k", "pivy_ecdh_p256_pub-x", "--"])).unwrap();
        assert_eq!(o.key, "pivy_ecdh_p256_pub-x");
    }

    #[test]
    fn sneaky_path_rejects_parent_dir() {
        assert!(sneaky_path_reason("../etc").is_some());
        assert!(sneaky_path_reason("a/../b").is_some());
        assert!(sneaky_path_reason("..").is_some());
    }

    #[test]
    fn sneaky_path_accepts_double_dot_inside_name() {
        assert!(sneaky_path_reason("a..b").is_none());
        assert!(sneaky_path_reason("team-a").is_none());
        assert!(sneaky_path_reason("foo/bar").is_none());
    }

    #[test]
    fn markl_id_accepts_bare_form() {
        assert!(is_piggy_recipient_markl_id(
            "pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
        ));
    }

    #[test]
    fn markl_id_accepts_purpose_tagged_form() {
        assert!(is_piggy_recipient_markl_id(
            "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
        ));
    }

    #[test]
    fn markl_id_rejects_wrong_format() {
        // sha256-* and age_x25519_pub-* are the two known
        // not-yet-accepted neighbors; #99 will broaden.
        assert!(!is_piggy_recipient_markl_id(
            "sha256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s7lcgm6"
        ));
        assert!(!is_piggy_recipient_markl_id(
            "age_x25519_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
        ));
        assert!(!is_piggy_recipient_markl_id(""));
        assert!(!is_piggy_recipient_markl_id("bogus"));
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
    fn write_piggy_ids_produces_three_lines() {
        let tmp = std::env::temp_dir().join(format!(
            "piggy-init-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        ));
        write_piggy_ids(&tmp, "RECIPIENT_X").unwrap();
        let contents = std::fs::read_to_string(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "# piggy-ids — piggy 2.x recipient template");
        assert_eq!(
            lines[1],
            "# format: piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # optional comment"
        );
        assert_eq!(lines[2], "RECIPIENT_X");
    }

    #[test]
    fn mkdir_p_verbose_existing_is_silent_and_ok() {
        // Existing directory: returns Ok without error or panic.
        let tmp = std::env::temp_dir();
        mkdir_p_verbose(&tmp).unwrap();
    }

    #[test]
    fn mkdir_p_verbose_creates_nested() {
        let base = std::env::temp_dir().join(format!(
            "piggy-init-mkdir-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
        ));
        let nested = base.join("a/b/c");
        let _ = std::fs::remove_dir_all(&base);
        mkdir_p_verbose(&nested).unwrap();
        assert!(nested.is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }
}
