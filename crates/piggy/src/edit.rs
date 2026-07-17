//! `piggy pass edit pass-name` — native Rust port of `cmd_edit` in
//! `src/piggy.sh` (Split B of piggy#96).
//!
//! The shape:
//!
//! 1. Sneaky-path check; mkdir -p the dirname; find piggy-ids;
//!    locate inner git work tree.
//! 2. Allocate a `SecureTmpdir` (RAII; `/dev/shm` ramdisk preferred,
//!    `${TMPDIR:-/tmp}` fallback with shred-on-drop).
//! 3. Build `tmp_file = $SECURE_TMPDIR/XXXXXX-${path//\//-}.txt`.
//!    Slashes in the pass-name become dashes so the tempfile name is
//!    a single filesystem entry (matches bash).
//! 4. If `$passfile` exists: decrypt into `$tmp_file` and set action
//!    = "Edit"; otherwise leave `$tmp_file` empty and set action = "Add".
//! 5. Spawn `${EDITOR:-vi} $tmp_file`. The bash ignores the editor's
//!    exit code (any exit, even non-zero, is followed by the
//!    file-exists check); we mirror.
//! 6. Bail if `$tmp_file` is gone (user deleted-and-exited).
//! 7. Bail with `Password unchanged.` if the decrypted-prior plaintext
//!    diffs identical to the new tempfile contents. For a fresh entry
//!    the prior decrypt is silently allowed to fail (stderr suppressed,
//!    output empty) and any non-empty new contents pass.
//! 8. Encrypt loop: try `piggy_encrypt $passfile`; on failure prompt
//!    `Encryption failed. Would you like to try again? [y/N]` and
//!    retry. The bash `yesno` returns 0 (i.e. continue) on non-TTY
//!    stdin; we mirror via `crate::confirm`.
//! 9. `git_add_file "$passfile" "${action} password for $path using
//!    ${EDITOR:-vi}."`.
//!
//! The `SecureTmpdir` guard is held in a local; it drops at function
//! exit (success and every error path) which is the RAII analogue of
//! the bash `trap remove_tmpfile EXIT` / `trap shred_tmpfile EXIT`
//! cleanup.

use std::io::{IsTerminal as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::crypt;
use crate::git_ops;
use crate::platform::tmpdir::SecureTmpdir;
use crate::store::{find_piggy_ids, store_root};

/// Exit code conventions:
/// - 0: edit succeeded (or "Password unchanged." short-circuit)
/// - 1: usage / sneaky-path / encrypt-retry-declined / IO failure
pub fn run(args: &[String]) -> i32 {
    let path = match parse_args(args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if let Some(reason) = sneaky_path_reason(&path) {
        eprintln!("Error: You've attempted to pass a sneaky path to piggy ({reason}). Go home.");
        return 1;
    }

    let root = store_root();
    let passfile = root.join(format!("{path}.ebox"));
    let parent = passfile.parent().unwrap_or(&root);
    if let Err(err) = std::fs::create_dir_all(parent) {
        eprintln!("piggy pass edit: create {}: {}", parent.display(), err);
        return 1;
    }

    let subfolder = path_parent_for_search(&path);
    let piggy_ids = match find_piggy_ids(&root, &subfolder)
        .and_then(|p| crate::pigpen_pointer::resolve_piggy_ids_path(&p))
    {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return 1;
        }
    };

    // Allocate the secure tmpdir. Held until function exit; Drop
    // shreds + removes the directory (disk fallback) or rm -rf's the
    // ramdisk path.
    let tmp = match SecureTmpdir::new(true) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("piggy pass edit: allocate secure tmpdir: {err}");
            return 1;
        }
    };
    let tmp_file = tmp.path().join(make_tmp_file_name(&path));

    let action = if passfile.is_file() {
        // The bash redirects stderr to /dev/null for the equivalence
        // check (line 308) but NOT for the priming decrypt (line
        // 303). The priming decrypt write-redirects stdout to
        // $tmp_file; stderr passes through. Mirror.
        match crypt::decrypt(&passfile) {
            Ok(bytes) => {
                if let Err(err) = std::fs::write(&tmp_file, &bytes) {
                    eprintln!("piggy pass edit: write {}: {}", tmp_file.display(), err);
                    return 1;
                }
                // Ensure 0600 — the SecureTmpdir is 0700 so the file
                // is already private, but match the umask 077 posture
                // explicitly. Best-effort; ignore errors.
                let _ = std::fs::set_permissions(&tmp_file, std::fs::Permissions::from_mode(0o600));
            }
            Err(err) => {
                eprintln!("piggy pass edit: {err}");
                return 1;
            }
        }
        "Edit"
    } else {
        "Add"
    };

    let editor = editor_command();
    let editor_status = Command::new(&editor).arg(&tmp_file).status();
    // The bash does not check `$?` from the editor; any exit
    // (zero or non-zero) proceeds to the file-existence check.
    // We deliberately discard the status here.
    drop(editor_status);

    if !tmp_file.is_file() {
        eprintln!("New password not saved.");
        return 1;
    }

    if is_unchanged(&passfile, &tmp_file) {
        eprintln!("Password unchanged.");
        return 1;
    }

    // Encrypt-retry loop. On encrypt failure, the bash `yesno`
    // (line 310) prompts `Encryption failed. Would you like to try
    // again? [y/N]` and re-encrypts on `y`. We mirror via
    // `confirm`. If the user declines, bash `yesno` calls `exit 1`;
    // we return 1.
    loop {
        let tmp_input = match std::fs::File::open(&tmp_file) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("piggy pass edit: open {}: {}", tmp_file.display(), err);
                return 1;
            }
        };
        match crypt::encrypt(&piggy_ids, &passfile, tmp_input) {
            Ok(()) => break,
            Err(err) => {
                eprintln!("piggy pass edit: {err}");
                if !confirm("Encryption failed. Would you like to try again?") {
                    return 1;
                }
            }
        }
    }

    if let Some(work_tree) = git_ops::find_inner_git_dir(&passfile, &root) {
        let _ = git_ops::add_and_commit(
            &work_tree,
            &passfile,
            &format!("{action} password for {path} using {editor}."),
        );
    }

    0
}

fn parse_args(args: &[String]) -> Result<String, String> {
    let mut positional: Vec<String> = Vec::new();
    let mut iter = args.iter();
    let usage = "Usage: piggy pass edit pass-name";
    while let Some(arg) = iter.next() {
        if arg == "--" {
            for rest in iter.by_ref() {
                positional.push(rest.clone());
            }
            break;
        }
        if arg.starts_with('-') {
            return Err(usage.into());
        }
        positional.push(arg.clone());
    }
    if positional.len() != 1 {
        return Err(usage.into());
    }
    Ok(positional[0].trim_end_matches('/').to_string())
}

/// `${EDITOR:-vi}` from the bash. Used both for spawning and for the
/// commit message.
fn editor_command() -> String {
    std::env::var("EDITOR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "vi".to_string())
}

/// Build the tempfile basename from a pass-name. The bash form is
/// `$(mktemp -u "$SECURE_TMPDIR/XXXXXX")-${path//\//-}.txt` —
/// six random alnum chars + dash + slashes-to-dashes pass-name +
/// `.txt`. We pick the random prefix here to avoid an mktemp(1) hop.
fn make_tmp_file_name(path: &str) -> String {
    let suffix = path.replace('/', "-");
    let prefix = random_alphanumeric(6);
    format!("{prefix}-{suffix}.txt")
}

/// Six-char random alphanumeric — same length as bash's `XXXXXX`
/// template. Deterministic-seedy enough for tempfile uniqueness; we
/// do NOT need cryptographic strength here (the directory is 0700
/// inside `/dev/shm` or a 0700 disk-backed dir).
fn random_alphanumeric(n: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(std::process::id() as u64);
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let idx = (seed as usize) % ALPHABET.len();
        s.push(ALPHABET[idx] as char);
    }
    s
}

/// `dirname -- "$path"` projected into the empty-string convention
/// `find_piggy_ids` expects for "walk from the store root".
fn path_parent_for_search(path: &str) -> String {
    let p = PathBuf::from(path);
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

fn sneaky_path_reason(path: &str) -> Option<&'static str> {
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Some("`..` component");
        }
    }
    None
}

/// Bash:
/// ```text
/// piggy_decrypt "$passfile" 2>/dev/null \
///   | diff - "$tmp_file" &>/dev/null \
///   && die "Password unchanged."
/// ```
///
/// Notes:
/// - When `$passfile` does not exist the bash chain fails (decrypt
///   errors → diff sees empty stdin → diff with non-empty $tmp_file
///   returns 1 → no `die`). Mirror by treating a decrypt failure or
///   missing passfile as "definitely changed".
/// - The `2>/dev/null` on the decrypt swallows pivy-box errors; we
///   simulate by suppressing the stderr inherit and only acting on
///   the byte comparison.
fn is_unchanged(passfile: &Path, tmp_file: &Path) -> bool {
    if !passfile.is_file() {
        return false;
    }
    let prior = match crypt::decrypt(passfile) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let new = match std::fs::read(tmp_file) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    prior == new
}

/// Bash `yesno` on a non-TTY stdin returns 0 (i.e. "proceed") without
/// prompting. We mirror.
fn confirm(message: &str) -> bool {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return true;
    }
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{message} [y/N] ");
    let _ = stderr.flush();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(_) => {
            let trimmed = line.trim();
            trimmed == "y" || trimmed == "Y"
        }
        Err(_) => false,
    }
}

// Pulled into scope so `read_line` resolves on the locked stdin
// handle returned by `stdin.lock()` above.
use std::io::BufRead as _;

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_args_requires_one_positional() {
        assert!(parse_args(&s(&[])).is_err());
        assert_eq!(parse_args(&s(&["cred1"])).unwrap(), "cred1");
        assert!(parse_args(&s(&["a", "b"])).is_err());
    }

    #[test]
    fn parse_args_rejects_flags() {
        assert!(parse_args(&s(&["-f", "cred1"])).is_err());
    }

    #[test]
    fn parse_args_trims_trailing_slash() {
        assert_eq!(parse_args(&s(&["folder/sub/"])).unwrap(), "folder/sub");
    }

    #[test]
    fn parse_args_double_dash_terminator_accepts_positional() {
        assert_eq!(parse_args(&s(&["--", "cred1"])).unwrap(), "cred1");
    }

    #[test]
    fn make_tmp_file_name_converts_slashes_to_dashes() {
        let name = make_tmp_file_name("folder/subfolder/cred1");
        assert!(name.ends_with("-folder-subfolder-cred1.txt"), "got: {name}");
    }

    #[test]
    fn make_tmp_file_name_has_six_char_random_prefix() {
        let name = make_tmp_file_name("x");
        // The shape is `<prefix>-<x>.txt`; split on the first `-` and
        // confirm the prefix is six alnum chars.
        let (prefix, rest) = name.split_once('-').unwrap();
        assert_eq!(prefix.len(), 6);
        assert!(prefix.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(rest, "x.txt");
    }

    #[test]
    fn make_tmp_file_name_preserves_top_level_name() {
        let name = make_tmp_file_name("cred1");
        assert!(name.ends_with("-cred1.txt"), "got: {name}");
    }

    #[test]
    fn make_tmp_file_lives_under_secure_tmpdir() {
        // Cross-check the join shape used by run() — we want
        // SECURE_TMPDIR/<name>, not the bash's literal sibling form.
        let secure = std::path::PathBuf::from("/tmp/secure");
        let name = make_tmp_file_name("folder/cred1");
        let joined = secure.join(&name);
        assert_eq!(joined.parent(), Some(secure.as_path()));
        assert!(name.contains("-folder-cred1.txt"));
    }

    #[test]
    fn path_parent_for_search_strips_basename() {
        assert_eq!(path_parent_for_search("a/b/c"), "a/b");
    }

    #[test]
    fn path_parent_for_search_returns_empty_for_top_level() {
        assert_eq!(path_parent_for_search("cred1"), "");
    }

    #[test]
    fn sneaky_path_rejects_parent_component() {
        assert!(sneaky_path_reason("../etc").is_some());
        assert!(sneaky_path_reason("a/../b").is_some());
    }

    #[test]
    fn sneaky_path_accepts_normal() {
        assert!(sneaky_path_reason("a/b").is_none());
        assert!(sneaky_path_reason("foo..bar").is_none());
    }

    #[test]
    fn is_unchanged_returns_false_when_passfile_missing() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "piggy-edit-test-{}-{}",
            std::process::id(),
            random_alphanumeric(8)
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let passfile = tmp_dir.join("missing.ebox");
        let tmp_file = tmp_dir.join("new.txt");
        std::fs::write(&tmp_file, b"new content").unwrap();
        assert!(!is_unchanged(&passfile, &tmp_file));
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
