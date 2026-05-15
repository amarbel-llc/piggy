//! `piggy pass grep [GREPOPTIONS] search-string` — walk the store,
//! decrypt every entry, and run `grep --color=always <args>` over
//! each plaintext. Print a colored `dir/name:` header before each
//! match block.
//!
//! Mirrors `cmd_grep` in `src/piggy.sh:438`. The decrypt is via the
//! same `pivy-box stream decrypt` pipeline used elsewhere; failing
//! decrypts and grep-no-match are both swallowed silently — only
//! actual matches produce output.

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::store::{collect_eboxes, store_root};

const HEADER_BLUE_BOLD_RESET: &str = "\x1b[94m"; // blue
const HEADER_BOLD: &str = "\x1b[1m"; // bold
const ANSI_RESET: &str = "\x1b[0m";

/// Exit code conventions:
/// - 0: command ran (regardless of whether there were matches)
/// - 1: usage error
/// - 2: IO error walking the store
pub fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("Usage: piggy pass grep [GREPOPTIONS] search-string");
        return 1;
    }

    let root = store_root();
    if !root.exists() {
        return 0;
    }

    let entries = match collect_eboxes(&root) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("piggy pass grep: walk {}: {}", root.display(), err);
            return 2;
        }
    };

    let mut stdout = std::io::stdout().lock();
    for path in entries {
        let plaintext = match decrypt(&path) {
            Some(p) => p,
            None => continue,
        };

        let grep_output = match grep_plaintext(&plaintext, args) {
            Some(o) => o,
            None => continue,
        };

        let (dir, name) = split_display(&path, &root);
        let _ = writeln!(
            stdout,
            "{HEADER_BLUE_BOLD_RESET}{dir}{HEADER_BOLD}{name}{ANSI_RESET}:"
        );
        let _ = stdout.write_all(&grep_output);
        if !grep_output.ends_with(b"\n") {
            let _ = stdout.write_all(b"\n");
        }
    }

    0
}

fn decrypt(path: &std::path::Path) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let mut child = Command::new("pivy-box")
        .arg("stream")
        .arg("decrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        let mut reader = file;
        if std::io::copy(&mut reader, &mut stdin).is_err() {
            return None;
        }
    }
    let output = child.wait_with_output().ok()?;
    if output.status.success() {
        Some(output.stdout)
    } else {
        None
    }
}

fn grep_plaintext(plaintext: &[u8], args: &[String]) -> Option<Vec<u8>> {
    let mut child = Command::new("grep")
        .arg("--color=always")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        if stdin.write_all(plaintext).is_err() {
            return None;
        }
    }
    let output = child.wait_with_output().ok()?;
    if output.status.success() && !output.stdout.is_empty() {
        Some(output.stdout)
    } else {
        None
    }
}

/// Split a path under `root` into the (directory-with-trailing-slash,
/// basename-without-.ebox) pair that `cmd_grep` prints in its header.
/// Mirrors the bash:
///
/// ```text
/// passfile="${passfile%.ebox}"
/// passfile="${passfile#$PREFIX/}"
/// local passfile_dir="${passfile%/*}/"
/// [[ $passfile_dir == "${passfile}/" ]] && passfile_dir=""
/// passfile="${passfile##*/}"
/// ```
fn split_display(path: &std::path::Path, root: &std::path::Path) -> (String, String) {
    let rel = path.strip_prefix(root).unwrap_or(path);
    let rel = rel.to_string_lossy();
    let without_ebox = rel.strip_suffix(".ebox").unwrap_or(&rel).to_string();
    match without_ebox.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name.to_string()),
        None => (String::new(), without_ebox),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn split_display_strips_ebox_and_isolates_basename() {
        let root = Path::new("/store");
        let p = Path::new("/store/folder/where/blah5.ebox");
        let (dir, name) = split_display(p, root);
        assert_eq!(dir, "folder/where/");
        assert_eq!(name, "blah5");
    }

    #[test]
    fn split_display_top_level_entry_has_empty_dir() {
        let root = Path::new("/store");
        let p = Path::new("/store/blah1.ebox");
        let (dir, name) = split_display(p, root);
        assert_eq!(dir, "");
        assert_eq!(name, "blah1");
    }

    #[test]
    fn split_display_leaves_non_ebox_alone() {
        let root = Path::new("/store");
        let p = Path::new("/store/folder/note.txt");
        let (dir, name) = split_display(p, root);
        assert_eq!(dir, "folder/");
        assert_eq!(name, "note.txt");
    }
}
