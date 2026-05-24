//! `piggy pass rm [-r] [-f] <path>` — delete an entry (or a whole
//! subtree) from the store, recording the deletion in git if the store
//! is a git work tree.
//!
//! Mirrors `cmd_delete` in `src/piggy.sh:616`. The path resolution
//! rule is:
//!
//! - If `<path>.ebox` exists as a regular file and `<path>` is not a
//!   directory ending in `/`, treat it as a single-entry delete.
//! - Otherwise (no `.ebox` file, or the user explicitly passed a
//!   trailing `/`, etc), treat it as a directory delete, which
//!   requires `-r`.
//!
//! Sneaky path components (`..`) are rejected to match
//! `check_sneaky_paths` in piggy.sh.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::git_ops;
use crate::store::store_root;

/// Exit code conventions:
/// - 0: deleted (or user declined the yesno prompt — same as bash)
/// - 1: usage / not-in-store / sneaky-path / IO error
pub fn run(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("piggy pass rm: {msg}");
            return 1;
        }
    };

    if let Some(reason) = sneaky_path_reason(&opts.path) {
        eprintln!("Error: You've attempted to pass a sneaky path to piggy ({reason}). Go home.");
        return 1;
    }

    let root = store_root();
    let resolved = match resolve_path(&root, &opts.path) {
        Some(r) => r,
        None => {
            eprintln!("Error: {} is not in the password store.", opts.path);
            return 1;
        }
    };

    if matches!(resolved, Resolved::Dir(_)) && !opts.recursive {
        eprintln!(
            "Error: {} is a directory; pass --recursive (-r) to remove the whole subtree.",
            opts.path
        );
        return 1;
    }

    if !opts.force
        && !confirm(&format!(
            "Are you sure you would like to delete {}?",
            opts.path
        ))
    {
        return 0;
    }

    let target = resolved.path();
    if let Err(err) = remove_from_disk(target, opts.recursive) {
        eprintln!("piggy pass rm: remove {}: {}", target.display(), err);
        return 1;
    }

    // If we're inside a git work tree, record the deletion. The bash
    // re-runs `set_git` after the rm so a deletion that empties out
    // the inner repo's work tree still gets a chance to be tracked
    // by an outer one; mirror that lookup ordering.
    if let Some(work_tree) = git_ops::find_inner_git_dir(target, &root) {
        if !target.exists() {
            if let Err(rc) = git_ops::rm(&work_tree, target) {
                return rc;
            }
            // Commit may legitimately fail (nothing to commit, etc) —
            // we mirror the bash behavior of treating that as
            // non-fatal.
            let _ = git_ops::commit(&work_tree, &format!("Remove {} from store.", opts.path));
        }
    }

    // `rmdir -p` removes empty parent directories all the way up.
    // Ignore failures — mirror the `2>/dev/null` in bash.
    if let Some(parent) = target.parent() {
        let _ = remove_empty_parents(parent, &root);
    }

    0
}

#[derive(Debug)]
struct Opts {
    recursive: bool,
    force: bool,
    path: String,
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut recursive = false;
    let mut force = false;
    let mut positional: Vec<&String> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-r" | "--recursive" => recursive = true,
            "-f" | "--force" => force = true,
            "-rf" | "-fr" => {
                recursive = true;
                force = true;
            }
            "--" => {
                for rest in iter.by_ref() {
                    positional.push(rest);
                }
                break;
            }
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            _ => positional.push(arg),
        }
    }

    if positional.len() != 1 {
        return Err("Usage: piggy pass rm [--recursive,-r] [--force,-f] <pass-name>".into());
    }
    Ok(Opts {
        recursive,
        force,
        path: positional[0].clone(),
    })
}

#[derive(Debug)]
enum Resolved {
    File(PathBuf),
    Dir(PathBuf),
}

impl Resolved {
    fn path(&self) -> &Path {
        match self {
            Resolved::File(p) | Resolved::Dir(p) => p,
        }
    }
}

fn resolve_path(root: &Path, path: &str) -> Option<Resolved> {
    // Strip trailing slashes from the user-supplied path to match
    // the bash `${path%/}` parameter expansion.
    let stripped = path.trim_end_matches('/');
    let ends_with_slash = path != stripped;
    let dir_candidate = root.join(stripped);
    let file_candidate = {
        let mut p = root.join(stripped);
        let last = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
        let mut name = last.into_string().ok()?;
        name.push_str(".ebox");
        p.set_file_name(name);
        p
    };

    let file_exists = file_candidate.is_file();
    let dir_exists = dir_candidate.is_dir();

    // Bash predicate, re-grouped:
    //   ( file_exists && dir_exists && ends_with_slash ) || !file_exists
    // Kept in the parenthesized form (rather than clippy's
    // "!file_exists || dir_exists && ends_with_slash") so the parallel
    // to the bash source stays line-for-line obvious; the simplified
    // form relies on && binding tighter than || which is easy to
    // misread.
    #[allow(clippy::nonminimal_bool)]
    let treat_as_dir = (file_exists && dir_exists && ends_with_slash) || !file_exists;

    if treat_as_dir {
        if dir_exists {
            Some(Resolved::Dir(dir_candidate))
        } else {
            None
        }
    } else if file_exists {
        Some(Resolved::File(file_candidate))
    } else {
        None
    }
}

fn remove_from_disk(path: &Path, recursive: bool) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        if recursive {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_dir(path) // empty-dir only; non-recursive
        }
    } else {
        std::fs::remove_file(path)
    }
}

/// Walk up from `start` removing empty directories, stopping at (and
/// not removing) `root`. Mirrors `rmdir -p` without complaining if a
/// directory isn't empty.
fn remove_empty_parents(start: &Path, root: &Path) -> std::io::Result<()> {
    let mut current = start.to_path_buf();
    while current != *root && current.starts_with(root) {
        match std::fs::remove_dir(&current) {
            Ok(()) => {}
            Err(_) => break,
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => break,
        }
    }
    Ok(())
}

/// Mirrors `check_sneaky_paths` in piggy.sh. The bash form checks for
/// `..` as a whole component (not as a substring of another name like
/// `..foo`), so we walk components here rather than string-matching.
fn sneaky_path_reason(path: &str) -> Option<&'static str> {
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Some("`..` component");
        }
    }
    None
}

/// Print a [y/N] prompt and return true iff the user typed `y` or
/// `Y`. Returns true silently when stdin is not a TTY — matches the
/// bash `yesno` which `return 0`s without prompting in non-interactive
/// contexts.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_simple() {
        let v = vec!["cred1".to_string()];
        let o = parse_args(&v).unwrap();
        assert!(!o.recursive);
        assert!(!o.force);
        assert_eq!(o.path, "cred1");
    }

    #[test]
    fn parse_args_short_flags() {
        let v = vec!["-r".to_string(), "-f".to_string(), "folder".to_string()];
        let o = parse_args(&v).unwrap();
        assert!(o.recursive);
        assert!(o.force);
        assert_eq!(o.path, "folder");
    }

    #[test]
    fn parse_args_combined_short_flags() {
        let v = vec!["-rf".to_string(), "folder".to_string()];
        let o = parse_args(&v).unwrap();
        assert!(o.recursive);
        assert!(o.force);
    }

    #[test]
    fn parse_args_long_flags() {
        let v = vec![
            "--recursive".to_string(),
            "--force".to_string(),
            "folder".to_string(),
        ];
        let o = parse_args(&v).unwrap();
        assert!(o.recursive);
        assert!(o.force);
    }

    #[test]
    fn parse_args_dashdash_terminates_flags() {
        let v = vec![
            "-f".to_string(),
            "--".to_string(),
            "-weird-name".to_string(),
        ];
        let o = parse_args(&v).unwrap();
        assert!(o.force);
        assert_eq!(o.path, "-weird-name");
    }

    #[test]
    fn parse_args_missing_path() {
        let v = vec!["-f".to_string()];
        let err = parse_args(&v).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn parse_args_too_many_positionals() {
        let v = vec!["a".to_string(), "b".to_string()];
        let err = parse_args(&v).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn sneaky_path_rejects_parent_dir() {
        assert!(sneaky_path_reason("../etc").is_some());
        assert!(sneaky_path_reason("folder/../etc").is_some());
        assert!(sneaky_path_reason("..").is_some());
    }

    #[test]
    fn sneaky_path_accepts_double_dot_inside_name() {
        // The bash form rejects `..` only as a path component;
        // names containing `..` as substring are fine.
        assert!(sneaky_path_reason("a..b").is_none());
        assert!(sneaky_path_reason("foo/bar").is_none());
    }

    #[test]
    fn resolve_file_takes_precedence_when_both_exist() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.join("cred1")).unwrap();
        std::fs::write(tmp.join("cred1.ebox"), b"x").unwrap();
        let r = resolve_path(&tmp, "cred1").unwrap();
        assert!(matches!(r, Resolved::File(_)));
    }

    #[test]
    fn resolve_dir_when_no_ebox_file() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.join("folder")).unwrap();
        let r = resolve_path(&tmp, "folder").unwrap();
        assert!(matches!(r, Resolved::Dir(_)));
    }

    #[test]
    fn resolve_dir_when_trailing_slash_and_both_exist() {
        let tmp = tempdir();
        std::fs::create_dir_all(tmp.join("cred1")).unwrap();
        std::fs::write(tmp.join("cred1.ebox"), b"x").unwrap();
        let r = resolve_path(&tmp, "cred1/").unwrap();
        assert!(matches!(r, Resolved::Dir(_)));
    }

    #[test]
    fn resolve_none_when_neither_exists() {
        let tmp = tempdir();
        assert!(resolve_path(&tmp, "ghost").is_none());
    }

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-rm-test-{}",
            std::process::id().wrapping_mul(0x9E37)
                ^ (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u32)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
