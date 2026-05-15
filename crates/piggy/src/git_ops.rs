//! Shared git helpers used by Rust pass-* handlers (`git`, `rm`,
//! ... and eventually `mv`/`cp`/`recipients add/remove/sync`).
//!
//! These mirror the small set of helpers at the top of `src/piggy.sh`:
//!
//! - `set_git "$path"` (piggy.sh:27) → [`find_inner_git_dir`]
//! - `git_add_file "$path" "$msg"` (piggy.sh:34) → [`add_and_commit`]
//! - `git_commit "$msg"` (piggy.sh:40) → [`commit`]
//!
//! Plus a thin [`rm`] for the `git rm -qr <path>` invocation used by
//! `cmd_delete`.

use std::path::Path;
use std::process::Command;

/// Returns the path to the inner work-tree if `path` (or its parents,
/// up to but not crossing `store_root`) is inside one. Mirrors
/// `set_git "$path"`: walks up from `path`'s parent toward
/// `store_root`, picks the first directory that resolves to "inside a
/// git work tree", and returns it. Returns None if none of the
/// candidates are git work trees.
pub(crate) fn find_inner_git_dir<'a>(
    path: &'a Path,
    store_root: &'a Path,
) -> Option<std::path::PathBuf> {
    let mut current = path.parent()?.to_path_buf();
    loop {
        if is_inside_work_tree(&current) {
            return Some(current);
        }
        if !current.starts_with(store_root) {
            return None;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return None,
        }
    }
}

/// `git -C <work_tree> rev-parse --is-inside-work-tree` returning
/// true only on success + "true" output.
pub(crate) fn is_inside_work_tree(work_tree: &Path) -> bool {
    let out = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .arg("rev-parse")
        .arg("--is-inside-work-tree")
        .output();
    match out {
        Ok(o) if o.status.success() => o.stdout.trim_ascii() == b"true",
        _ => false,
    }
}

/// Mirrors `git_add_file` in piggy.sh: `git -C <work_tree> add <path>`
/// then commit only if there are actual staged changes.
///
/// `add_and_commit` is a no-op (returns Ok) when:
///
/// - `git add` failed (mirrors the `|| return` in bash)
/// - `git status --porcelain <path>` is empty (nothing to commit)
///
/// A failing `git commit` is also non-fatal — the bash silently
/// inherits git's exit code and proceeds.
pub(crate) fn add_and_commit(work_tree: &Path, path: &Path, message: &str) -> Result<(), i32> {
    let add_status = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .arg("add")
        .arg(path)
        .status();
    match add_status {
        Ok(s) if s.success() => {}
        Ok(_) | Err(_) => return Ok(()),
    }

    let porcelain = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .arg("status")
        .arg("--porcelain")
        .arg(path)
        .output();
    let Ok(out) = porcelain else { return Ok(()) };
    if out.stdout.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(());
    }

    commit(work_tree, message)
}

/// `git_commit "$message"` from piggy.sh. Honors the
/// `piggy.signcommits` boolean config; failures are non-fatal and
/// returned as Ok per the bash behavior.
pub(crate) fn commit(work_tree: &Path, message: &str) -> Result<(), i32> {
    let sign = signing_flag(work_tree);
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(work_tree).arg("commit");
    if sign {
        cmd.arg("-S");
    }
    cmd.arg("-m").arg(message);
    match cmd.status() {
        Ok(s) if s.success() => Ok(()),
        _ => Ok(()),
    }
}

fn signing_flag(work_tree: &Path) -> bool {
    let out = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .arg("config")
        .arg("--bool")
        .arg("--get")
        .arg("piggy.signcommits")
        .output();
    match out {
        Ok(o) if o.status.success() => o.stdout.trim_ascii() == b"true",
        _ => false,
    }
}

/// `git -C <work_tree> rm -qr <path>` — used by the rm handler.
/// Failures return Err with the underlying git exit code.
pub(crate) fn rm(work_tree: &Path, path: &Path) -> Result<(), i32> {
    let status = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .arg("rm")
        .arg("-qr")
        .arg(path)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(s.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("piggy: spawn git rm failed: {err}");
            Err(127)
        }
    }
}

/// Run `git -C <work_tree> <args>` and propagate the exit code.
pub(crate) fn git_at(work_tree: &Path, args: &[String]) -> Result<(), i32> {
    let status = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .args(args)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(s.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("piggy: spawn git failed: {err}");
            Err(127)
        }
    }
}
