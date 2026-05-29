//! `piggy pass mv|cp [-f] <old-path> <new-path>` — move/rename or copy
//! an entry (or a whole subtree) within the store, re-encrypting any
//! `.ebox` files that cross a recipient boundary and recording the
//! change in git if the store is a git work tree.
//!
//! Mirrors `cmd_copy_move` in `src/piggy.sh:599`. The two entry points
//! (`run_move`, `run_copy`) correspond to the bash `cmd_copy_move
//! "move"` / `cmd_copy_move "copy"` wrappers.
//!
//! The old-path resolution rule matches `rm`'s: if `<old>.ebox` exists
//! as a regular file and `<old>` is not a directory the user named with
//! a trailing slash, treat it as a single-entry move/copy; otherwise
//! treat `<old>` as a directory. The new-path gets a `.ebox` suffix
//! unless the old path is a directory, the new path already exists as a
//! directory, or the new path was named with a trailing slash.
//!
//! The actual move/copy shells out to `mv`/`cp` so the `-i`/`-f`
//! overwrite semantics (interactive prompt on a TTY, force otherwise)
//! match the bash original byte-for-byte.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git_ops;
use crate::reencrypt;
use crate::store::store_root;

pub fn run_move(args: &[String]) -> i32 {
    run(Op::Move, args)
}

pub fn run_copy(args: &[String]) -> i32 {
    run(Op::Copy, args)
}

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Move,
    Copy,
}

impl Op {
    fn command_label(self) -> &'static str {
        match self {
            Op::Move => "mv",
            Op::Copy => "cp",
        }
    }
}

fn run(op: Op, args: &[String]) -> i32 {
    let opts = match parse_args(op, args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if let Some(reason) = sneaky_path_reason(&opts.old) {
        eprintln!("Error: You've attempted to pass a sneaky path to piggy ({reason}). Go home.");
        return 1;
    }
    if let Some(reason) = sneaky_path_reason(&opts.new) {
        eprintln!("Error: You've attempted to pass a sneaky path to piggy ({reason}). Go home.");
        return 1;
    }

    let root = store_root();

    // The new path is carried as a string so the bash `${new_path%/*}`
    // mkdir target and the `$new_path == */` trailing-slash test survive
    // (PathBuf::join normalizes trailing slashes away).
    let root_str = root.to_string_lossy().into_owned();
    let old_stripped = opts.old.trim_end_matches('/');
    let old_ends_with_slash = opts.old != old_stripped;
    let mut old_path = root.join(old_stripped);
    let mut old_dir = old_path.clone();
    let mut new_path = format!("{}/{}", root_str, opts.new);

    let old_ebox = with_ebox_suffix(&old_path);
    let old_is_dir = old_path.is_dir();
    let old_ebox_is_file = old_ebox.is_file();

    // Bash: `! [[ -f $old.ebox && -d $old && $1 == */ || ! -f $old.ebox ]]`
    // — treat as a single-entry move when the `.ebox` file exists and we
    // are not in the directory-with-trailing-slash case.
    let treat_as_file = old_ebox_is_file && !(old_is_dir && old_ends_with_slash);
    if treat_as_file {
        old_dir = old_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| old_path.clone());
        old_path = old_ebox;
    }

    println!("{}", old_path.display());
    if !old_path.exists() {
        eprintln!("Error: {} is not in the password store.", opts.old);
        return 1;
    }

    let mkdir_target = dirname(&new_path);
    if let Err(err) = std::fs::create_dir_all(&mkdir_target) {
        eprintln!(
            "piggy pass {}: mkdir {}: {}",
            op.command_label(),
            mkdir_target,
            err
        );
        return 1;
    }

    let new_ends_with_slash = new_path.ends_with('/');
    if !(old_path.is_dir() || Path::new(&new_path).is_dir() || new_ends_with_slash) {
        new_path.push_str(".ebox");
    }
    let new_path = PathBuf::from(new_path);

    let force = opts.force || !std::io::IsTerminal::is_terminal(&std::io::stdin());

    if !transfer(op, &old_path, &new_path, force) {
        return 1;
    }

    if new_path.exists() {
        reencrypt::run(&new_path);
    }

    match op {
        Op::Move => commit_move(&root, &old_path, &old_dir, &new_path, &opts),
        Op::Copy => {
            if let Some(work_tree) = git_ops::find_inner_git_dir(&new_path, &root) {
                let _ = git_ops::add_and_commit(
                    &work_tree,
                    &new_path,
                    &format!("Copy {} to {}.", opts.old, opts.new),
                );
            }
        }
    }

    0
}

/// Mirrors the move branch's git bookkeeping in cmd_copy_move: stage the
/// renamed destination under the new path's work tree, then record the
/// source removal under the old path's work tree (which may differ), and
/// finally prune emptied parent directories of the old path.
fn commit_move(root: &Path, old_path: &Path, old_dir: &Path, new_path: &Path, opts: &Opts) {
    if !old_path.exists() {
        if let Some(work_tree) = git_ops::find_inner_git_dir(new_path, root) {
            let _ = git_ops::rm(&work_tree, old_path);
            let _ = git_ops::add_and_commit(
                &work_tree,
                new_path,
                &format!("Rename {} to {}.", opts.old, opts.new),
            );
        }
    }

    if !old_path.exists() {
        if let Some(work_tree) = git_ops::find_inner_git_dir(old_path, root) {
            let _ = git_ops::rm(&work_tree, old_path);
            if has_staged_changes(&work_tree, old_path) {
                let _ = git_ops::commit(&work_tree, &format!("Remove {}.", opts.old));
            }
        }
    }

    let _ = remove_empty_parents(old_dir, root);
}

fn has_staged_changes(work_tree: &Path, path: &Path) -> bool {
    let out = Command::new("git")
        .arg("-C")
        .arg(work_tree)
        .arg("status")
        .arg("--porcelain")
        .arg(path)
        .output();
    match out {
        Ok(o) => !o.stdout.iter().all(|b| b.is_ascii_whitespace()),
        Err(_) => false,
    }
}

/// Shell out to `mv`/`cp` to preserve the bash overwrite semantics:
/// `-f` when forced or stdin is not a TTY, `-i` otherwise. `cp` adds
/// `-r` so directory copies work. Both run with `-v`, matching bash.
fn transfer(op: Op, old_path: &Path, new_path: &Path, force: bool) -> bool {
    let interactive = if force { "-f" } else { "-i" };
    let mut cmd = Command::new(op.command_label());
    cmd.arg(interactive);
    if op == Op::Copy {
        cmd.arg("-r");
    }
    cmd.arg("-v").arg(old_path).arg(new_path);
    matches!(cmd.status(), Ok(s) if s.success())
}

/// Append `.ebox` to a path's final component, mirroring the bash
/// `${path}.ebox`.
fn with_ebox_suffix(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".ebox");
    path.with_file_name(name)
}

/// `${new_path%/*}` — strip the shortest trailing `/...`, mirroring the
/// bash parameter expansion that computes the mkdir -p target. Unlike
/// `Path::parent`, this leaves a trailing-slash path pointing at the
/// directory itself (`a/b/` -> `a/b`), not its parent.
fn dirname(path: &str) -> String {
    match path.rfind('/') {
        Some(idx) => path[..idx].to_string(),
        None => path.to_string(),
    }
}

/// Walk up from `start` removing empty directories, stopping at (and not
/// removing) `root`. Mirrors `rmdir -p ... 2>/dev/null`.
fn remove_empty_parents(start: &Path, root: &Path) -> std::io::Result<()> {
    let mut current = start.to_path_buf();
    while current != *root && current.starts_with(root) {
        if std::fs::remove_dir(&current).is_err() {
            break;
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => break,
        }
    }
    Ok(())
}

/// Mirrors `check_sneaky_paths`: rejects `..` as a whole path component.
fn sneaky_path_reason(path: &str) -> Option<&'static str> {
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Some("`..` component");
        }
    }
    None
}

#[derive(Debug)]
struct Opts {
    force: bool,
    old: String,
    new: String,
}

fn parse_args(op: Op, args: &[String]) -> Result<Opts, String> {
    let mut force = false;
    let mut positional: Vec<&String> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-f" | "--force" => force = true,
            "--" => {
                for rest in iter.by_ref() {
                    positional.push(rest);
                }
                break;
            }
            s if s.starts_with('-') => {
                return Err(format!(
                    "piggy pass {}: unknown flag: {s}",
                    op.command_label()
                ));
            }
            _ => positional.push(arg),
        }
    }

    if positional.len() != 2 {
        return Err(format!(
            "Usage: piggy pass {} [--force,-f] old-path new-path",
            op.command_label()
        ));
    }
    Ok(Opts {
        force,
        old: positional[0].clone(),
        new: positional[1].clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_requires_two_positionals() {
        assert!(parse_args(Op::Move, &["a".into()]).is_err());
        assert!(parse_args(Op::Move, &["a".into(), "b".into(), "c".into()]).is_err());
        let o = parse_args(Op::Move, &["a".into(), "b".into()]).unwrap();
        assert!(!o.force);
        assert_eq!(o.old, "a");
        assert_eq!(o.new, "b");
    }

    #[test]
    fn parse_args_force_flag() {
        let o = parse_args(Op::Copy, &["-f".into(), "a".into(), "b".into()]).unwrap();
        assert!(o.force);
        let o = parse_args(Op::Copy, &["--force".into(), "a".into(), "b".into()]).unwrap();
        assert!(o.force);
    }

    #[test]
    fn parse_args_dashdash_terminates_flags() {
        let o = parse_args(Op::Move, &["--".into(), "-weird".into(), "dst".into()]).unwrap();
        assert_eq!(o.old, "-weird");
        assert_eq!(o.new, "dst");
    }

    #[test]
    fn with_ebox_suffix_appends_to_final_component() {
        assert_eq!(
            with_ebox_suffix(Path::new("/store/a/cred")),
            PathBuf::from("/store/a/cred.ebox")
        );
    }

    #[test]
    fn sneaky_path_rejects_parent_dir_component() {
        assert!(sneaky_path_reason("../etc").is_some());
        assert!(sneaky_path_reason("a/../b").is_some());
        assert!(sneaky_path_reason("a..b").is_none());
    }
}
