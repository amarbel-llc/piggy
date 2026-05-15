//! `piggy pass git` — `init` subcase plus generic git passthrough.
//!
//! Mirrors `cmd_git` in `src/piggy.sh:718`:
//!
//! - `piggy pass git init`: run `git init` inside the store, write
//!   `.gitattributes` with `*.ebox diff=ebox`, configure
//!   `diff.ebox.binary=true` and
//!   `diff.ebox.textconv="pivy-box stream decrypt"`, and commit the
//!   resulting tree.
//! - Otherwise: re-exec `git -C $store_root ARGS`.
//!
//! ## v1 limitation
//!
//! The bash `cmd_git` runs `tmpdir nowarn` before non-init passthrough
//! to point `$TMPDIR` at a ramdisk so that any temp files git writes
//! (e.g. when `diff.ebox.textconv` is invoked) land on volatile
//! memory. The Rust port currently forwards a pre-existing
//! `$SECURE_TMPDIR` via `$TMPDIR` but does not allocate a ramdisk
//! itself. On test runs the harness already sets `SECURE_TMPDIR`. On
//! real user systems the security posture is slightly weaker than the
//! bash original until a Rust port of `tmpdir` lands. See the
//! umbrella tracking issue.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::git_ops::{add_and_commit, git_at, is_inside_work_tree};
use crate::store::store_root;

const PIGGY_DIFF_TEXTCONV: &str = "pivy-box stream decrypt";

/// Exit code conventions:
/// - 0: success (including a passthrough that exits 0)
/// - 1: the password store is not a git repo (non-init invocation)
/// - other: exit code of the underlying git process
pub fn run(args: &[String]) -> i32 {
    let root = store_root();
    let first = args.first().map(|s| s.as_str());

    if first == Some("init") {
        run_init(&root, args)
    } else {
        run_passthrough(&root, args)
    }
}

fn run_init(root: &Path, args: &[String]) -> i32 {
    // `git init` is idempotent — the harness pre-initializes the
    // store via init_test_git, then `pass git init` runs to set up
    // .gitattributes and the diff filter. We mirror that ordering.
    if let Err(rc) = git_at(root, args) {
        return rc;
    }
    if let Err(rc) = add_and_commit(root, root, "Add current contents of password store.") {
        return rc;
    }

    let gitattributes = root.join(".gitattributes");
    if let Err(err) = std::fs::write(&gitattributes, "*.ebox diff=ebox\n") {
        eprintln!(
            "piggy pass git init: write {}: {}",
            gitattributes.display(),
            err
        );
        return 1;
    }
    if let Err(rc) = add_and_commit(
        root,
        Path::new(".gitattributes"),
        "Configure git repository for ebox file diff.",
    ) {
        return rc;
    }

    if let Err(rc) = git_at(
        root,
        &[
            "config".into(),
            "--local".into(),
            "diff.ebox.binary".into(),
            "true".into(),
        ],
    ) {
        return rc;
    }
    if let Err(rc) = git_at(
        root,
        &[
            "config".into(),
            "--local".into(),
            "diff.ebox.textconv".into(),
            PIGGY_DIFF_TEXTCONV.into(),
        ],
    ) {
        return rc;
    }
    0
}

fn run_passthrough(root: &Path, args: &[String]) -> i32 {
    // Reproduce `set_git`'s validation: if the store is not a git
    // repo, refuse with the same error message as cmd_git.
    if !is_inside_work_tree(root) {
        eprintln!(
            "Error: the password store is not a git repository. Try \"piggy pass git init\"."
        );
        return 1;
    }

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root);
    for a in args {
        cmd.arg(a);
    }
    // Forward an externally-provided $SECURE_TMPDIR as $TMPDIR so any
    // git temp files (e.g. textconv intermediate buffers) land where
    // the operator asked. We deliberately do NOT allocate a ramdisk
    // here; see module doc.
    if let Some(sec) = std::env::var_os("SECURE_TMPDIR") {
        if !sec.is_empty() {
            cmd.env("TMPDIR", sec);
        }
    }

    let err = cmd.exec();
    eprintln!("piggy pass git: exec git failed: {err}");
    127
}

// No unit tests in this module — every behavior reaches a real git
// binary or filesystem, and the bats integration tests (t0050, t0055,
// t0060, t0100, t0200, t0300, t0500, t0600) cover the full surface
// end-to-end. Shared git helpers live in `git_ops`.
