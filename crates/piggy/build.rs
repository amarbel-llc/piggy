// Read PIGGY_VERSION from ../../version.env at build time and re-export
// it as a rustc env var so the dispatcher binary can use
// env!("PIGGY_VERSION") in any Rust handler (today: src/version.rs and
// the usage banner).
//
// The repo-root version.env is piggy's single source of truth (see
// eng-versioning(7), piggy CLAUDE.md). flake.nix's piggy derivation reads
// the same file via builtins.match; this script keeps the dev `cargo
// build` path consistent.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // CARGO_MANIFEST_DIR resolves to crates/piggy/. The workspace root
    // (where version.env lives) is two levels up.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let version_env = manifest_dir.join("../../version.env");

    // Re-run only when version.env changes. cargo:rerun-if-changed takes
    // a path relative to the crate manifest; pass the canonicalized path
    // so Cargo's deduplication works regardless of which form we use.
    println!("cargo:rerun-if-changed={}", version_env.display());

    let version = match fs::read_to_string(&version_env) {
        Ok(content) => parse_piggy_version(&content).unwrap_or_else(|| {
            println!(
                "cargo:warning=PIGGY_VERSION not found in {}; defaulting to 'dev'",
                version_env.display()
            );
            "dev".to_string()
        }),
        Err(e) => {
            println!(
                "cargo:warning=failed to read {}: {}; defaulting to 'dev'",
                version_env.display(),
                e
            );
            "dev".to_string()
        }
    };

    println!("cargo:rustc-env=PIGGY_VERSION={}", version);

    emit_git_commit(&manifest_dir);
}

/// Resolve `git rev-parse --short HEAD` and emit it as `PIGGY_COMMIT` so a
/// dev `cargo build` embeds the real short-rev instead of `unknown` (#126).
///
/// The nix build sandbox strips `.git`, so git resolution fails there — that
/// is fine: we simply don't set the compile-time var, and `version::run`
/// keeps getting the commit from the wrapper's `self.shortRev` at runtime
/// (it prefers the runtime value). This is the same version-from-`version.env`
/// / commit-from-`src.rev` split the Go path uses. Uses `git rev-parse
/// --git-path` for the rerun triggers so it works inside git worktrees (where
/// `.git` is a file, not a directory).
fn emit_git_commit(manifest_dir: &std::path::Path) {
    let git = |args: &[&str]| -> Option<String> {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(manifest_dir)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    };

    let Some(rev) = git(&["rev-parse", "--short", "HEAD"]) else {
        // No git (nix sandbox, or git not on PATH) — leave PIGGY_COMMIT unset
        // so `option_env!("PIGGY_COMMIT")` is None and the runtime/`unknown`
        // fallback applies.
        return;
    };
    println!("cargo:rustc-env=PIGGY_COMMIT={rev}");

    // Rebuild when HEAD moves (commit or branch switch) and when the current
    // branch's tip advances. `--git-path` resolves to the real files even in
    // a worktree; the ref lookup is skipped on a detached HEAD.
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(ref_name) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(ref_path) = git(&["rev-parse", "--git-path", &ref_name]) {
            println!("cargo:rerun-if-changed={ref_path}");
        }
    }
}

// Hand-rolled parse: avoids a regex crate dependency on the build script.
// Looks for the first non-comment line whose key (with optional `export `
// prefix) is `PIGGY_VERSION`, strips trailing whitespace and optional
// surrounding quotes, and returns the value.
fn parse_piggy_version(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let body = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let (key, value) = body.split_once('=')?;
        if key.trim() != "PIGGY_VERSION" {
            continue;
        }
        let value = value
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .to_string();
        if value.is_empty() {
            return None;
        }
        return Some(value);
    }
    None
}
