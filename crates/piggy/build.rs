// Guard Cargo.toml's package.version against drifting from version.env,
// the repo's single version source of truth (eng-versioning(7), piggy#171).
// `just bump-version` rewrites version.env, this crate's Cargo.toml and its
// Cargo.lock entry together; this build script fails the build if they ever
// disagree, so the runtime can trust env!("CARGO_PKG_VERSION").
//
// Resolution order for the authoritative version:
//   1. $PIGGY_VERSION, when set at build time.
//   2. ../../version.env — the workspace checkout, and the nix build, whose
//      source keeps version.env at its root.
// If neither exists (e.g. a published crate tarball), the guard is a no-op
// and CARGO_PKG_VERSION stands on its own.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // CARGO_MANIFEST_DIR resolves to crates/piggy/. The workspace root
    // (where version.env lives) is two levels up.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let version_env = manifest_dir.join("../../version.env");

    println!("cargo:rerun-if-changed={}", version_env.display());
    println!("cargo:rerun-if-env-changed=PIGGY_VERSION");

    let authoritative = env::var("PIGGY_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            fs::read_to_string(&version_env)
                .ok()
                .as_deref()
                .and_then(parse_piggy_version)
        });
    if let Some(want) = authoritative {
        let have = env::var("CARGO_PKG_VERSION").expect("cargo always sets CARGO_PKG_VERSION");
        if want != have {
            panic!(
                "crates/piggy/Cargo.toml version ({have}) disagrees with version.env \
                 PIGGY_VERSION ({want}); run `just bump-version {want}` to resync"
            );
        }
    }

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
