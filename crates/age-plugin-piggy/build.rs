// Embed piggy's version+commit into `age-plugin-piggy` so `--version` reports
// `age-plugin-piggy <version>+<commit>` per eng-versioning(7), matching the
// rest of the piggy stack.
//
// `PIGGY_VERSION` comes from the repo-root `version.env` (piggy's single
// source of truth) at compile time. `PIGGY_COMMIT` comes from `git rev-parse`
// in dev builds; in the nix sandbox (no `.git`) it stays unset and the
// flake's makeWrapper `--set PIGGY_COMMIT` supplies the runtime value — the
// same split `crates/piggy/build.rs` uses.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // CARGO_MANIFEST_DIR is crates/age-plugin-piggy/; version.env is two up.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let version_env = manifest_dir.join("../../version.env");

    println!("cargo:rerun-if-changed={}", version_env.display());

    let version = match fs::read_to_string(&version_env) {
        Ok(content) => parse_piggy_version(&content).unwrap_or_else(|| "dev".to_string()),
        Err(_) => "dev".to_string(),
    };
    println!("cargo:rustc-env=PIGGY_VERSION={version}");

    emit_git_commit(&manifest_dir);
}

/// `git rev-parse --short HEAD` → `PIGGY_COMMIT`. Absent under the nix sandbox
/// (no `.git`); the wrapper's `--set PIGGY_COMMIT` covers that at runtime.
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
        return;
    };
    println!("cargo:rustc-env=PIGGY_COMMIT={rev}");

    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(ref_name) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        if let Some(ref_path) = git(&["rev-parse", "--git-path", &ref_name]) {
            println!("cargo:rerun-if-changed={ref_path}");
        }
    }
}

/// First non-comment `PIGGY_VERSION=<value>` (optional `export `), quotes
/// trimmed. Hand-rolled to keep the build script dependency-free.
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
