// Read PIGGY_VERSION from ../../version.env at build time and re-export
// it as a rustc env var so the dispatcher binary can use
// env!("PIGGY_VERSION") to inject the version into the bash subprocess
// (see src/fallback.rs::set_piggy_version) and any future Rust handler.
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
