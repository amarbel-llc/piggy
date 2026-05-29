//! `piggy version` — eng-versioning(7) hybrid output.
//!
//! Emits the self-identification line `piggy <version>+<commit>`, a blank
//! line, then a table of the pinned downstream components piggy
//! orchestrates (pivy) and depends on at runtime (pcsclite).
//!
//! All values are read from the environment that `flake.nix`'s makeWrapper
//! bakes into the wrapped binary (`PIGGY_VERSION`, `PIGGY_COMMIT`,
//! `PIGGY_<COMPONENT>_VERSION`/`_REV`). Component versions are sourced live
//! off the derivations there, so a pin bump shows up here with no code
//! change — drift stays visible. A dev `cargo build` has no wrapper, so the
//! component vars are unset and render "unknown"; the version still resolves
//! via `build.rs`'s compile-time `env!("PIGGY_VERSION")` (the spec-accepted
//! "dev" behavior, mirroring the Go path's `-X main.version`/`main.commit`).
//!
//! Ported from `cmd_version` in `src/piggy.sh` (piggy #96). The bash
//! `piggy_version_line` helper survives for `cmd_usage` (the `help` banner).
//!
//! IGLOO-PROMOTION CANDIDATE (amarbel-llc/nixpkgs#68): the flake-side
//! injection that feeds these env vars is the non-Go analog of
//! buildGoApplication's auto-embedding (#31); this module is its reference
//! consumer.

/// A pinned downstream component row in the version table.
struct Component {
    name: &'static str,
    version: String,
    rev: String,
}

/// Render the eng-versioning(7) version output: self-line, blank line, then
/// a `COMPONENT VERSION REV` table. Pure (no env / IO) so it is unit-testable
/// directly; column widths mirror the bash `printf '%-11s %-9s %s'` this was
/// ported from so the output is byte-identical.
fn render(version: &str, commit: &str, components: &[Component]) -> String {
    let mut out = format!("piggy {version}+{commit}\n\n");
    out.push_str(&format!("{:<11} {:<9} {}\n", "COMPONENT", "VERSION", "REV"));
    for c in components {
        out.push_str(&format!("{:<11} {:<9} {}\n", c.name, c.version, c.rev));
    }
    out
}

/// Environment variable value, treating empty as absent and falling back to
/// `default`.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Print the `piggy version` output. Always succeeds.
pub fn run() -> i32 {
    // Prefer the wrapper-injected runtime value (authoritative for nix
    // builds); fall back to the compile-time value for dev cargo builds.
    let version = env_or("PIGGY_VERSION", env!("PIGGY_VERSION"));
    let commit = env_or("PIGGY_COMMIT", "unknown");
    let components = [
        Component {
            name: "pivy",
            version: env_or("PIGGY_PIVY_VERSION", "unknown"),
            rev: env_or("PIGGY_PIVY_REV", "unknown"),
        },
        Component {
            name: "pcsclite",
            version: env_or("PIGGY_PCSCLITE_VERSION", "unknown"),
            rev: env_or("PIGGY_PCSCLITE_REV", "unknown"),
        },
    ];
    print!("{}", render(&version, &commit, &components));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [Component; 2] {
        [
            Component {
                name: "pivy",
                version: "0.15.0".into(),
                rev: "vendored".into(),
            },
            Component {
                name: "pcsclite",
                version: "2.4.1".into(),
                rev: "d233902".into(),
            },
        ]
    }

    #[test]
    fn self_line_is_name_version_plus_commit() {
        let out = render("0.1.1", "abc1234", &sample());
        assert_eq!(out.lines().next().unwrap(), "piggy 0.1.1+abc1234");
    }

    #[test]
    fn blank_line_separates_self_line_from_table() {
        let out = render("0.1.1", "abc1234", &sample());
        let mut lines = out.lines();
        lines.next(); // self-line
        assert_eq!(lines.next().unwrap(), "");
    }

    #[test]
    fn table_header_and_component_rows_present() {
        let out = render("0.1.1", "abc1234", &sample());
        let lines: Vec<&str> = out.lines().collect();
        // Header columns in order.
        assert!(lines.iter().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f == ["COMPONENT", "VERSION", "REV"]
        }));
        // Each component renders name/version/rev in order.
        assert!(lines
            .iter()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["pivy", "0.15.0", "vendored"]));
        assert!(
            lines
                .iter()
                .any(|l| l.split_whitespace().collect::<Vec<_>>()
                    == ["pcsclite", "2.4.1", "d233902"])
        );
    }
}
