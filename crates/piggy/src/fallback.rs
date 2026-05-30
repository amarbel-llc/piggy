//! C-pivy + piggy-ids fallback dispatch.
//!
//! Post Split B of #96 the piggy dispatcher is pure Rust on the
//! pass-style path; no `cmd_*` function survives in bash. The two
//! exec helpers below cover the remaining out-of-process hops:
//!
//! - [`exec_piggy_ids`] runs the `piggy-ids` helper binary for the
//!   top-level `piggy list` (and previously for the
//!   `recipients list-available` subcommand, kept for namespace
//!   stability).
//! - [`exec_pivy`] runs `pivy-<tool>` for the C-pivy shortcuts
//!   (`agent` / `box` / `tool` / `ca` / `luks` / `zfs`) and the
//!   `piggy pivy <tool>` passthrough.
//!
//! Top-level dispatch is exhaustive in clap; this module owns no
//! subcommand-name routing and has no catch-all. Every reachable
//! function here is named explicitly by some clap handler.
//!
//! Uses [`std::os::unix::process::CommandExt`]'s process-image-replacement
//! primitive (a thin wrapper around the `execve(2)` syscall) so the child
//! takes over `piggy`'s PID entirely — no extra shell layer, no PID
//! indirection. This is the safe `execve`-style call, not a shell-based one.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Exec `piggy-ids <subcmd> <rest...>`. Used by top-level commands
/// that drive piggy-ids directly — avoids name collisions with
/// pass-style handlers (e.g. the top-level `piggy list` versus the
/// `piggy pass list` alias for `show`).
///
/// Locates the binary via the makeWrapper-set `PIGGY_IDS_PATH`,
/// falling back to a bare `piggy-ids` PATH lookup so devshell builds
/// without `flake.nix`'s wrapper still work. Never returns on success.
pub fn exec_piggy_ids(subcmd: &str, rest: &[String]) -> ! {
    let binary = std::env::var_os("PIGGY_IDS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("piggy-ids"));
    let mut cmd = Command::new(&binary);
    cmd.arg(subcmd);
    cmd.args(rest);
    let err = cmd.exec();
    eprintln!("piggy: failed to launch {}: {}", binary.display(), err);
    std::process::exit(127);
}

/// Exec `pivy-<tool> <rest...>`. Used by the C-pivy shortcut handlers
/// (`tool/ca/luks/zfs`) and by the `piggy pivy <tool>` passthrough.
/// Never returns on success.
///
/// `tool` is rejected if it contains a path separator, a NUL, or
/// shell-meaningful characters that have no business being part of a
/// pivy subcommand name. Anything else is concatenated as
/// `pivy-<tool>` and looked up on `$PATH`; missing binaries surface as
/// a clear error from the OS via the print-and-exit-127 path below.
pub fn exec_pivy(tool: &str, rest: &[String]) -> ! {
    if !is_safe_pivy_tool_name(tool) {
        eprintln!("piggy: invalid pivy tool name: {tool:?}");
        std::process::exit(2);
    }
    let binary = format!("pivy-{}", tool);
    let err = Command::new(&binary).args(rest).exec();
    eprintln!("piggy: failed to launch {}: {}", binary, err);
    std::process::exit(127);
}

/// `piggy pivy <tool>` accepts free-form `tool` strings; keep them
/// restricted to printable ASCII without separators so a misbehaving
/// caller cannot synthesize a path or option-prefixed binary name.
/// `pivy-*` upstream uses lowercase letters only (`pivy-box`,
/// `pivy-tool`, …) so this is also tighter than `$PATH` lookups.
fn is_safe_pivy_tool_name(tool: &str) -> bool {
    !tool.is_empty()
        && tool
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::is_safe_pivy_tool_name;

    #[test]
    fn accepts_known_pivy_tool_names() {
        for name in ["box", "tool", "agent", "ca", "luks", "zfs"] {
            assert!(is_safe_pivy_tool_name(name), "{name} should be accepted");
        }
    }

    #[test]
    fn rejects_path_separators() {
        for bad in ["box/sh", "../bash", "tool/.."] {
            assert!(!is_safe_pivy_tool_name(bad), "{bad} should be rejected");
        }
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for bad in ["box;rm", "tool|cat", "box$X", "tool ", " tool", "box\n"] {
            assert!(!is_safe_pivy_tool_name(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_safe_pivy_tool_name(""));
    }

    #[test]
    fn accepts_underscore_and_digits() {
        assert!(is_safe_pivy_tool_name("box2"));
        assert!(is_safe_pivy_tool_name("tool_v2"));
    }
}
