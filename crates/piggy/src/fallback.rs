//! Bash + C pivy fallback dispatch.
//!
//! Pass-style clap handlers in `main` call [`exec_bash`] to run the
//! corresponding `cmd_*` function inside `piggy.sh`. The C-pivy shortcut
//! handlers (`piggy tool/ca/luks/zfs ...`) and the `piggy pivy <tool>`
//! passthrough call [`exec_pivy`] to run the matching `pivy-*` binary
//! from `$PATH`.
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

/// Exec `piggy.sh <subcmd> <rest...>`. Used by every pass-style clap
/// handler. Never returns on success.
///
/// Sets `$PIGGY_BIN` to the current executable path so any bash
/// function that needs to call back into the Rust binary (e.g. the
/// `reencrypt_path` shim that exec's `piggy internal-reencrypt-path`)
/// has an absolute path to use without depending on `$PATH`.
pub fn exec_bash(subcmd: &str, rest: &[String]) -> ! {
    let script = find_piggy_sh();
    let mut cmd = Command::new(&script);
    cmd.arg(subcmd);
    cmd.args(rest);
    set_piggy_bin(&mut cmd);
    set_piggy_version(&mut cmd);
    let err = cmd.exec();
    eprintln!("piggy: failed to launch {}: {}", script.display(), err);
    std::process::exit(127);
}

/// Exec `piggy.sh <subcmd> <op> <rest...>`. Used by structured pass
/// subcommand groups (e.g. `pass recipients add/remove/sync`) that
/// dispatch through bash via a parent + nested operation pair. The
/// piggy.sh `cmd_pass_<subcmd>` function dispatches on its first
/// positional, so we feed it `op` followed by `rest`. Never returns on
/// success.
pub fn exec_bash_subcmds(subcmd: &str, op: &str, rest: &[String]) -> ! {
    let script = find_piggy_sh();
    let mut cmd = Command::new(&script);
    cmd.arg(subcmd);
    cmd.arg(op);
    cmd.args(rest);
    set_piggy_bin(&mut cmd);
    set_piggy_version(&mut cmd);
    let err = cmd.exec();
    eprintln!("piggy: failed to launch {}: {}", script.display(), err);
    std::process::exit(127);
}

/// Set `$PIGGY_BIN=<current_exe>` on the command unless the caller's
/// environment already pins it. The bats harness sets `$PIGGY` to the
/// debug binary; we mirror that with `$PIGGY_BIN` so bash helpers can
/// call back into the same binary deterministically. `current_exe()`
/// can fail in unusual environments; we silently skip in that case
/// and let the bash side fall back to a bare-PATH lookup.
fn set_piggy_bin(cmd: &mut Command) {
    if std::env::var_os("PIGGY_BIN").is_some() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        cmd.env("PIGGY_BIN", exe);
    }
}

/// Set `$PIGGY_VERSION` on the command unless the caller's environment
/// already pins it (e.g. flake.nix's makeWrapper `--set PIGGY_VERSION
/// <piggyVersion>`). The value is injected at compile time by
/// `build.rs`, which reads `version.env` at the repo root — the single
/// source of truth shared with the Nix derivation. `piggy.sh`'s
/// `piggy_version_line` (the `help` banner) reads this env var; local
/// cargo builds get the right value without the wrapper layer. (The
/// `version` subcommand itself is the native `version` handler, which
/// reads `PIGGY_VERSION` directly with the same compile-time fallback.)
fn set_piggy_version(cmd: &mut Command) {
    if std::env::var_os("PIGGY_VERSION").is_some() {
        return;
    }
    cmd.env("PIGGY_VERSION", env!("PIGGY_VERSION"));
}

/// Exec `piggy-ids <subcmd> <rest...>`. Used by top-level commands
/// that drive piggy-ids directly rather than going through piggy.sh —
/// avoids name collisions with pass-style bash subcommands (e.g. the
/// top-level `piggy list` versus the `piggy pass list` alias for
/// `show`).
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

/// Locate `piggy.sh`. `piggy.sh` is an internal implementation detail
/// of the installed binary, not a callable program — `flake.nix`
/// installs it under `$out/libexec/piggy/` and the makeWrapper-set
/// `PIGGY_SH_PATH` points the rust dispatcher at that absolute path.
///
/// Resolution order:
///
/// 1. `$PIGGY_SH_PATH` (set by `flake.nix`'s makeWrapper for installed
///    builds, or by the bats harness's `common.bash` for local tests
///    against the in-repo copy).
/// 2. Bare `piggy.sh` as a final-resort PATH lookup. This branch only
///    matters for unusual devshell setups that put `src/` on `$PATH`;
///    every other reachable invocation goes through `$PIGGY_SH_PATH`.
fn find_piggy_sh() -> PathBuf {
    if let Some(path) = std::env::var_os("PIGGY_SH_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from("piggy.sh")
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
