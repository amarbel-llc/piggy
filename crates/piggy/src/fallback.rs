//! Bash + C pivy fallback dispatch.
//!
//! Pass-style clap handlers in `main` call [`exec_bash`] directly with an
//! explicit `subcmd` and `rest`. The catch-all [`dispatch`] entry point
//! handles the C-pivy shortcuts (`tool`, `ca`, `luks`, `zfs`) and also
//! retains a bash catch-all for argv that clap rejects with an error.
//! Under the v1.0 minimal-rewrite framing the catch-all is logically
//! unreachable for any subcommand clap names; #50 removes
//! [`hand_off_to_bash`] entirely once #48 promotes the C-pivy shortcuts
//! into clap handlers.
//!
//! Uses [`std::os::unix::process::CommandExt`]'s process-image-replacement
//! primitive (a thin wrapper around the `execve(2)` syscall) so the child
//! takes over `piggy`'s PID entirely — no extra shell layer, no PID
//! indirection. This is the safe `execve`-style call, not a shell-based one.

use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Subcommand names that currently live in the C pivy implementation.
/// Each maps to a `pivy-<name>` binary expected on `$PATH`.
const PIVY_SUBCOMMANDS: &[&str] = &["tool", "ca", "luks", "zfs"];

/// Returns true if `name` is a C-pivy shortcut handled outside clap.
/// Used by `main` to short-circuit clap parsing for `piggy tool ...`
/// etc. — #48 replaces this with explicit clap handlers.
pub fn is_pivy_shortcut(name: &str) -> bool {
    PIVY_SUBCOMMANDS.contains(&name)
}

/// Dispatch an argv that did not reach clap (currently only the C-pivy
/// shortcuts). `args` is the full argv (including `args[0]` = program
/// name). Never returns on success — the process is replaced in-place.
pub fn dispatch(args: &[String]) -> ! {
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();

    if let Some(&first) = rest.first() {
        if PIVY_SUBCOMMANDS.contains(&first) {
            hand_off_to_pivy(first, &rest[1..]);
        }
    }

    // Defense in depth: if `dispatch` is called with anything else, fall
    // back to bash. Under the current main.rs flow this branch is
    // unreachable — `is_pivy_shortcut` gates the call.
    hand_off_to_bash(&rest);
}

/// Exec `piggy.sh <subcmd> <rest...>`. Used by every pass-style clap
/// handler. Never returns on success.
pub fn exec_bash(subcmd: &str, rest: &[String]) -> ! {
    let script = find_piggy_sh();
    let mut cmd = Command::new(&script);
    cmd.arg(subcmd);
    cmd.args(rest);
    let err = cmd.exec();
    eprintln!("piggy: failed to launch {}: {}", script.display(), err);
    std::process::exit(127);
}

fn hand_off_to_pivy(subcmd: &str, rest: &[&str]) -> ! {
    let binary = format!("pivy-{}", subcmd);
    let err = Command::new(&binary).args(rest).exec();
    eprintln!("piggy: failed to launch {}: {}", binary, err);
    std::process::exit(127);
}

fn hand_off_to_bash(rest: &[&str]) -> ! {
    let script = find_piggy_sh();
    let err = Command::new(&script).args(rest).exec();
    eprintln!("piggy: failed to launch {}: {}", script.display(), err);
    std::process::exit(127);
}

/// Locate `piggy.sh`:
///
/// 1. `$PIGGY_SH_PATH` if set (baked in by nix makeWrapper at build time, or
///    set explicitly by bats tests to point at the in-repo copy).
/// 2. Otherwise assume `piggy.sh` is on `$PATH` (unusual, but OK for a
///    devshell setup where `src/` is on `$PATH`).
fn find_piggy_sh() -> PathBuf {
    if let Some(path) = std::env::var_os("PIGGY_SH_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from("piggy.sh")
}
