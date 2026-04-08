//! Bash + C pivy fallback dispatch.
//!
//! Unknown subcommands are handed off to either a C `pivy-*` binary (for
//! subcommands that currently have no rust implementation) or to the bash
//! `piggy.sh` script (for everything else, including the passwordstore-style
//! commands and `--help`).
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
const PIVY_SUBCOMMANDS: &[&str] = &["box", "tool", "ca", "luks", "zfs"];

/// Dispatch an argv that did not match any rust subcommand.
///
/// `args` is the full argv (including `args[0]` = program name).
/// Never returns on success — the process is replaced in-place.
pub fn dispatch(args: &[String]) -> ! {
    // Strip the program name; the target binary gets only the subcommand + rest.
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();

    if let Some(&first) = rest.first() {
        if PIVY_SUBCOMMANDS.contains(&first) {
            hand_off_to_pivy(first, &rest[1..]);
        }
    }

    hand_off_to_bash(&rest);
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
