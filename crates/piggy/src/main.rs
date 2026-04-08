//! Top-level `piggy` binary.
//!
//! Dispatch logic:
//!
//! 1. `piggy agent ...` — handled in rust (see [`cmd::agent`]).
//! 2. `piggy box|tool|ca|luks|zfs ...` — handed off to the corresponding
//!    C `pivy-*` binary from `$PATH` (see [`fallback`]).
//! 3. Anything else (including `piggy` with no args, `--help`, `show`,
//!    `insert`, `edit`, …) — handed off to the bash `piggy.sh`
//!    implementation.
//!
//! Top-level dispatch is a simple `argv[1]` match so that argument parsing
//! does not interfere with the bash fallback path. Clap is only invoked
//! inside rust subcommands where its flag parsing actually applies.

mod cmd;
mod fallback;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() >= 2 && args[1] == "agent" {
        std::process::exit(cmd::agent::run(args));
    }

    fallback::dispatch(&args);
}
