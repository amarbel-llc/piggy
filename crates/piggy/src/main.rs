//! Top-level `piggy` binary.
//!
//! Dispatch layout (top-level argv is parsed entirely by clap):
//!
//! 1. Pass-style subcommands (init, show, find, grep, insert, edit,
//!    generate, rm, mv, cp, git, help, version) `exec(2)` into
//!    `piggy.sh <subcommand> <rest...>` — Shape A from the v1.0 scoping
//!    doc. The case statement at the bottom of `piggy.sh` does the
//!    second-level dispatch to the matching `cmd_*` function. Per-
//!    subcommand `getopt` parsing stays in bash; clap captures all
//!    trailing argv verbatim.
//! 2. Rust-native subcommands (agent, box) dispatch to their existing
//!    handlers in [`cmd::agent`] / [`cmd::pivy_box`].
//! 3. C-pivy shortcuts (tool, ca, luks, zfs) `exec(2)` the matching
//!    `pivy-*` binary from `$PATH` via [`fallback::exec_pivy`].
//! 4. The `pivy` passthrough (`piggy pivy <tool> [args...]`) is a
//!    generic escape hatch around the Rust subcommands — always
//!    forwards to the C `pivy-*` binary, even when there's a Rust
//!    counterpart (`piggy pivy box` ≠ `piggy box`). See the v1.0
//!    scoping doc for the rationale.

mod cmd;
mod fallback;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "piggy",
    bin_name = "piggy",
    about = "PIV-encrypted password store",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
}

/// Each pass-style variant captures `rest` with `trailing_var_arg` +
/// `allow_hyphen_values` so per-command flags (e.g. `-c`, `--multiline`,
/// `-r`) reach `piggy.sh`'s `getopt` blocks untouched. Clap is only
/// responsible for matching the subcommand name and any of its visible
/// aliases.
#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize a new password store.
    Init {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// List or show a password (default when no subcommand is given).
    #[command(visible_aliases = ["ls", "list"])]
    Show {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// List passwords whose names match a search term.
    #[command(visible_alias = "search")]
    Find {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Grep across decrypted password contents.
    Grep {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Insert a new password.
    #[command(visible_alias = "add")]
    Insert {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Edit an existing password in $EDITOR.
    Edit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Generate a new password.
    Generate {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Remove a password or directory.
    #[command(visible_aliases = ["delete", "remove"])]
    Rm {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Move/rename a password.
    #[command(visible_alias = "rename")]
    Mv {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Copy a password.
    #[command(visible_alias = "copy")]
    Cp {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Run git inside the password store.
    Git {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Print piggy.sh's pass-style usage text.
    Help {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Print piggy.sh's version banner.
    Version {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// PIV-backed SSH signing agent.
    ///
    /// `piggy agent` has its own clap parser; `--help`, `-h`, and any
    /// other flags pass through to that parser rather than being
    /// consumed by this top-level one.
    #[command(disable_help_flag = true)]
    Agent {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// PIV-based encryption/decryption (Rust pivy-box reimplementation).
    ///
    /// `piggy box` has its own argv handling; `--help`, `-h`, and any
    /// other flags pass through to that handler rather than being
    /// consumed by this top-level one.
    #[command(disable_help_flag = true)]
    Box {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Run the C `pivy-tool` binary.
    ///
    /// Forwarded to `pivy-tool` from `$PATH`; piggy does not interpret
    /// any of its flags. Scheduled for a Rust port post-1.0 (#3).
    #[command(disable_help_flag = true)]
    Tool {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Run the C `pivy-ca` binary.
    #[command(disable_help_flag = true)]
    Ca {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Run the C `pivy-luks` binary.
    #[command(disable_help_flag = true)]
    Luks {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Run the C `pivy-zfs` binary.
    #[command(disable_help_flag = true)]
    Zfs {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Run any C `pivy-<tool>` binary explicitly (escape hatch).
    ///
    /// Always reaches the C binary from `$PATH`; `piggy pivy box` runs
    /// `pivy-box` even though `piggy box` runs the Rust reimplementation,
    /// and `piggy pivy agent` runs `pivy-agent` even though `piggy agent`
    /// runs the Rust agent. Useful when callers specifically want the
    /// upstream C behavior or are scripting against the full `pivy-*`
    /// family.
    #[command(disable_help_flag = true)]
    Pivy {
        /// Subcommand name (e.g. `box`, `tool`, `agent`, `ca`, `luks`,
        /// `zfs`). Concatenated as `pivy-<TOOL>` and looked up on
        /// `$PATH`.
        tool: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let cli = Cli::parse_from(&argv);
    let prog = argv[0].clone();

    match cli.cmd {
        // No subcommand: piggy.sh's default-case (line 789-792) calls
        // `cmd_show ""`. Forward an empty argv and let bash do that.
        None => fallback::exec_bash("show", &[]),

        Some(Command::Agent { rest }) => {
            let mut full = vec![prog, "agent".to_string()];
            full.extend(rest);
            std::process::exit(cmd::agent::run(full));
        }
        Some(Command::Box { rest }) => {
            let mut full = vec![prog, "box".to_string()];
            full.extend(rest);
            std::process::exit(cmd::pivy_box::run(full));
        }

        Some(Command::Init { rest }) => fallback::exec_bash("init", &rest),
        Some(Command::Show { rest }) => fallback::exec_bash("show", &rest),
        Some(Command::Find { rest }) => fallback::exec_bash("find", &rest),
        Some(Command::Grep { rest }) => fallback::exec_bash("grep", &rest),
        Some(Command::Insert { rest }) => fallback::exec_bash("insert", &rest),
        Some(Command::Edit { rest }) => fallback::exec_bash("edit", &rest),
        Some(Command::Generate { rest }) => fallback::exec_bash("generate", &rest),
        Some(Command::Rm { rest }) => fallback::exec_bash("rm", &rest),
        Some(Command::Mv { rest }) => fallback::exec_bash("mv", &rest),
        Some(Command::Cp { rest }) => fallback::exec_bash("cp", &rest),
        Some(Command::Git { rest }) => fallback::exec_bash("git", &rest),
        Some(Command::Help { rest }) => fallback::exec_bash("help", &rest),
        Some(Command::Version { rest }) => fallback::exec_bash("version", &rest),

        Some(Command::Tool { rest }) => fallback::exec_pivy("tool", &rest),
        Some(Command::Ca { rest }) => fallback::exec_pivy("ca", &rest),
        Some(Command::Luks { rest }) => fallback::exec_pivy("luks", &rest),
        Some(Command::Zfs { rest }) => fallback::exec_pivy("zfs", &rest),

        Some(Command::Pivy { tool, rest }) => match tool {
            Some(tool) => fallback::exec_pivy(&tool, &rest),
            None => {
                eprintln!("piggy pivy: missing tool name");
                eprintln!("Usage: piggy pivy <tool> [args...]");
                eprintln!("Examples: piggy pivy box help, piggy pivy tool list");
                std::process::exit(2);
            }
        },
    }
}
