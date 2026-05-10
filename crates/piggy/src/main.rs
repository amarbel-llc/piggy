//! Top-level `piggy` binary.
//!
//! Dispatch layout (top-level argv is parsed entirely by clap):
//!
//! 1. `piggy pass <X>` — every password-store subcommand (`init`, `show`,
//!    `find`, `grep`, `insert`, `edit`, `generate`, `rm`, `mv`, `cp`,
//!    `git`) lives under the `pass` namespace and `exec(2)`s into
//!    `piggy.sh <X> <rest...>` via [`fallback::exec_bash`]. The case
//!    statement at the bottom of `piggy.sh` does the second-level
//!    dispatch to the matching `cmd_*` function. Per-subcommand
//!    `getopt` parsing stays in bash; clap captures all trailing argv
//!    verbatim.
//! 2. Top-level `help` and `version` also `exec_bash` into piggy.sh's
//!    `cmd_usage`/`cmd_version` — they print piggy-wide usage and
//!    version banners and so live outside the `pass` namespace.
//! 3. C-pivy passthroughs — every other subcommand `exec(2)`s the
//!    matching `pivy-*` binary from `$PATH` via
//!    [`fallback::exec_pivy`]:
//!    - `agent` → `pivy-agent`
//!    - `box` → `pivy-box`
//!    - `tool` → `pivy-tool`, `ca` → `pivy-ca`, `luks` → `pivy-luks`,
//!      `zfs` → `pivy-zfs`
//!    - `pivy <X>` is the explicit-escape-hatch form — `piggy pivy
//!      <tool> [args]` always reaches `pivy-<tool>`.
//!
//! Bare `piggy` and bare `piggy pass` both print clap help (no implicit
//! `cmd_show ""`); `arg_required_else_help` handles that on the top-level
//! `Cli` and the nested `PassArgs`.
//!
//! Rust-native re-implementations of `agent` and `box` exist under
//! `cmd::agent` / `cmd::pivy_box` but are NOT on the binary's
//! dispatch path. They will return once they reach feature parity
//! with the C implementations. The maturation roadmap:
//! - #56 — PC/SC transaction handling in `piggy-piv`.
//! - #57 — direct-PCSC ECDH oracle for `piggy box stream decrypt`,
//!   currently lost because C `pivy-box` requires an agent for ECDH.
//! - #58 — restore `[piggy-test]` askpass-context tagging when
//!   `piggy agent` returns to the user path.
//! - #59 — restore probe-loop PIN-clearing in `piggy agent`.

mod fallback;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "piggy",
    bin_name = "piggy",
    about = "PIV-encrypted password store",
    version,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Password-store commands (init/show/find/grep/insert/edit/generate/rm/mv/cp/git).
    Pass(PassArgs),
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

#[derive(Args, Debug)]
#[command(arg_required_else_help = true, disable_help_subcommand = true)]
struct PassArgs {
    #[command(subcommand)]
    cmd: PassCommand,
}

/// Each variant captures `rest` with `trailing_var_arg` +
/// `allow_hyphen_values` so per-command flags (e.g. `-c`, `--multiline`,
/// `-r`) reach `piggy.sh`'s `getopt` blocks untouched. Clap is only
/// responsible for matching the subcommand name and any of its visible
/// aliases.
#[derive(Subcommand, Debug)]
enum PassCommand {
    /// Initialize a new password store.
    Init {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// List or show a password.
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
    /// Manage recipients in `.piggy-ids` (list/add/remove/sync).
    Recipients {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Pass(args) => match args.cmd {
            PassCommand::Init { rest } => fallback::exec_bash("init", &rest),
            PassCommand::Show { rest } => fallback::exec_bash("show", &rest),
            PassCommand::Find { rest } => fallback::exec_bash("find", &rest),
            PassCommand::Grep { rest } => fallback::exec_bash("grep", &rest),
            PassCommand::Insert { rest } => fallback::exec_bash("insert", &rest),
            PassCommand::Edit { rest } => fallback::exec_bash("edit", &rest),
            PassCommand::Generate { rest } => fallback::exec_bash("generate", &rest),
            PassCommand::Rm { rest } => fallback::exec_bash("rm", &rest),
            PassCommand::Mv { rest } => fallback::exec_bash("mv", &rest),
            PassCommand::Cp { rest } => fallback::exec_bash("cp", &rest),
            PassCommand::Git { rest } => fallback::exec_bash("git", &rest),
            PassCommand::Recipients { rest } => fallback::exec_bash("recipients", &rest),
        },

        Command::Help { rest } => fallback::exec_bash("help", &rest),
        Command::Version { rest } => fallback::exec_bash("version", &rest),

        Command::Agent { rest } => fallback::exec_pivy("agent", &rest),
        Command::Box { rest } => fallback::exec_pivy("box", &rest),
        Command::Tool { rest } => fallback::exec_pivy("tool", &rest),
        Command::Ca { rest } => fallback::exec_pivy("ca", &rest),
        Command::Luks { rest } => fallback::exec_pivy("luks", &rest),
        Command::Zfs { rest } => fallback::exec_pivy("zfs", &rest),

        Command::Pivy { tool, rest } => match tool {
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
