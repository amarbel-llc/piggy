//! Top-level `piggy` binary.
//!
//! Dispatch layout (top-level argv is parsed entirely by clap):
//!
//! 1. `piggy pass <X>` — every password-store subcommand (`init`, `show`,
//!    `find`, `grep`, `insert`, `edit`, `generate`, `rm`, `git`) lives
//!    under the `pass` namespace and `exec(2)`s into
//!    `piggy.sh <X> <rest...>` via [`fallback::exec_bash`]. The case
//!    statement at the bottom of `piggy.sh` does the second-level
//!    dispatch to the matching `cmd_*` function. Per-subcommand
//!    `getopt` parsing stays in bash; clap captures all trailing argv
//!    verbatim.
//! 2. Top-level `help` `exec_bash`es into piggy.sh's `cmd_usage` (the
//!    pass-style usage text). `version` is a native Rust handler
//!    (`version::run`) emitting the eng-versioning(7) format; both live
//!    outside the `pass` namespace.
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

mod copy_move;
mod fallback;
mod find;
mod git;
mod git_ops;
mod grep;
mod recipients;
mod reencrypt;
mod rm;
mod show_batch;
mod store;
mod verify;
mod version;

use std::path::PathBuf;

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
    /// Enumerate every populated PIV slot across all attached cards.
    ///
    /// Like `piggy pass recipients list-available` but also includes
    /// slots 9A (auth), 9C (signature), and 9E (card auth) — each with
    /// its own slot-semantic markl purpose (`piggy-piv_auth-v1`,
    /// `piggy-piv_sig-v1`, `piggy-piv_card_auth-v1`). Recipient-eligible
    /// slots (9D + retired 0x82..=0x95) keep the existing
    /// `piggy-recipient-v1` purpose.
    List {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Print piggy.sh's pass-style usage text.
    Help {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Print piggy's version: a `piggy <version>+<commit>` self-line plus a
    /// table of pinned downstream components. See eng-versioning(7).
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
    /// Internal: re-encrypt every entry under DIR to the nearest
    /// piggy-ids. Invoked by piggy.sh's `reencrypt_path` shim; not a
    /// user-facing command. Hidden from `--help`.
    #[command(name = "internal-reencrypt-path", hide = true)]
    InternalReencryptPath {
        /// Directory under the store to walk.
        dir: PathBuf,
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
    /// Manage recipients in `piggy-ids` (list/add/remove/sync).
    Recipients(RecipientsArgs),
    /// Decrypt every entry under the store (or under SUBPATH) and
    /// report each one as ok / not ok in tree form.
    ///
    /// Unlike the other `pass` subcommands this is handled in Rust and
    /// does not delegate to piggy.sh, so plain clap flag parsing
    /// applies (`--help` works, no `--` passthrough).
    Verify {
        /// Optional sub-directory within the store to limit the walk.
        subpath: Option<String>,
    },
    /// Decrypt N eboxes in a single PIV-card session (one PIN prompt)
    /// and emit per-ebox progress per RFC 0005.
    ///
    /// Selects the first attached PIV card whose slot can decrypt the
    /// first ebox in the batch, then reuses that (card, slot) for
    /// every remaining ebox. Pre-flight failures (no card; no usable
    /// slot) bail out before any PIN prompt. See
    /// `docs/rfcs/0005-pass-show-batch-ndjson.md` and piggy#121.
    #[command(name = "show-batch")]
    ShowBatch(ShowBatchCmdArgs),
}

#[derive(Args, Debug)]
struct ShowBatchCmdArgs {
    /// Pass-names to decrypt, in source order. May be empty when
    /// `--names-from` is set.
    names: Vec<String>,
    /// File containing additional pass-names, one per line. Lines are
    /// trimmed; blank lines and `#`-prefixed comments are ignored.
    /// Appended to any positional `names`.
    #[arg(long = "names-from", value_name = "FILE")]
    names_from: Option<PathBuf>,
    /// Directory under which to write `<out-dir>/<pass-name>` for each
    /// successfully decrypted ebox. Defaults to the current working
    /// directory.
    #[arg(long = "out-dir", value_name = "DIR")]
    out_dir: Option<PathBuf>,
    /// Output format. `human` is implementation-defined and intended
    /// for terminal use; `ndjson` is normatively pinned by RFC 0005
    /// and is what bridging tooling (eng's `2-piggy.bash`) consumes.
    #[arg(long, value_enum, default_value_t = ShowBatchFormat::Human)]
    format: ShowBatchFormat,
    /// Wipe partial outputs in `--out-dir` if any decrypt fails.
    /// Default: leave partials in place.
    #[arg(long = "all-or-nothing")]
    all_or_nothing: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
enum ShowBatchFormat {
    Ndjson,
    Human,
}

#[derive(Args, Debug)]
struct RecipientsArgs {
    #[command(subcommand)]
    cmd: RecipientsCommand,
}

#[derive(Subcommand, Debug)]
enum RecipientsCommand {
    /// Print recipients in the relevant piggy-ids, one per line.
    List {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Enumerate attached PIV cards and print one record per
    /// populated recipient-eligible slot. Delegates to
    /// `piggy-ids list-available`.
    #[command(name = "list-available")]
    ListAvailable {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Append recipients to piggy-ids and re-encrypt.
    Add {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Remove recipients (matched by full markl ID) and re-encrypt.
    Remove {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
    /// Replace piggy-ids with another file's contents (idempotent).
    Sync {
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
            PassCommand::Find { rest } => std::process::exit(find::run(&rest)),
            PassCommand::Grep { rest } => std::process::exit(grep::run(&rest)),
            PassCommand::Insert { rest } => fallback::exec_bash("insert", &rest),
            PassCommand::Edit { rest } => fallback::exec_bash("edit", &rest),
            PassCommand::Generate { rest } => fallback::exec_bash("generate", &rest),
            PassCommand::Rm { rest } => std::process::exit(rm::run(&rest)),
            PassCommand::Mv { rest } => std::process::exit(copy_move::run_move(&rest)),
            PassCommand::Cp { rest } => std::process::exit(copy_move::run_copy(&rest)),
            PassCommand::Git { rest } => std::process::exit(git::run(&rest)),
            PassCommand::Recipients(args) => match args.cmd {
                RecipientsCommand::List { rest } => std::process::exit(recipients::list(&rest)),
                RecipientsCommand::ListAvailable { rest } => {
                    fallback::exec_piggy_ids("list-available", &rest)
                }
                RecipientsCommand::Add { rest } => std::process::exit(recipients::add(&rest)),
                RecipientsCommand::Remove { rest } => std::process::exit(recipients::remove(&rest)),
                RecipientsCommand::Sync { rest } => std::process::exit(recipients::sync(&rest)),
            },
            PassCommand::Verify { subpath } => std::process::exit(verify::run(subpath.as_deref())),
            PassCommand::ShowBatch(args) => {
                let mapped = show_batch::ShowBatchArgs {
                    names: args.names,
                    names_from: args.names_from,
                    out_dir: args
                        .out_dir
                        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into())),
                    format: match args.format {
                        ShowBatchFormat::Ndjson => show_batch::OutputFormat::Ndjson,
                        ShowBatchFormat::Human => show_batch::OutputFormat::Human,
                    },
                    all_or_nothing: args.all_or_nothing,
                };
                std::process::exit(show_batch::run(mapped))
            }
        },

        Command::List { rest } => fallback::exec_piggy_ids("list-all", &rest),
        Command::Help { rest } => fallback::exec_bash("help", &rest),
        Command::Version { .. } => std::process::exit(version::run()),

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

        Command::InternalReencryptPath { dir } => std::process::exit(reencrypt::run(&dir)),
    }
}
