//! Top-level `piggy` binary.
//!
//! Dispatch layout (top-level argv is parsed entirely by clap):
//!
//! 1. `piggy pass <X>` — every password-store subcommand is a native
//!    Rust handler under `crates/piggy/src/`. There is no bash hop.
//!    Each module mirrors its bash predecessor `cmd_*` in
//!    `src/piggy.sh` (now retired); see the per-module docstrings for
//!    the line-by-line provenance. Per-subcommand argv parsing is
//!    done in the handler; clap captures all trailing argv via
//!    `trailing_var_arg + allow_hyphen_values`.
//! 2. Top-level `help` is the native [`usage`] module — the pass-style
//!    banner ported from `cmd_usage`. `version` is a native Rust
//!    handler ([`version::run`]) emitting the eng-versioning(7)
//!    format; both live outside the `pass` namespace.
//! 3. `box` runs piggy's **Rust** re-implementation (`piggy::cmd::pivy_box::run`)
//!    for the subcommands it handles (`stream encrypt`/`decrypt`,
//!    `tpl create`/`show`) — restoring the agentless direct-PCSC decrypt
//!    that C `pivy-box` lacks (piggy#57). Subcommands it doesn't handle
//!    (`tpl edit` + the rest of the pivy-box surface) fall back to C
//!    `pivy-box` via [`fallback::exec_pivy`], so `piggy box` is a superset.
//! 4. C-pivy passthroughs — `agent`/`tool`/`ca`/`luks`/`zfs` `exec(2)` the
//!    matching `pivy-*` binary from `$PATH` via [`fallback::exec_pivy`]
//!    (`agent` → `pivy-agent`, `tool` → `pivy-tool`, `ca` → `pivy-ca`,
//!    `luks` → `pivy-luks`, `zfs` → `pivy-zfs`). `piggy pivy <X>` is the
//!    explicit escape hatch — `piggy pivy box` always reaches C `pivy-box`
//!    even though `piggy box` runs the Rust impl.
//!
//! Bare `piggy` and bare `piggy pass` both print clap help (no implicit
//! `cmd_show ""`); `arg_required_else_help` handles that on the top-level
//! `Cli` and the nested `PassArgs`.
//!
//! The Rust `agent` re-implementation (`cmd::agent`) is ON the dispatch
//! path: `piggy agent` runs it (piggy#58), prompting for the PIN on demand
//! via SSH_ASKPASS and clearing it on a card-presence probe loop (piggy#59),
//! atop the PC/SC transactions from #56. This is a clean cutover to the Rust
//! flag surface (e.g. `-i` prints keys and exits here, unlike C's foreground
//! mode); the C `pivy-agent` and its C-only features (`-C`, `-K`,
//! `install-service`, …) stay reachable via `piggy pivy agent`.

mod copy_move;
mod crypt;
mod edit;
mod fallback;
mod find;
mod generate;
mod git;
mod git_ops;
mod grep;
mod init;
mod insert;
mod internal_clipboard_restore;
mod platform;
mod recipients;
mod reencrypt;
mod rm;
mod show;
mod show_batch;
mod store;
mod usage;
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
    /// Print the pass-style usage text.
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
    /// piggy-ids. Historically invoked by the bash `reencrypt_path`
    /// shim; now reached only from in-process callers (`init` etc.)
    /// but still exposed as a subcommand for backward compat and for
    /// out-of-tree integrations. Hidden from `--help`.
    #[command(name = "internal-reencrypt-path", hide = true)]
    InternalReencryptPath {
        /// Directory under the store to walk.
        dir: PathBuf,
    },
    /// Internal: deferred-restore clipboard worker spawned by
    /// `show -c`. Reads a serialized ClipPlan from stdin, sleeps
    /// `clip_time`, restores the prior clipboard contents iff still
    /// matching, then exits. The parent process exec's this with
    /// argv0 = `sleep_argv0` so subsequent `clip` calls can `pkill -f
    /// "^<argv0>"` stale workers. Not a user-facing command. Hidden
    /// from `--help`.
    #[command(name = "internal-clipboard-restore", hide = true)]
    InternalClipboardRestore,
}

#[derive(Args, Debug)]
#[command(arg_required_else_help = true, disable_help_subcommand = true)]
struct PassArgs {
    #[command(subcommand)]
    cmd: PassCommand,
}

/// Each variant captures `rest` with `trailing_var_arg` +
/// `allow_hyphen_values` so per-command flags (e.g. `-c`, `--multiline`,
/// `-r`) reach the native handler's argv parser untouched. Clap is only
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
    /// Uses clap arg parsing (plain `subpath` positional, no
    /// `trailing_var_arg` rest) so `--help` works and `--` is not a
    /// passthrough — historically this differed from the bash-bound
    /// handlers that captured everything verbatim; that distinction
    /// no longer matters post-#96 but the explicit clap arg is kept.
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
        // Each `pass` subcommand is wrapped in `stats::timed_pass` so it
        // emits `piggy.pass.<cmd>.<result>` + duration telemetry (stats-me,
        // best-effort/opt-in). `recipients list-available` is an exec-to-C
        // passthrough that never returns, so it can't be timed.
        Command::Pass(args) => match args.cmd {
            PassCommand::Init { rest } => {
                std::process::exit(piggy::stats::timed_pass("init", || init::run(&rest)))
            }
            PassCommand::Show { rest } => {
                std::process::exit(piggy::stats::timed_pass("show", || show::run(&rest)))
            }
            PassCommand::Find { rest } => {
                std::process::exit(piggy::stats::timed_pass("find", || find::run(&rest)))
            }
            PassCommand::Grep { rest } => {
                std::process::exit(piggy::stats::timed_pass("grep", || grep::run(&rest)))
            }
            PassCommand::Insert { rest } => {
                std::process::exit(piggy::stats::timed_pass("insert", || insert::run(&rest)))
            }
            PassCommand::Edit { rest } => {
                std::process::exit(piggy::stats::timed_pass("edit", || edit::run(&rest)))
            }
            PassCommand::Generate { rest } => {
                std::process::exit(piggy::stats::timed_pass("generate", || {
                    generate::run(&rest)
                }))
            }
            PassCommand::Rm { rest } => {
                std::process::exit(piggy::stats::timed_pass("rm", || rm::run(&rest)))
            }
            PassCommand::Mv { rest } => std::process::exit(piggy::stats::timed_pass("mv", || {
                copy_move::run_move(&rest)
            })),
            PassCommand::Cp { rest } => std::process::exit(piggy::stats::timed_pass("cp", || {
                copy_move::run_copy(&rest)
            })),
            PassCommand::Git { rest } => {
                std::process::exit(piggy::stats::timed_pass("git", || git::run(&rest)))
            }
            PassCommand::Recipients(args) => match args.cmd {
                RecipientsCommand::List { rest } => {
                    std::process::exit(piggy::stats::timed_pass("recipients_list", || {
                        recipients::list(&rest)
                    }))
                }
                RecipientsCommand::ListAvailable { rest } => {
                    fallback::exec_piggy_ids("list-available", &rest)
                }
                RecipientsCommand::Add { rest } => {
                    std::process::exit(piggy::stats::timed_pass("recipients_add", || {
                        recipients::add(&rest)
                    }))
                }
                RecipientsCommand::Remove { rest } => {
                    std::process::exit(piggy::stats::timed_pass("recipients_remove", || {
                        recipients::remove(&rest)
                    }))
                }
                RecipientsCommand::Sync { rest } => {
                    std::process::exit(piggy::stats::timed_pass("recipients_sync", || {
                        recipients::sync(&rest)
                    }))
                }
            },
            PassCommand::Verify { subpath } => {
                std::process::exit(piggy::stats::timed_pass("verify", || {
                    verify::run(subpath.as_deref())
                }))
            }
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
                std::process::exit(piggy::stats::timed_pass("show_batch", move || {
                    show_batch::run(mapped)
                }))
            }
        },

        Command::List { rest } => fallback::exec_piggy_ids("list-all", &rest),
        Command::Help { .. } => std::process::exit(usage::run()),
        Command::Version { .. } => std::process::exit(version::run()),

        // `agent` runs the Rust impl (piggy#58): a PIV-backed SSH agent that
        // prompts for the PIN on demand via SSH_ASKPASS and clears it on a
        // card-presence probe loop (piggy#59). Unlike `box`, this is a clean
        // cutover — `piggy agent` uses the Rust flag surface, not the C one
        // (notably `-i` = print-keys-and-exit here, NOT C's foreground mode).
        // C-only features (confirm `-C`, `-K` CAK, `install-service`, …) stay
        // reachable via the `piggy pivy agent` passthrough.
        Command::Agent { rest } => {
            let mut argv = vec!["piggy".to_string(), "agent".to_string()];
            argv.extend(rest);
            std::process::exit(piggy::cmd::agent::run(argv));
        }
        // `box` runs the Rust impl (restores agentless direct-PCSC decrypt,
        // piggy#57); subcommands it doesn't handle return None and fall back
        // to C `pivy-box`, so `piggy box` stays a superset.
        Command::Box { rest } => match piggy::cmd::pivy_box::run(&rest) {
            Some(code) => std::process::exit(code),
            None => fallback::exec_pivy("box", &rest),
        },
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
        Command::InternalClipboardRestore => std::process::exit(internal_clipboard_restore::run()),
    }
}
