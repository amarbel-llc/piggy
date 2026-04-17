//! `piggy agent` subcommand — PIV-backed SSH signing agent.
//!
//! Historically this was the standalone `pivy-agent` (rust) binary. It has
//! been absorbed into `piggy` as a subcommand; the argv handling and the
//! async body are lifted verbatim from the original `pivy-agent/src/main.rs`
//! with only the clap parser and the runtime bootstrapping adjusted.

use clap::Parser;
use ssh_agent_lib::agent::listen;
use tokio::net::UnixListener;

mod card;
mod session;

use session::{CachedKey, PiggyAgent};

/// Clap arguments for `piggy agent`.
#[derive(Parser, Debug)]
#[command(name = "piggy agent", about = "PIV-backed SSH agent")]
pub struct AgentArgs {
    /// GUID of the PIV card to use
    #[arg(short = 'g')]
    pub guid: Option<String>,

    /// All-card mode: expose keys from all PIV cards
    #[arg(short = 'A')]
    pub all_cards: bool,

    /// Socket path for the agent
    #[arg(short = 'a')]
    pub socket: Option<String>,

    /// Slot spec: comma-separated list of slots to expose (e.g. "9a,9e")
    #[arg(short = 'S')]
    pub slot_spec: Option<String>,

    /// Kill a running agent (reads SSH_AGENT_PID)
    #[arg(short = 'k')]
    pub kill: bool,

    /// Debug level (repeat for more)
    #[arg(short = 'd', action = clap::ArgAction::Count)]
    pub debug: u8,

    /// Foreground debug mode
    #[arg(short = 'D')]
    pub foreground_debug: bool,

    /// Print key info and exit
    #[arg(short = 'i')]
    pub info: bool,

    /// Generate Bourne shell commands on stdout
    #[arg(short = 's')]
    pub sh_format: bool,

    /// Generate C-shell commands on stdout
    #[arg(short = 'c')]
    pub csh_format: bool,

    /// Command to execute with agent env set
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// Entry point for `piggy agent ...`.
///
/// `full_argv` is the full argv as passed to `piggy`, including `args[0]`
/// (program name) and `args[1]` (`"agent"`). We rebuild the clap-facing argv
/// with a synthetic program name so errors and `--help` display as
/// `piggy agent` instead of `piggy`.
pub fn run(full_argv: Vec<String>) -> i32 {
    let agent_argv: Vec<String> = std::iter::once("piggy agent".to_string())
        .chain(full_argv.into_iter().skip(2))
        .collect();

    let cli = match AgentArgs::try_parse_from(&agent_argv) {
        Ok(cli) => cli,
        Err(e) => {
            // clap prints help/errors itself; match its exit codes.
            e.exit();
        }
    };

    if cli.kill {
        return match kill_agent() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("piggy agent: {}", e);
                1
            }
        };
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start tokio runtime");

    match rt.block_on(run_async(cli)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy agent: {}", e);
            1
        }
    }
}

async fn run_async(cli: AgentArgs) -> Result<(), Box<dyn std::error::Error>> {
    let filter = match cli.debug {
        0 if cli.foreground_debug => "piggy=debug",
        0 => "piggy=info",
        1 => "piggy=debug",
        _ => "piggy=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // Parse slot spec if provided
    let allowed_slots: Option<Vec<u8>> = cli.slot_spec.as_ref().map(|spec| {
        spec.split(',')
            .filter_map(|s| u8::from_str_radix(s.trim(), 16).ok())
            .collect()
    });

    // Enumerate PIV tokens and cache their keys.
    // If PCSC is unavailable (e.g. no pcscd), start with zero keys.
    let (tokens, _ctx_available) = match piggy_piv::PivContext::new() {
        Ok(ctx) => match ctx.enumerate_tokens() {
            Ok(tokens) => (tokens, true),
            Err(e) => {
                tracing::warn!("Failed to enumerate PIV tokens: {e}");
                (Vec::new(), false)
            }
        },
        Err(e) => {
            tracing::warn!("PCSC not available: {e}");
            (Vec::new(), false)
        }
    };

    let mut cached_keys = Vec::new();
    let mut primary_guid = None;
    for token in &tokens {
        let guid = token.guid().clone();

        if let Some(ref filter_guid) = cli.guid {
            if guid.to_hex() != *filter_guid && guid.short_id() != *filter_guid {
                continue;
            }
        }

        if primary_guid.is_none() {
            primary_guid = Some(guid.clone());
        }

        let slots = token.read_all_slots().unwrap_or_default();
        for slot in &slots {
            // Filter by slot spec
            if let Some(ref allowed) = allowed_slots {
                if !allowed.contains(&slot.id()) {
                    continue;
                }
            }

            cached_keys.push(CachedKey {
                guid: guid.clone(),
                reader_name: token.reader_name().to_string(),
                slot_id: slot.id(),
                algorithm: slot.algorithm(),
                public_key: slot.public_key().key_data().clone(),
                comment: format!("PIV_slot_{:02X} {}", slot.id(), guid.short_id()),
            });
        }

        if !cli.all_cards {
            break;
        }
    }

    // Handle -i (info mode)
    if cli.info {
        if cached_keys.is_empty() {
            eprintln!("No PIV keys found");
        } else {
            for key in &cached_keys {
                let pubkey: ssh_key::PublicKey = key.public_key.clone().into();
                println!(
                    "{:02X} {:?} {}",
                    key.slot_id,
                    key.algorithm,
                    pubkey.to_openssh().unwrap_or_default()
                );
            }
        }
        return Ok(());
    }

    tracing::info!("Loaded {} keys from PIV tokens", cached_keys.len());

    // Determine socket path
    let socket_path = cli.socket.unwrap_or_else(|| {
        let dir = std::env::temp_dir().join(format!("piggy-agent.{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        dir.join("agent.sock").to_string_lossy().into_owned()
    });

    // Detect shell output format
    let use_csh = cli.csh_format
        || (!cli.sh_format && std::env::var("SHELL").map_or(false, |s| s.ends_with("csh")));

    if use_csh {
        println!("setenv SSH_AUTH_SOCK {};", socket_path);
        println!("setenv SSH_AGENT_PID {};", std::process::id());
        println!("echo Agent pid {};", std::process::id());
    } else {
        println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path);
        println!(
            "SSH_AGENT_PID={}; export SSH_AGENT_PID;",
            std::process::id()
        );
        println!("echo Agent pid {};", std::process::id());
    }

    let listener = UnixListener::bind(&socket_path)?;
    let agent = PiggyAgent::new(cached_keys);

    // Spawn card probe loop if we have a primary card
    if let Some(guid) = primary_guid {
        let pin_handle = agent.pin_handle();
        tokio::spawn(card::probe_loop(guid, pin_handle));
    }

    // If a command was given, run it with the agent env, then exit
    if !cli.command.is_empty() {
        let agent_handle = tokio::spawn(listen(listener, agent));

        let status = tokio::process::Command::new(&cli.command[0])
            .args(&cli.command[1..])
            .env("SSH_AUTH_SOCK", &socket_path)
            .env("SSH_AGENT_PID", std::process::id().to_string())
            .status()
            .await?;

        // Clean up
        agent_handle.abort();
        let _ = std::fs::remove_file(&socket_path);

        std::process::exit(status.code().unwrap_or(1));
    }

    // Clean up socket on exit
    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = std::fs::remove_file(&socket_path_clone);
        std::process::exit(0);
    });

    listen(listener, agent).await?;

    Ok(())
}

fn kill_agent() -> Result<(), Box<dyn std::error::Error>> {
    let pid_str = std::env::var("SSH_AGENT_PID")
        .map_err(|_| "SSH_AGENT_PID not set")?;
    let pid: i32 = pid_str.parse().map_err(|_| "invalid SSH_AGENT_PID")?;

    #[cfg(unix)]
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    println!("unset SSH_AUTH_SOCK;");
    println!("unset SSH_AGENT_PID;");
    println!("echo Agent pid {} killed;", pid);

    Ok(())
}
