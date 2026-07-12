//! `piggy agent` subcommand — PIV-backed SSH signing agent.
//!
//! Historically this was the standalone `pivy-agent` (rust) binary. It has
//! been absorbed into `piggy` as a subcommand; the argv handling and the
//! async body are lifted verbatim from the original `pivy-agent/src/main.rs`
//! with only the clap parser and the runtime bootstrapping adjusted.

use std::sync::Arc;

use clap::Parser;
use ssh_agent_lib::agent::listen;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

mod cak;
mod card;
mod session;
// pub: `agent_client::probe_upstream_status` (the `piggy health` side)
// shares the UPSTREAM_STATUS_EXT name + UpstreamStatus payload type.
pub mod upstream;

use session::{CachedKey, PiggyAgent};
use upstream::{UpstreamPool, parse_upstream_specs};

/// Clap arguments for `piggy agent`.
#[derive(Parser, Debug)]
#[command(name = "piggy agent", about = "PIV-backed SSH agent")]
pub struct AgentArgs {
    /// GUID of the PIV card to use
    #[arg(short = 'g')]
    pub guid: Option<String>,

    /// All-card mode: expose keys from all PIV cards
    #[arg(short = 'A', conflicts_with = "guid")]
    pub all_cards: bool,

    /// Card Authentication Key: an SSH public key (e.g.
    /// "ecdsa-sha2-nistp256 AAAA…"). When set, only cards whose slot 9E
    /// answers a challenge with this key are exposed — an anti-card-swap
    /// check matching the C pivy-agent's -K (piggy#143).
    #[arg(short = 'K')]
    pub cak: Option<String>,

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

    /// Upstream SSH agent to proxy, as NAME=SOCKET_PATH (repeatable).
    /// Upstream keys are offered after piggy's native PIV keys; sign
    /// requests for them are routed to the owning upstream (piggy#215).
    #[arg(long = "upstream", value_name = "NAME=PATH")]
    pub upstream: Vec<String>,

    /// Per-upstream request timeout in seconds (connect/list/sign)
    #[arg(long = "agent-timeout", value_name = "SECONDS", default_value_t = 5)]
    pub agent_timeout: u64,

    /// Route add_identity (ssh-add) requests to this named --upstream;
    /// without it, adds are refused (piggy's native keys live on the
    /// card — an added software key needs a software agent to go to)
    #[arg(long = "add-new-keys-to", value_name = "NAME", requires = "upstream")]
    pub add_new_keys_to: Option<String>,

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

    let filter = match cli.debug {
        0 if cli.foreground_debug => "piggy=debug",
        0 => "piggy=info",
        1 => "piggy=debug",
        _ => "piggy=trace",
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let allowed_slots: Option<Vec<u8>> = match cli
        .slot_spec
        .as_ref()
        .map(|spec| {
            spec.split(',')
                .map(|s| {
                    let s = s.trim();
                    let slot = u8::from_str_radix(s, 16)
                        .map_err(|_| format!("invalid slot in -S spec: {:?}", s))?;
                    if !piggy_piv::slot::is_valid_piv_slot(slot) {
                        return Err(format!(
                            "unknown PIV slot 0x{slot:02x} in -S spec \
                             (valid: 9a, 9c, 9d, 9e, 82-95, f9)"
                        ));
                    }
                    Ok(slot)
                })
                .collect::<Result<Vec<u8>, _>>()
        })
        .transpose()
    {
        Ok(slots) => slots,
        Err(e) => {
            eprintln!("piggy agent: {}", e);
            return 1;
        }
    };

    // Parse the optional CAK (Card Authentication Key, piggy#143). Invalid
    // input is a hard startup error — better than silently exposing keys.
    let cak: Option<ssh_key::public::KeyData> = match cli.cak.as_deref() {
        Some(s) => match ssh_key::PublicKey::from_openssh(s) {
            Ok(pk) => Some(pk.key_data().clone()),
            Err(e) => {
                eprintln!("piggy agent: invalid -K Card Authentication Key: {e}");
                return 1;
            }
        },
        None => None,
    };

    // Build the upstream proxy pool (piggy#215). Malformed specs,
    // duplicate names, and an unresolvable --add-new-keys-to are
    // startup errors, not runtime degradation.
    let upstreams = match parse_upstream_specs(&cli.upstream) {
        Ok(ups) => ups,
        Err(e) => {
            eprintln!("piggy agent: {e}");
            return 1;
        }
    };
    let upstream_pool: Option<UpstreamPool> = if upstreams.is_empty() {
        None
    } else {
        tracing::info!(
            upstreams = %upstreams
                .iter()
                .map(|u| u.name.as_str())
                .collect::<Vec<_>>()
                .join(","),
            "proxying upstream agents"
        );
        let pool = UpstreamPool::new(upstreams, std::time::Duration::from_secs(cli.agent_timeout));
        match cli.add_new_keys_to.as_deref() {
            Some(name) => match pool.with_add_new_keys_to(name) {
                Ok(pool) => Some(pool),
                Err(e) => {
                    eprintln!("piggy agent: {e}");
                    return 1;
                }
            },
            None => Some(pool),
        }
    };

    // The full set of inputs that select and shape the key load. Bundled so the
    // piggy#175 recovery loop can re-run the exact same enumeration later.
    let config = KeyLoadConfig {
        guid_filter: cli.guid.clone(),
        all_cards: cli.all_cards,
        allowed_slots,
        cak,
    };

    let (cached_keys, primary_guid) = load_cached_keys_from_cards(&config);

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
        return 0;
    }

    tracing::info!("Loaded {} keys from PIV tokens", cached_keys.len());

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("piggy agent: failed to start async runtime: {}", e);
            return 1;
        }
    };

    match rt.block_on(run_async(
        cli,
        cached_keys,
        primary_guid,
        config,
        upstream_pool,
    )) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy agent: {}", e);
            1
        }
    }
}

/// Inputs that select and shape the PIV key load (and re-load): the GUID
/// filter, all-cards mode, the optional slot whitelist, and the optional CAK.
/// Owned by `run` and threaded into `run_async` so the piggy#175 recovery loop
/// can re-run the identical enumeration after a transient startup PCSC failure.
#[derive(Clone)]
struct KeyLoadConfig {
    guid_filter: Option<String>,
    all_cards: bool,
    allowed_slots: Option<Vec<u8>>,
    cak: Option<ssh_key::public::KeyData>,
}

/// Enumerate PIV tokens, logging and degrading to an empty list on any PCSC
/// failure (no card, denied access, cold pcscd). Both the startup load and the
/// recovery loop go through here so they treat a transient failure identically.
fn enumerate_tokens_or_empty() -> Vec<piggy_piv::PivToken> {
    match piggy_piv::PivContext::new() {
        Ok(ctx) => ctx.enumerate_tokens().unwrap_or_else(|e| {
            tracing::warn!("Failed to enumerate PIV tokens: {e}");
            Vec::new()
        }),
        Err(e) => {
            tracing::warn!("PCSC not available: {e}");
            Vec::new()
        }
    }
}

/// Build the cached key set (and the primary card's GUID) from already-
/// enumerated `tokens`, applying the GUID filter, slot whitelist, CAK
/// anti-swap, and all-cards/first-card selection from `config`. Returns an
/// empty vec / `None` GUID when no matching card is reachable.
fn build_cached_keys(
    tokens: &[piggy_piv::PivToken],
    config: &KeyLoadConfig,
) -> (Vec<CachedKey>, Option<piggy_piv::Guid>) {
    let mut cached_keys = Vec::new();
    let mut primary_guid = None;
    for token in tokens {
        let guid = token.guid().clone();

        if let Some(ref filter_guid) = config.guid_filter {
            if guid.to_hex() != *filter_guid && guid.short_id() != *filter_guid {
                continue;
            }
        }

        // Read this token's keys BEFORE the CAK check. CAK auth opens its own
        // card connection and signs; a co-resident reset on disconnect can
        // disturb the live enumerated connection this read uses (observed on
        // fibby). Read first, then discard the keys if the card fails CAK.
        let slots = token.read_all_slots().unwrap_or_default();
        let mut token_keys = Vec::new();
        for slot in &slots {
            if let Some(ref allowed) = config.allowed_slots {
                if !allowed.contains(&slot.id()) {
                    continue;
                }
            }

            token_keys.push(CachedKey {
                guid: guid.clone(),
                reader_name: token.reader_name().to_string(),
                slot_id: slot.id(),
                algorithm: slot.algorithm(),
                public_key: slot.public_key().key_data().clone(),
                comment: format!("PIV_slot_{:02X} {}", slot.id(), guid.short_id()),
            });
        }

        // CAK anti-swap (piggy#143): if a CAK is configured, only expose a
        // card whose slot 9E authenticates against it.
        if let Some(ref cak) = config.cak {
            if cak::authenticate(&guid, cak) {
                tracing::info!(guid = %guid.short_id(), "CAK authentication succeeded");
            } else {
                tracing::warn!(
                    guid = %guid.short_id(),
                    "CAK authentication failed; not exposing this card's keys"
                );
                continue;
            }
        }

        if primary_guid.is_none() {
            primary_guid = Some(guid.clone());
        }
        cached_keys.extend(token_keys);

        if !config.all_cards {
            break;
        }
    }
    (cached_keys, primary_guid)
}

/// Enumerate the cards and build the cached key set in one shot. Used for the
/// startup load and re-run each tick by the piggy#175 recovery loop.
fn load_cached_keys_from_cards(
    config: &KeyLoadConfig,
) -> (Vec<CachedKey>, Option<piggy_piv::Guid>) {
    build_cached_keys(&enumerate_tokens_or_empty(), config)
}

async fn run_async(
    cli: AgentArgs,
    cached_keys: Vec<CachedKey>,
    primary_guid: Option<piggy_piv::Guid>,
    config: KeyLoadConfig,
    upstream_pool: Option<UpstreamPool>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Determine socket path
    let socket_path = match cli.socket {
        Some(s) => s,
        None => {
            let dir = std::env::temp_dir().join(format!("piggy-agent.{}", std::process::id()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)?;
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(&dir)?;
            }
            dir.join("agent.sock").to_string_lossy().into_owned()
        }
    };

    // Detect shell output format
    let use_csh = cli.csh_format
        || (!cli.sh_format && std::env::var("SHELL").is_ok_and(|s| s.ends_with("csh")));

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
    // piggy#215: with --upstream flags, proxy the named agents for keys
    // piggy does not serve natively. Without them the pool stays empty
    // and the agent behaves exactly as before.
    let agent = match upstream_pool {
        Some(pool) => agent.with_upstream_pool(pool),
        None => agent,
    };

    // Spawn the card-presence probe loop (piggy#59): polls the primary card
    // every PROBE_INTERVAL (60s) and clears the cached PIN after
    // PROBE_FAIL_LIMIT (3) consecutive failures, so an unattended agent drops
    // its PIN shortly after the card is removed. This is piggy-specific — the
    // C pivy-agent has its own card-presence handling with different timing.
    let pin_handle = agent.pin_handle();
    match primary_guid {
        Some(guid) => spawn_probe_loop(guid, pin_handle, config.cak.clone()),
        None => {
            // piggy#175: 0 keys at startup almost always means a *transient*
            // PCSC failure (a polkit-gated, socket-activated pcscd that denied
            // the agent's first call before the logind session was
            // polkit-`active`, or a card not yet inserted). The old code
            // spawned no loop here, leaving the agent wedged at 0 keys until a
            // manual restart. Spawn a recovery loop that re-enumerates until a
            // card is reachable, adopts its keys into the live set, then hands
            // off to the normal probe loop — so the agent self-heals.
            tracing::warn!("0 keys loaded at startup; spawning PIV recovery loop (piggy#175)");
            let keys_handle = agent.keys_handle();
            let cak_for_probe = config.cak.clone();
            tokio::spawn(async move {
                let guid = card::recovery_loop_with(
                    keys_handle,
                    move || load_cached_keys_from_cards(&config),
                    // piggy#179: confirm the recovered GUID round-trips through
                    // the sign-path's own reconnect helper before adopting its
                    // keys, so a card that enumerates but can't sign is not
                    // served as live keys.
                    |guid: &piggy_piv::Guid| {
                        session::reconnect_to_token(guid)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    },
                    card::RECOVERY_INTERVAL,
                )
                .await;
                spawn_probe_loop(guid, pin_handle, cak_for_probe);
            });
        }
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

/// Spawn the card-presence PIN-clearing probe loop for `guid`, choosing the
/// CAK-reauthenticating variant when a CAK is configured. Shared by the
/// card-present-at-startup path and the piggy#175 post-recovery handoff.
fn spawn_probe_loop(
    guid: piggy_piv::Guid,
    pin_handle: Arc<Mutex<Option<String>>>,
    cak: Option<ssh_key::public::KeyData>,
) {
    match cak {
        Some(cak) => {
            // CAK mode (piggy#143): the probe also re-runs the slot-9E
            // challenge each tick, so a mid-session card swap clears the PIN.
            tracing::info!(guid = %guid.short_id(), "spawning CAK-reauthenticating card probe loop");
            tokio::spawn(card::probe_loop_cak(guid, pin_handle, cak));
        }
        None => {
            tracing::info!(guid = %guid.short_id(), "spawning card-presence probe loop");
            tokio::spawn(card::probe_loop(guid, pin_handle));
        }
    }
}

fn kill_agent() -> Result<(), Box<dyn std::error::Error>> {
    let pid_str = std::env::var("SSH_AGENT_PID").map_err(|_| "SSH_AGENT_PID not set")?;
    let pid: i32 = pid_str.parse().map_err(|_| "invalid SSH_AGENT_PID")?;

    #[cfg(unix)]
    {
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        if rc != 0 {
            return Err(
                format!("kill({pid}, SIGTERM): {}", std::io::Error::last_os_error()).into(),
            );
        }
    }

    println!("unset SSH_AUTH_SOCK;");
    println!("unset SSH_AGENT_PID;");
    println!("echo Agent pid {} killed;", pid);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `command` is trailing_var_arg, so pin that the piggy#215 long
    /// flags parse as flags (not slurped into the command tail) and that
    /// values repeat/default as intended.
    #[test]
    fn agent_args_parse_upstream_flags() {
        let cli = AgentArgs::try_parse_from([
            "piggy agent",
            "-A",
            "--upstream",
            "soft=/tmp/s.sock",
            "--upstream",
            "launchd=/tmp/l.sock",
            "--agent-timeout",
            "7",
        ])
        .unwrap();
        assert_eq!(
            cli.upstream,
            vec!["soft=/tmp/s.sock", "launchd=/tmp/l.sock"]
        );
        assert_eq!(cli.agent_timeout, 7);
        assert!(cli.command.is_empty());
    }

    #[test]
    fn agent_args_default_no_upstreams_timeout_5() {
        let cli = AgentArgs::try_parse_from(["piggy agent", "-A"]).unwrap();
        assert!(cli.upstream.is_empty());
        assert_eq!(cli.agent_timeout, 5);
        assert!(cli.add_new_keys_to.is_none());
    }

    #[test]
    fn agent_args_add_new_keys_to_requires_an_upstream() {
        let err = AgentArgs::try_parse_from(["piggy agent", "--add-new-keys-to", "soft"]);
        assert!(
            err.is_err(),
            "--add-new-keys-to without --upstream must be rejected"
        );
        let ok = AgentArgs::try_parse_from([
            "piggy agent",
            "--upstream",
            "soft=/tmp/s.sock",
            "--add-new-keys-to",
            "soft",
        ])
        .unwrap();
        assert_eq!(ok.add_new_keys_to.as_deref(), Some("soft"));
    }
}
