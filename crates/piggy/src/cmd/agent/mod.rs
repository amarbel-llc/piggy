//! `piggy agent` subcommand — PIV-backed SSH signing agent.
//!
//! Historically this was the standalone `pivy-agent` (rust) binary. It has
//! been absorbed into `piggy` as a subcommand; the argv handling and the
//! async body are lifted verbatim from the original `pivy-agent/src/main.rs`
//! with only the clap parser and the runtime bootstrapping adjusted.

use clap::Parser;
use ssh_agent_lib::agent::listen;
use tokio::net::UnixListener;

mod cak;
mod card;
// pub: the holder's scope rules and bindings (FDR 0006 phase (d)).
pub mod holder;
mod listener;
pub mod peer;
// pub: `agent_client::probe_agent_mode` (the `piggy health` side) shares
// the AGENT_MODE_EXT name + AgentMode payload type.
pub mod mode;
mod pin_policy;
mod pins;
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

    /// Per-upstream request timeout in seconds (connect/list)
    #[arg(long = "agent-timeout", value_name = "SECONDS", default_value_t = 5)]
    pub agent_timeout: u64,

    /// Seconds a sign relayed to an upstream is waited for: it may sit
    /// behind a PIN dialog and a touch on the card's machine. A sign that
    /// times out is not tried on another upstream.
    #[arg(
        long = "sign-wait",
        value_name = "SECONDS",
        default_value_t = upstream::SIGN_UPSTREAM_WAIT.as_secs(),
        value_parser = clap::value_parser!(u64).range(1..=600)
    )]
    pub sign_wait: u64,

    /// Seconds a listing that finds every --upstream unreachable keeps
    /// redialing before it answers with a failure instead of an empty key
    /// list (piggy#333). Applies only when the agent has no native keys.
    #[arg(
        long = "upstream-grace",
        value_name = "SECONDS",
        default_value_t = upstream::DEFAULT_OUTAGE_GRACE.as_secs()
    )]
    pub upstream_grace: u64,

    /// Card-presence reconcile interval in seconds (piggy#244): how often the
    /// agent re-enumerates to drop a removed card's keys/PIN and adopt a
    /// newly-inserted card. Default 10; a removed card clears after ~3 ticks.
    #[arg(long = "probe-interval", value_name = "SECONDS")]
    pub probe_interval: Option<u64>,

    /// Poll-only card presence (piggy#255): opt OUT of the default
    /// event-driven presence watch and reconcile by --probe-interval polling
    /// only. Event-driven (a SCardGetStatusChange reader-state watch for
    /// near-instant hot-swap, piggy#248) is the DEFAULT as of #255; this is
    /// the escape hatch if it misbehaves on a host. Rejected under
    /// --proxy-only (a cardless agent runs no card loop either way).
    #[arg(long = "poll-only", conflicts_with = "proxy_only")]
    pub poll_only: bool,

    /// Route add_identity (ssh-add) requests to this named --upstream;
    /// without it, adds are refused (piggy's native keys live on the
    /// card — an added software key needs a software agent to go to)
    #[arg(long = "add-new-keys-to", value_name = "NAME", requires = "upstream")]
    pub add_new_keys_to: Option<String>,

    /// Proxy-only mode: serve NO native PIV keys — never touch PCSC, no
    /// card presence reconcile loop — and proxy everything to the
    /// --upstream agents. The remote-host role (eng#295): one stable
    /// piggy-agent socket fronting the forwarded, card-backed agents.
    /// Requires at least one --upstream; card-selection flags are
    /// meaningless here and rejected.
    #[arg(
        long = "proxy-only",
        requires = "upstream",
        conflicts_with_all = ["guid", "all_cards", "cak", "slot_spec", "info"]
    )]
    pub proxy_only: bool,

    /// Service unit / launchd label this agent runs under, relayed in the
    /// `agent-mode@piggy` self-report so `piggy health` probes the right
    /// unit instead of hardcoding `piggy-agent.service` (piggy#162). The
    /// home-manager module emits the platform-appropriate value (systemd
    /// unit on Linux, launchd label on macOS). Unset → health uses the
    /// platform default.
    #[arg(long = "service-name", value_name = "UNIT")]
    pub service_name: Option<String>,

    /// Holder mode (FDR 0006 phase (d)): serve `mint@piggy` and
    /// `retire@piggy`, creating keys on virtual cards in the fibby reached
    /// through --holder-fibby-ctl, each bound to the scope that minted it
    /// (see --scope) and usable from that scope only. Implies -A. Conflicts
    /// with proxying: a holder serves its own cards and nothing else.
    #[arg(
        long = "holder",
        requires = "holder_fibby_ctl",
        conflicts_with_all = ["proxy_only", "upstream", "guid", "cak", "info"]
    )]
    pub holder: bool,

    /// The control socket of the fibby holding the minted cards
    /// (`fibby --control-socket PATH`); its PC/SC socket is reached through
    /// PCSCLITE_CSOCK_NAME as for any card.
    #[arg(long = "holder-fibby-ctl", value_name = "PATH", requires = "holder")]
    pub holder_fibby_ctl: Option<String>,

    /// A scope definition, NAME=RULE, repeatable: what a mint naming NAME
    /// binds to. RULE is `caller` (the calling connection's own cgroup) or
    /// `cgroup:/absolute/path` (that cgroup; the caller must be inside it).
    /// A mint naming no scope, or one not defined here, is refused.
    #[arg(long = "scope", value_name = "NAME=RULE", requires = "holder")]
    pub scope: Vec<String>,

    /// Where the cgroup2 filesystem is mounted; a bound cgroup whose
    /// directory disappears from under it has exited, and its card is
    /// destroyed.
    #[arg(long = "cgroup-root", value_name = "DIR", default_value = holder::DEFAULT_CGROUP_ROOT)]
    pub cgroup_root: String,

    /// How often, in seconds, the holder checks that every bound cgroup
    /// still exists.
    #[arg(long = "scope-poll-interval", value_name = "SECONDS", default_value_t = holder::DEFAULT_POLL_INTERVAL.as_secs())]
    pub scope_poll_interval: u64,

    /// Command to execute with agent env set
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// FDR 0006 phase (b): the process that caches PINs is not dumpable and
/// writes no core file. A step that fails is a warning, and the agent
/// serves anyway, as C pivy-agent did when `mlockall` failed.
fn harden_agent_process() {
    let hardening = piggy_guard::harden_process();
    if let Some(Err(e)) = &hardening.non_dumpable {
        tracing::warn!(error = %e, "could not mark the agent non-dumpable");
    }
    if let Err(e) = &hardening.core_limit_zero {
        tracing::warn!(error = %e, "could not set the agent's core size limit to zero");
    }
    tracing::debug!(
        non_dumpable = ?hardening.non_dumpable.as_ref().map(Result::is_ok),
        core_limit_zero = hardening.core_limit_zero.is_ok(),
        dumpable = ?piggy_guard::is_dumpable(),
        "process hardening"
    );
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
        return match kill_agent(wants_csh_output(&cli)) {
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
    harden_agent_process();

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
        let pool = UpstreamPool::new(upstreams, std::time::Duration::from_secs(cli.agent_timeout))
            .with_outage_grace(std::time::Duration::from_secs(cli.upstream_grace))
            .with_sign_wait(std::time::Duration::from_secs(cli.sign_wait));
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
    // piggy#244 reconcile loop can re-run the exact same enumeration each tick.
    // FDR 0006 phase (d): a holder serves every card its fibby holds.
    let config = KeyLoadConfig {
        guid_filter: cli.guid.clone(),
        all_cards: cli.all_cards || cli.holder,
        allowed_slots,
        cak,
        policies: PolicyMemo::default(),
    };

    let holder = match build_holder(&cli) {
        Ok(holder) => holder,
        Err(e) => {
            eprintln!("piggy agent: {e}");
            return 1;
        }
    };

    // Proxy-only (eng#295): skip PIV enumeration entirely — no PCSC
    // context is ever opened, so a cardless host (no pcscd at all) starts
    // silently instead of warning every recovery tick.
    let cached_keys = if cli.proxy_only {
        tracing::info!("proxy-only: serving no native PIV keys; proxying upstreams only");
        Vec::new()
    } else {
        load_cached_keys_from_cards(&config).0
    };

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

    // The claim on fibby (one holder per fibby), after `--info` above.
    let holder = match holder.map(|h| claim_fibby(h, &cli)).transpose() {
        Ok(holder) => holder,
        Err(e) => {
            eprintln!("piggy agent: {e}");
            return 1;
        }
    };

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

    let code = match rt.block_on(run_async(cli, cached_keys, config, upstream_pool, holder)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piggy agent: {}", e);
            1
        }
    };
    // Exiting through here, not std::process::exit inside the runtime, lets the
    // dropped tasks run their destructors. Card work already in a blocking
    // thread (a PinSession's reset on drop) gets a short grace to finish.
    rt.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
    code
}

/// How long a stopping agent waits for card work in blocking threads.
const RUNTIME_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// The holder, from the `--holder` flags (FDR 0006 phase (d)), or `None`
/// without `--holder`. A malformed `--scope` is a startup error.
fn build_holder(cli: &AgentArgs) -> Result<Option<holder::Holder>, String> {
    if !cli.holder {
        return Ok(None);
    }
    let ctl = cli
        .holder_fibby_ctl
        .as_deref()
        .ok_or("--holder needs --holder-fibby-ctl PATH")?;
    let mut scopes = std::collections::HashMap::new();
    for spec in &cli.scope {
        let (name, rule) = holder::parse_scope_spec(spec)?;
        if scopes.insert(name.clone(), rule).is_some() {
            return Err(format!("--scope {name:?} is defined twice"));
        }
    }
    if scopes.is_empty() {
        tracing::warn!("holder: no --scope defined; every mint will be refused unknown-scope");
    }
    let config = holder::HolderConfig {
        scopes,
        cgroup_root: std::path::PathBuf::from(&cli.cgroup_root),
        poll_interval: std::time::Duration::from_secs(cli.scope_poll_interval.max(1)),
        cap: holder::CARD_CAP,
    };
    config.check_scopes_agree()?;
    // An `any` scope makes the socket the only boundary (a holder per
    // session): refuse to start unless all three sockets (this agent's and
    // fibby's two) are in private directories, the agent's apart from
    // fibby's, and none is a symlink. Here, before the first PC/SC use (the
    // keys are loaded over PC/SC right after) and before any socket of the
    // agent's exists. The agent's socket must be named: a default path is not
    // something an operator placed.
    if config.socket_is_the_boundary() {
        let socket = cli.socket.as_deref().ok_or(
            "holder: an `any` scope needs the agent's socket named with -a, in a private directory of its own",
        )?;
        let pcsc = std::env::var_os("PCSCLITE_CSOCK_NAME");
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        holder::check_boundary_sockets(
            std::path::Path::new(socket),
            std::path::Path::new(ctl),
            pcsc.as_deref().map(std::path::Path::new),
            uid,
        )
        .map_err(|e| format!("holder: an `any` scope needs private sockets: {e}"))?;
    }
    tracing::info!(
        fibby_ctl = ctl,
        cgroup_root = %config.cgroup_root.display(),
        scopes = config.scopes.len(),
        "holder mode (FDR 0006 phase (d))"
    );
    Ok(Some(holder::Holder::new(
        config,
        Box::new(holder::FibbyControl::new(ctl)),
    )))
}

/// One holder per fibby: claim fibby's directory (a `flock`, held for the
/// agent's life), so a second agent on the same fibby is refused instead of
/// destroying the first's cards at its start. Taken after the `--info` early
/// return (which serves nothing and must not hold a fibby) and before the
/// first thing that touches fibby's cards.
fn claim_fibby(
    holder: holder::Holder,
    cli: &AgentArgs,
) -> Result<std::sync::Arc<holder::Holder>, String> {
    let ctl = cli
        .holder_fibby_ctl
        .as_deref()
        .ok_or("--holder needs --holder-fibby-ctl PATH")?;
    let claim = holder::lock_fibby(std::path::Path::new(ctl))?;
    let holder = holder.with_fibby_lock(claim);
    tracing::debug!(
        claimed = holder.holds_fibby_lock(),
        "holder: the claim on fibby's directory"
    );
    Ok(std::sync::Arc::new(holder))
}

/// What a startup that could not list fibby's cards means: the cards of an
/// earlier run could not be destroyed, so one that stays would be signable over
/// fibby's PC/SC socket. For a holder whose socket is its boundary that is
/// fatal; another holder (whose keys are bound to cgroups, and which has no
/// binding for such a card, so serves it to no one) logs and goes on.
fn orphans_outcome(
    listed: Result<Vec<String>, String>,
    socket_is_the_boundary: bool,
) -> Result<(), String> {
    match listed {
        Ok(_) => Ok(()),
        Err(e) if socket_is_the_boundary => Err(format!("holder: {e}")),
        Err(e) => {
            tracing::warn!("holder: {e}");
            Ok(())
        }
    }
}

/// Resolves on SIGINT or SIGTERM (`systemctl stop`, launchd). Falls back
/// to SIGINT alone when the SIGTERM handler cannot be installed.
async fn shutdown_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(e) => {
            tracing::warn!("cannot install SIGTERM handler: {e}");
            tokio::signal::ctrl_c().await.ok();
        }
    }
}

/// Inputs that select and shape the PIV key load (and re-load): the GUID
/// filter, all-cards mode, the optional slot whitelist, and the optional CAK.
/// Owned by `run` and threaded into `run_async` so the piggy#244 reconcile loop
/// can re-run the identical enumeration each tick.
#[derive(Clone)]
struct KeyLoadConfig {
    guid_filter: Option<String>,
    all_cards: bool,
    allowed_slots: Option<Vec<u8>>,
    cak: Option<ssh_key::public::KeyData>,
    /// Each served slot's reported PIN policy, read once (piggy#383 item 4).
    policies: PolicyMemo,
}

/// The PIN policy of every (card, slot, key) the agent has looked at, so a
/// real card answers one ATTEST per slot for the life of the process, not
/// one per reconcile tick. Keyed by the key's fingerprint too: a slot whose
/// key was regenerated is read again.
#[derive(Clone, Default)]
struct PolicyMemo(std::sync::Arc<std::sync::Mutex<PolicyMap>>);

/// (card GUID hex, slot, key fingerprint) -> the slot's reported PIN policy.
type PolicyMap = std::collections::HashMap<(String, u8, String), Option<piggy_piv::PinPolicy>>;

impl PolicyMemo {
    /// The slot's reported PIN policy, from the memo or from the card's
    /// attestation (`None` when the card does not attest the slot: a seeded
    /// virtual slot, a non-YubiKey; the agent then prompts as it always did).
    fn pin_policy_of(
        &self,
        token: &piggy_piv::PivToken,
        slot: &piggy_piv::PivSlot,
    ) -> Option<piggy_piv::PinPolicy> {
        let key = (
            token.guid().to_hex(),
            slot.id(),
            slot.public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
        );
        if let Some(known) = self.0.lock().unwrap().get(&key) {
            return *known;
        }
        let policy = match token.read_slot_policy(slot.id()) {
            Ok((pin, _touch)) => Some(pin),
            Err(e) => {
                tracing::debug!(
                    guid = %token.guid().short_id(),
                    slot = format!("{:02X}", slot.id()),
                    "slot policy not attested ({e}); a PIN will be asked for as before"
                );
                None
            }
        };
        self.0.lock().unwrap().insert(key, policy);
        policy
    }
}

/// Enumerate PIV tokens, logging and degrading to an empty list on any PCSC
/// failure (no card, denied access, cold pcscd). Both the startup load and the
/// reconcile loop go through here so they treat a transient failure identically.
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
        let slots = token.read_all_slots();
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
                pin_policy: config.policies.pin_policy_of(token, slot),
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
/// startup load and re-run each tick by the piggy#244 reconcile loop.
fn load_cached_keys_from_cards(
    config: &KeyLoadConfig,
) -> (Vec<CachedKey>, Option<piggy_piv::Guid>) {
    build_cached_keys(&enumerate_tokens_or_empty(), config)
}

async fn run_async(
    cli: AgentArgs,
    cached_keys: Vec<CachedKey>,
    config: KeyLoadConfig,
    upstream_pool: Option<UpstreamPool>,
    holder: Option<std::sync::Arc<holder::Holder>>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let use_csh = wants_csh_output(&cli);
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

    // (An `any` holder's three sockets were checked in `build_holder`.)
    let socket_is_the_boundary = holder
        .as_ref()
        .is_some_and(|h| h.config().socket_is_the_boundary());

    // piggy#326: an upstream at this agent's own socket would send every
    // proxied request straight back in, without end.
    if let Some(name) = upstream_pool
        .as_ref()
        .and_then(|pool| pool.upstream_at(std::path::Path::new(&socket_path)))
    {
        return Err(format!(
            "--upstream {name} is this agent's own socket ({socket_path}); proxying to it would loop"
        )
        .into());
    }

    // Cards fibby holds from before this start have no binding, and nothing
    // would ever retire them: destroy them now. Before the environment is
    // printed and before the socket is bound, so a holder that cannot start
    // (fibby cannot be listed, for one whose socket is its boundary) leaves no
    // stale socket and has told its caller nothing.
    if let Some(holder) = &holder {
        orphans_outcome(holder.destroy_orphans().await, socket_is_the_boundary)?;
    }

    // A holder whose socket is its boundary creates it mode 0600, whatever the
    // umask it was started with (the directory is already private, this is
    // the second lock).
    let previous_umask = socket_is_the_boundary.then(|| {
        // SAFETY: umask takes one mode and cannot fail.
        unsafe { libc::umask(0o177) }
    });
    let bound = bind_reclaiming_stale(&socket_path);
    if let Some(previous) = previous_umask {
        // SAFETY: as above.
        unsafe { libc::umask(previous) };
    }
    let listener = listener::ResilientListener(bound?);

    // The environment is printed once the socket is bound: an agent that could
    // not start has told its caller nothing to `eval`.
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
    // piggy#255: event-driven presence is the default for a card-backed agent;
    // --poll-only opts out, and a proxy-only agent runs no card loop at all.
    let event_driven = !cli.proxy_only && !cli.poll_only;
    let agent = PiggyAgent::new(cached_keys)
        .with_proxy_only(cli.proxy_only)
        .with_event_driven(event_driven)
        .with_service_name(cli.service_name.clone());
    // piggy#404: the PIN cache table is compiled in; say which one this is.
    tracing::info!(
        table = %pin_policy::PinCachePolicy::compiled_in().describe().join("; "),
        "PIN cache (compiled in, not configuration)"
    );
    // piggy#215: with --upstream flags, proxy the named agents for keys
    // piggy does not serve natively. Without them the pool stays empty
    // and the agent behaves exactly as before.
    let agent = match upstream_pool {
        Some(pool) => agent.with_upstream_pool(pool),
        None => agent,
    };
    // FDR 0006 phase (d): the holder's teardown watcher destroys a minted
    // card once its bound cgroup is gone; retire does the same on request.
    let agent = match holder {
        Some(holder) => {
            tokio::spawn(holder::watch_bindings(
                holder.clone(),
                agent.keys_handle(),
                agent.pin_handle(),
            ));
            agent.with_holder(holder)
        }
        None => agent,
    };

    // piggy#244: one per-card presence reconcile loop maintains the served
    // key set against the cards physically present — dropping a removed card's
    // keys AND forgetting its PIN, and adopting a newly-inserted card
    // (sign-path gated, piggy#179). It subsumes the old single-primary
    // PIN-clear probe (piggy#59), the piggy#175 0-key recovery (an addition
    // once a card appears), and the piggy#143 CAK-swap loop (a CAK-mismatched
    // card drops out of the per-tick enumeration and reconciles as a removal).
    // Under the piggy#214 card lock, `try_lock`ed so a tick never races an
    // in-flight request.
    let pin_handle = agent.pin_handle();
    let card_lock = agent.card_lock_handle();
    if cli.proxy_only {
        // Proxy-only: no card ever appears, so there is nothing to reconcile.
    } else {
        let keys_handle = agent.keys_handle();
        let probe_interval = cli
            .probe_interval
            .map(std::time::Duration::from_secs)
            .unwrap_or(card::DEFAULT_PROBE_INTERVAL)
            // A zero interval would spin the reconcile loop (`sleep(0)`); the
            // flag is whole seconds, so 0 is the only sub-second value — floor
            // it to 1s rather than busy-loop (piggy#251).
            .max(std::time::Duration::from_secs(1));
        let load = move || load_cached_keys_from_cards(&config).0;
        let verify = |guid: &piggy_piv::Guid| {
            session::reconnect_to_token(guid)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        if event_driven {
            // piggy#248: an SCardGetStatusChange watch on a dedicated blocking
            // thread fires this Notify on any reader-state change, triggering
            // an immediate reconcile; the poll interval stays the safety net.
            // The default since piggy#255 (--poll-only takes the else branch).
            // `changed` carries which readers transitioned, so the reconcile
            // collapses the debounce for only those cards.
            let notify = std::sync::Arc::new(tokio::sync::Notify::new());
            let changed: card::ChangedReaders =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
            // Bound each blocking wait so the watch periodically re-lists
            // readers (catching a whole reader added/removed); small relative
            // to the poll interval.
            let bounded = probe_interval
                .min(std::time::Duration::from_secs(5))
                .max(std::time::Duration::from_secs(1));
            let watch_notify = notify.clone();
            let watch_changed = changed.clone();
            std::thread::Builder::new()
                .name("piggy-agent-card-events".into())
                .spawn(move || card::run_event_source(watch_notify, watch_changed, bounded))?;
            tracing::info!(
                interval_secs = probe_interval.as_secs(),
                bounded_secs = bounded.as_secs(),
                "spawning event-driven per-card presence reconcile loop (piggy#248)"
            );
            tokio::spawn(card::reconcile_loop_with_events(
                keys_handle,
                pin_handle,
                card_lock,
                load,
                verify,
                probe_interval,
                card::PROBE_FAIL_LIMIT,
                notify,
                changed,
            ));
        } else {
            tracing::info!(
                interval_secs = probe_interval.as_secs(),
                "spawning per-card presence reconcile loop (piggy#244)"
            );
            tokio::spawn(card::reconcile_loop(
                keys_handle,
                pin_handle,
                card_lock,
                load,
                verify,
                probe_interval,
                card::PROBE_FAIL_LIMIT,
            ));
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

        return Ok(status.code().unwrap_or(1));
    }

    // Clean up the socket on exit — on SIGINT (interactive ^C) AND on
    // SIGTERM (what `systemctl stop` / launchd send). Without the SIGTERM
    // half a service stop left the socket file behind, so the next start
    // EADDRINUSEd unless a launcher unlinked it first; the agent now owns
    // its own stale-socket cleanup (the ssh-agent-mux#8 parity piggy#215
    // asked for).
    tokio::select! {
        res = listen(listener, agent) => res?,
        () = shutdown_signal() => {}
    }
    let _ = std::fs::remove_file(&socket_path);
    Ok(0)
}

/// Bind the agent socket, reclaiming a *stale* socket file first: a
/// leftover file at `path` that nothing accepts on (connect →
/// `ConnectionRefused`, the signature of a dead listener's orphaned inode)
/// is unlinked and re-bound. A file a live agent is serving is NOT
/// clobbered — that surfaces as the `AddrInUse` it always was, so two
/// agents can't silently fight over one path. The ssh-agent-mux#8 parity
/// piggy#215 asked for; it also makes the agent self-sufficient under a
/// supervisor that doesn't pre-clean (the HM launcher's `rm -f` stays as
/// belt-and-braces).
///
/// Only a leftover SOCKET is ever unlinked. A path that exists and is a
/// regular file, a directory or a SYMLINK (even one to a dead socket) is
/// refused with "exists and is not a socket; not removing it": connecting to
/// such a path is refused too, which used to read as "stale" and delete what
/// the operator had put there. A supervisor that passed `-a` a symlink and
/// relied on this replacing it must remove it first (the HM launcher's `rm -f`
/// does; units that pass a plain path are unaffected).
fn bind_reclaiming_stale(path: &str) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::FileTypeExt;
    match UnixListener::bind(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Only a leftover SOCKET is ever unlinked: connecting to a regular
            // file is refused too, which would read as "stale" and delete a
            // file the operator named by mistake.
            if !std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("{path} exists and is not a socket; not removing it"),
                ));
            }
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => Err(e),
                Err(ce) if ce.kind() == std::io::ErrorKind::ConnectionRefused => {
                    tracing::warn!(path, "reclaiming stale agent socket (nothing listening)");
                    std::fs::remove_file(path)?;
                    UnixListener::bind(path)
                }
                Err(_) => Err(e),
            }
        }
        other => other,
    }
}

/// `-c` forces csh output and `-s` Bourne output; with neither, a `SHELL`
/// ending in `csh` picks csh. Shared by agent start and `-k`.
fn wants_csh_output(cli: &AgentArgs) -> bool {
    cli.csh_format || (!cli.sh_format && std::env::var("SHELL").is_ok_and(|s| s.ends_with("csh")))
}

/// What `-k` prints for the caller's shell to eval after the agent is gone.
fn kill_agent_shell_lines(use_csh: bool, pid: i32) -> String {
    if use_csh {
        format!("unsetenv SSH_AUTH_SOCK;\nunsetenv SSH_AGENT_PID;\necho Agent pid {pid} killed;\n")
    } else {
        format!("unset SSH_AUTH_SOCK;\nunset SSH_AGENT_PID;\necho Agent pid {pid} killed;\n")
    }
}

fn kill_agent(use_csh: bool) -> Result<(), Box<dyn std::error::Error>> {
    let pid_str = std::env::var("SSH_AGENT_PID").map_err(|_| "SSH_AGENT_PID not set")?;
    let pid: i32 = pid_str.parse().map_err(|_| "invalid SSH_AGENT_PID")?;

    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc != 0 {
        return Err(format!("kill({pid}, SIGTERM): {}", std::io::Error::last_os_error()).into());
    }

    print!("{}", kill_agent_shell_lines(use_csh, pid));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_agent_prints_bourne_lines() {
        assert_eq!(
            kill_agent_shell_lines(false, 42),
            "unset SSH_AUTH_SOCK;\nunset SSH_AGENT_PID;\necho Agent pid 42 killed;\n"
        );
    }

    #[test]
    fn kill_agent_prints_csh_lines() {
        assert_eq!(
            kill_agent_shell_lines(true, 42),
            "unsetenv SSH_AUTH_SOCK;\nunsetenv SSH_AGENT_PID;\necho Agent pid 42 killed;\n"
        );
    }

    #[test]
    fn csh_flag_picks_csh_output_for_kill_too() {
        let cli = AgentArgs::try_parse_from(["piggy agent", "-c", "-k"]).unwrap();
        assert!(wants_csh_output(&cli));
        let cli = AgentArgs::try_parse_from(["piggy agent", "-s", "-k"]).unwrap();
        assert!(!wants_csh_output(&cli));
    }

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

    /// `--proxy-only` (eng#295): needs an upstream, and rejects every
    /// card-selection flag — there is no card to select.
    #[test]
    fn agent_args_proxy_only_requires_upstream_and_rejects_card_flags() {
        assert!(
            AgentArgs::try_parse_from(["piggy agent", "--proxy-only"]).is_err(),
            "--proxy-only without --upstream must be rejected"
        );
        let ok = AgentArgs::try_parse_from([
            "piggy agent",
            "--proxy-only",
            "--upstream",
            "fwd=/tmp/f.sock",
        ])
        .unwrap();
        assert!(ok.proxy_only);
        for card_flag in [
            ["-A", ""],
            ["-g", "ABCD"],
            ["-S", "9a"],
            ["-K", "ecdsa-sha2-nistp256 AAAA"],
            ["-i", ""],
        ] {
            let mut argv = vec![
                "piggy agent",
                "--proxy-only",
                "--upstream",
                "fwd=/tmp/f.sock",
                card_flag[0],
            ];
            if !card_flag[1].is_empty() {
                argv.push(card_flag[1]);
            }
            assert!(
                AgentArgs::try_parse_from(&argv).is_err(),
                "--proxy-only must conflict with {}",
                card_flag[0]
            );
        }
    }

    /// Sockets for these tests live under `/tmp`, NOT the honored TMPDIR
    /// (inside the worktree — a leftover socket file there breaks later
    /// `builtins.getFlake` path copies; see upstream::test_support).
    fn scratch_socket_path(tag: &str) -> String {
        let p = format!("/tmp/pgbind{}-{tag}.sock", std::process::id());
        let _ = std::fs::remove_file(&p);
        p
    }

    #[tokio::test]
    async fn bind_reclaims_stale_socket_file() {
        let path = scratch_socket_path("stale");
        // A listener that bound and died leaves its socket file behind.
        let dead = UnixListener::bind(&path).unwrap();
        drop(dead);
        assert!(
            std::path::Path::new(&path).exists(),
            "precondition: orphaned socket file"
        );

        let reclaimed = bind_reclaiming_stale(&path).expect("stale socket must be reclaimed");
        drop(reclaimed);
        let _ = std::fs::remove_file(&path);
    }

    // Follow-up review, 9: a startup that cannot list fibby's cards is fatal for
    // a holder whose socket is its boundary and only a log line for any other.
    #[test]
    fn a_failed_listing_is_fatal_only_for_a_holder_whose_socket_is_its_boundary() {
        assert!(orphans_outcome(Ok(vec!["piggy-holder 1".into()]), true).is_ok());
        assert!(orphans_outcome(Ok(Vec::new()), false).is_ok());
        assert!(orphans_outcome(Err("could not list".into()), false).is_ok());
        let err = orphans_outcome(Err("could not list".into()), true).unwrap_err();
        assert!(err.contains("could not list"), "{err}");
    }

    // Round 3, L6: a regular file named by -a is not "a stale socket": connecting
    // to it is refused too, and it must not be unlinked.
    #[tokio::test]
    async fn bind_never_unlinks_a_file_that_is_not_a_socket() {
        let path = scratch_socket_path("regular");
        std::fs::write(&path, b"precious").unwrap();
        let err = bind_reclaiming_stale(&path).expect_err("a regular file must not be reclaimed");
        assert!(err.to_string().contains("not a socket"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"precious");
        let _ = std::fs::remove_file(&path);
    }

    // Round 3, L7: the `any` checks live in `build_holder`, which `run` calls
    // BEFORE the first PC/SC use: an error here is an agent that never
    // enumerated a card.
    #[test]
    fn an_any_holder_is_refused_in_build_holder_before_any_card_is_touched() {
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "piggy agent",
                "--holder",
                "--holder-fibby-ctl",
                "/tmp/no-such-ctl.sock",
                "--scope",
                "session=any",
            ];
            args.extend_from_slice(extra);
            AgentArgs::try_parse_from(args).unwrap()
        };
        // No -a at all.
        let err = build_holder(&parse(&[])).err().expect("refused");
        assert!(err.contains("named with -a"), "{err}");
        // -a in a directory more than the operator can reach.
        let shared = format!("/tmp/pgshared{}", std::process::id());
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::set_permissions(
            &shared,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .unwrap();
        let sock = format!("{shared}/a.sock");
        let err = build_holder(&parse(&["-a", &sock])).err().expect("refused");
        assert!(err.contains("private sockets"), "{err}");
        // A holder with only a cgroup scope has no such requirement.
        let ok = AgentArgs::try_parse_from([
            "piggy agent",
            "--holder",
            "--holder-fibby-ctl",
            "/tmp/no-such-ctl.sock",
            "--scope",
            "s=caller",
        ])
        .unwrap();
        assert!(build_holder(&ok).is_ok());
        let _ = std::fs::remove_dir_all(&shared);
    }

    #[tokio::test]
    async fn bind_refuses_to_clobber_live_listener() {
        let path = scratch_socket_path("live");
        let _live = UnixListener::bind(&path).unwrap();

        let err = bind_reclaiming_stale(&path).expect_err("live listener must not be clobbered");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            std::path::Path::new(&path).exists(),
            "live socket file must survive"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// piggy#255: event-driven is the DEFAULT; `--poll-only` opts out and is
    /// rejected together with `--proxy-only` (a cardless agent runs no card
    /// loop either way).
    #[test]
    fn agent_args_poll_only_parses_and_conflicts_with_proxy_only() {
        // Default is event-driven, i.e. NOT poll-only.
        assert!(
            !AgentArgs::try_parse_from(["piggy agent", "-A"])
                .unwrap()
                .poll_only,
            "event-driven is the default (poll_only false)"
        );
        let ok = AgentArgs::try_parse_from(["piggy agent", "-A", "--poll-only"]).unwrap();
        assert!(ok.poll_only);
        assert!(
            AgentArgs::try_parse_from([
                "piggy agent",
                "--proxy-only",
                "--upstream",
                "fwd=/tmp/f.sock",
                "--poll-only",
            ])
            .is_err(),
            "--poll-only must conflict with --proxy-only"
        );
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
