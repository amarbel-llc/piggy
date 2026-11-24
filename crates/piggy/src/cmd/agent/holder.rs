//! The holder agent mode of `piggy agent` (FDR 0006 phase (d), piggy#383
//! items 1 to 3): the scope definitions a mint names, the bindings of
//! minted keys to cgroups, the fibby control-socket client that creates
//! and destroys the cards, the provisioning of a fresh card (slot 9A read,
//! factory PIN replaced by a random one the holder keeps), and the watcher
//! that tears a card down when its bound cgroup disappears.
//!
//! The decisions (which scope, whose peer, the cap) are pure methods on
//! [`Holder`] so they are unit-tested without a card; the IO (fibby's
//! control socket, PC/SC) is behind [`CardControl`] and
//! [`provision_minted_card`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use piggy_piv::Guid;
use ssh_key::public::KeyData;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use super::peer::{CgroupPath, Peer};
use super::pins::PinCache;
use super::session::CachedKey;
use crate::holder_ext::Status;

/// Live cards per holder (FDR 0006 "Tuning Levers": the pcsc-lite reader
/// table has 16 entries; phase (h) lifts it).
pub const CARD_CAP: usize = 16;
/// Where cgroup2 is mounted, unless `--cgroup-root` says otherwise.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// How often the watcher checks that every bound cgroup still exists.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// The PIN a card created by fibby's `create` verb starts with (phase (c)).
const FACTORY_PIN: &str = "123456";
/// The slot a minted key lives in (ruled: 9A only, never 9C or 9D).
pub const MINTED_SLOT: u8 = 0x9A;

/// What a scope name resolves to: a rule for the binding a mint under that
/// name gets. Holder configuration (`--scope NAME=RULE`) until clown#244
/// defines the scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRule {
    /// Bind to the calling connection's own cgroup.
    Caller,
    /// Bind to this cgroup; the caller must be inside it.
    Cgroup(CgroupPath),
    /// Bind to nothing: whoever can open the agent's socket may use the key
    /// (the shape of a holder per session, whose socket only that session
    /// can reach). A cgroup is something a same-uid process can move itself
    /// into, so this rule keeps no cgroup and reads no peer; the socket is
    /// the whole boundary, and the agent refuses to start unless that socket
    /// sits in a private directory ([`check_private_socket_dir`]). A holder
    /// that has one `any` scope has only `any` scopes.
    Any,
}

/// Parse one `--scope NAME=RULE`: `NAME=caller`, `NAME=any` or
/// `NAME=cgroup:/path`. The name is opaque (it may hold `@`); the split is at
/// the first `=`.
pub fn parse_scope_spec(spec: &str) -> Result<(String, ScopeRule), String> {
    let Some((name, rule)) = spec.split_once('=') else {
        return Err(format!(
            "--scope {spec:?}: want NAME=caller, NAME=any or NAME=cgroup:/path"
        ));
    };
    if name.is_empty() {
        return Err(format!("--scope {spec:?}: the scope name is empty"));
    }
    let rule = match rule {
        "caller" => ScopeRule::Caller,
        "any" => ScopeRule::Any,
        other => match other.strip_prefix("cgroup:") {
            Some(path) => {
                let cgroup = CgroupPath::parse(path).ok_or_else(|| {
                    format!("--scope {spec:?}: {path:?} is not an absolute cgroup path")
                })?;
                // The root cgroup contains every process: a scope bound to it
                // binds to no one in particular, and is not what `any` says
                // (no peer read, a private socket directory) either.
                if cgroup.is_root() {
                    return Err(format!(
                        "--scope {spec:?}: the root cgroup contains every process; name the cgroup, or use `any` on a private socket"
                    ));
                }
                ScopeRule::Cgroup(cgroup)
            }
            None => {
                return Err(format!(
                    "--scope {spec:?}: unknown rule {other:?}; want caller, any or cgroup:/path"
                ));
            }
        },
    };
    Ok((name.to_string(), rule))
}

/// Holder configuration, from the `--holder` flags.
#[derive(Debug, Clone)]
pub struct HolderConfig {
    pub scopes: HashMap<String, ScopeRule>,
    pub cgroup_root: PathBuf,
    pub poll_interval: Duration,
    pub cap: usize,
}

impl HolderConfig {
    /// Whether this holder's socket is its only boundary: it has an `any`
    /// scope. Then ALL its scopes are `any` ([`Self::check_scopes_agree`]).
    pub fn socket_is_the_boundary(&self) -> bool {
        self.scopes.values().any(|r| matches!(r, ScopeRule::Any))
    }

    /// An `any` scope on a holder that also has cgroup rules would serve two
    /// kinds of key on one socket, one open to every connection and one not:
    /// refused, so a socket is either the boundary or it is not.
    pub fn check_scopes_agree(&self) -> Result<(), String> {
        if self.socket_is_the_boundary()
            && self.scopes.values().any(|r| !matches!(r, ScopeRule::Any))
        {
            return Err(
                "an `any` scope makes the socket the only boundary, so every --scope must be \
                 `any` (it is mixed with caller or cgroup rules)"
                    .into(),
            );
        }
        Ok(())
    }
}

/// An `any` scope trusts whoever can open the socket, so the socket's
/// directory must be the operator's alone: owned by `uid` and with no group
/// or other bits. A shared directory (the host holder's 0750 one) is refused,
/// whatever the scope names; this catches the mistake of an `any` scope on a
/// socket more than one session can reach, not an attacker who can already
/// write the directory.
pub fn check_private_socket_dir(socket: &std::path::Path, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let dir = match socket.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let meta = std::fs::metadata(dir)
        .map_err(|e| format!("the socket's directory {}: {e}", dir.display()))?;
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != uid {
        return Err(format!(
            "the socket's directory {} is owned by uid {}, not the agent's {uid}",
            dir.display(),
            meta.uid()
        ));
    }
    let loose = meta.mode() & 0o077;
    if loose != 0 {
        return Err(format!(
            "the socket's directory {} has group or other permission bits (mode {:o}); an `any` scope needs it private (0700)",
            dir.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// The three sockets a holder whose socket is its boundary has: the agent's,
/// fibby's control socket, and fibby's PC/SC socket. Minted cards are PIN
/// `never` and touch `never`, so whoever reaches fibby's PC/SC socket signs
/// with every minted key and no agent, and whoever reaches the control socket
/// creates and destroys cards: guarding the agent's socket alone guards
/// nothing. Each directory must be private ([`check_private_socket_dir`]),
/// and the agent's must be a different directory from the other two, so a
/// view that holds the agent's socket does not hold fibby's. This is a check
/// for a misconfigured launch (a shared or world-reachable directory), not a
/// defence against a process that can already write the directory.
pub fn check_boundary_sockets(
    agent: &std::path::Path,
    fibby_ctl: &std::path::Path,
    fibby_pcsc: Option<&std::path::Path>,
    uid: u32,
) -> Result<(), String> {
    let pcsc = fibby_pcsc.ok_or(
        "PCSCLITE_CSOCK_NAME is not set; an `any` scope needs it to name fibby's own PC/SC socket, in a private directory",
    )?;
    for (what, path) in [
        ("the agent's socket", agent),
        ("fibby's control socket (--holder-fibby-ctl)", fibby_ctl),
        ("fibby's PC/SC socket (PCSCLITE_CSOCK_NAME)", pcsc),
    ] {
        check_private_socket_dir(path, uid).map_err(|e| format!("{what}: {e}"))?;
    }
    // The sockets themselves: none may be a symlink (it could lead out of the
    // private directory), and fibby's two must already be sockets (fibby is
    // started first, and the agent reads cards over PC/SC as soon as it runs).
    // The agent's own may be absent (it is bound later) or a stale socket.
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    for (what, path, must_exist) in [
        ("the agent's socket", agent, false),
        ("fibby's control socket", fibby_ctl, true),
        ("fibby's PC/SC socket", pcsc, true),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("{what} {} is a symlink", path.display()));
            }
            // (the agent's own path may be absent or a stale socket, but never
            // a file of another kind: binding would unlink it)
            Ok(m) if !m.file_type().is_socket() => {
                return Err(format!("{what} {} is not a socket", path.display()));
            }
            Ok(_) => {}
            Err(e) if must_exist => {
                return Err(format!(
                    "{what} {}: {e} (fibby must be running first)",
                    path.display()
                ));
            }
            Err(_) => {}
        }
    }
    // Apart: neither of fibby's directories may be the agent's, or under it
    // (a view that holds the agent's directory holds everything below it).
    let dir_of = |path: &std::path::Path| {
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))
    };
    let id = |dir: &std::path::Path| {
        std::fs::metadata(dir)
            .map(|m| (m.dev(), m.ino()))
            .map_err(|e| format!("{}: {e}", dir.display()))
    };
    let agent_dir = dir_of(agent)?;
    let agent_id = id(&agent_dir)?;
    for (what, path) in [
        ("fibby's control socket", fibby_ctl),
        ("fibby's PC/SC socket", pcsc),
    ] {
        for ancestor in dir_of(path)?.ancestors() {
            if id(ancestor)? == agent_id {
                return Err(format!(
                    "{what} is in the agent socket's own directory or under it; they must be apart, so a view that holds the agent's socket does not hold fibby's"
                ));
            }
        }
    }
    Ok(())
}

/// A minted key and what it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub key: KeyData,
    pub guid: Guid,
    /// The reader fibby serves the card as.
    pub reader: String,
    pub scope: String,
    /// The cgroup the key is bound to, or `None` for an [`ScopeRule::Any`]
    /// scope: the key is then usable from every connection to this agent's
    /// socket, lives until it is retired or the agent ends, and no watcher
    /// looks at any cgroup for it.
    pub cgroup: Option<CgroupPath>,
    /// Set when the card is being destroyed (a retire, or its scope exited)
    /// and cleared by nothing: the key is then usable by no one, whatever
    /// the card reconcile loop does with a card fibby still holds, and the
    /// watcher keeps trying to destroy it. Never inferred from a key being
    /// absent from the served set: that loop drops keys for a PC/SC blip too.
    pub retiring: bool,
}

/// The card store's create and destroy verbs (fibby's control socket in
/// production, a recorder in tests).
#[ssh_agent_lib::async_trait]
pub trait CardControl: Send + Sync {
    /// Create a card served as `reader` whose slot 9A holds a key of the
    /// fibby algorithm `alg` (`ed25519` or `p256`), PIN and touch `never`.
    async fn create(&self, alg: &str, reader: &str) -> Result<(), String>;
    /// Wipe the card served as `reader` and remove it.
    async fn destroy(&self, reader: &str) -> Result<(), String>;
    /// The readers the card store serves a card for, by name.
    async fn readers(&self) -> Result<Vec<String>, String>;
}

/// How long the agent waits on fibby's control socket for one command. A
/// fibby that accepts and never answers must not hold a teardown (and the
/// lock it takes) for ever.
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

/// fibby's control socket (piggy#130, #382 item 6): one line in, one reply
/// out, `ok …` or `err …`.
pub struct FibbyControl {
    socket: PathBuf,
    timeout: Duration,
}

impl FibbyControl {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: CONTROL_TIMEOUT,
        }
    }

    /// The same control socket with another timeout (the tests').
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// One command, as `fibby ctl` sends it: a line, then read to EOF. A
    /// plain blocking socket on a blocking task; the exchange is tiny. It
    /// ends after `timeout` whatever fibby does: the socket's reads and
    /// writes time out, and the whole call is bounded too (a connect has no
    /// socket timeout), so a silent fibby costs a failed command, not a hung
    /// retire, watcher and lock.
    async fn command(&self, line: &str) -> Result<String, String> {
        let timeout = self.timeout;
        let display = self.socket.display().to_string();
        let work = self.command_blocking(line);
        match tokio::time::timeout(timeout + Duration::from_secs(1), work).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "fibby's control socket {display} did not answer within {timeout:?}"
            )),
        }
    }

    async fn command_blocking(&self, line: &str) -> Result<String, String> {
        let socket = self.socket.clone();
        let line = line.to_string();
        let timeout = self.timeout;
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut stream = std::os::unix::net::UnixStream::connect(&socket)
                .map_err(|e| format!("connect {}: {e}", socket.display()))?;
            stream
                .set_read_timeout(Some(timeout))
                .and_then(|()| stream.set_write_timeout(Some(timeout)))
                .map_err(|e| format!("timeouts on {}: {e}", socket.display()))?;
            stream
                .write_all(format!("{line}\n").as_bytes())
                .map_err(|e| format!("write to {}: {e}", socket.display()))?;
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|e| format!("shutdown {}: {e}", socket.display()))?;
            let mut reply = String::new();
            stream
                .read_to_string(&mut reply)
                .map_err(|e| format!("read from {}: {e}", socket.display()))?;
            let reply = reply.trim_end().to_string();
            match reply.strip_prefix("err") {
                Some(reason) => Err(reason.trim().to_string()),
                None if reply.starts_with("ok") => Ok(reply),
                None => Err(format!("unexpected reply {reply:?}")),
            }
        })
        .await
        .map_err(|e| format!("control task: {e}"))?
    }
}

#[ssh_agent_lib::async_trait]
impl CardControl for FibbyControl {
    async fn create(&self, alg: &str, reader: &str) -> Result<(), String> {
        self.command(&format!("create alg={alg} pin=never touch=never {reader}"))
            .await
            .map(drop)
    }

    async fn destroy(&self, reader: &str) -> Result<(), String> {
        self.command(&format!("destroy {reader}")).await.map(drop)
    }

    async fn readers(&self) -> Result<Vec<String>, String> {
        // `ok`, then one `<reader>\t<present|absent>` line per card.
        let reply = self.command("list").await?;
        Ok(reply
            .lines()
            .skip(1)
            .filter_map(|line| line.split('\t').next())
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect())
    }
}

#[derive(Default)]
struct HolderState {
    bindings: Vec<Binding>,
    /// Cards reserved by a mint in progress plus the live bindings; what
    /// the cap is checked against.
    live: usize,
    next_card: u64,
    /// Readers a mint gave up on (its `create` failed or timed out) whose card
    /// fibby may still make, late: each is tried again, by its own task, until
    /// a destroy finds the card or its deadline passes. At most
    /// [`CARD_CAP`] are kept (the oldest is dropped, with a warning). Reader
    /// names never repeat, so a card that shows up under one is an orphan.
    suspects: Vec<(String, std::time::Instant)>,
}

/// How long a reader whose `create` failed stays suspect: longer than the
/// control timeout plus slack, so a fibby that is merely slow is waited out.
pub const SUSPECT_FOR: Duration = Duration::from_secs(120);

/// The holder: configuration, the live bindings, and the card store.
pub struct Holder {
    config: HolderConfig,
    control: Box<dyn CardControl>,
    state: Mutex<HolderState>,
    /// One teardown at a time: a retire and the watcher's retry never
    /// destroy the same card together.
    teardown_lock: Mutex<()>,
    /// The claim on this fibby (see [`lock_fibby`]), held for as long as the
    /// holder lives.
    fibby_lock: Option<FibbyLock>,
}

/// A claim that this agent is the only holder serving one fibby. Dropping it
/// (the agent ending) frees the claim.
pub struct FibbyLock {
    _directory: std::fs::File,
}

/// Claim fibby for this agent: an exclusive `flock` on fibby's control socket
/// DIRECTORY. A fibby belongs to ONE holder agent: at start an agent destroys
/// the `piggy-holder N` cards it did not mint, so a second agent on the same
/// fibby would destroy the first's live cards (and two agents would count
/// reader names from 1 each). The lock is keyed on the directory's inode, not
/// on a path string (two views of one directory contend; two sessions' own
/// directories, whatever their names inside their views, do not), needs only
/// read access to the directory, is freed by the kernel when the agent ends
/// however it ends, and can be contended only by a process that has the
/// directory in view, so no one else can squat on it (an abstract socket
/// name, which every process of the network namespace can bind, could). A
/// directory that cannot be opened is an error, not "no claim". "Never share
/// a fibby" is a refusal, not a convention.
pub fn lock_fibby(ctl: &std::path::Path) -> Result<FibbyLock, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    // Every holder, whatever its scopes: a symlink where the control socket
    // should be leads somewhere the claim and the checks did not look.
    if std::fs::symlink_metadata(ctl).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!(
            "fibby's control socket {} is a symlink; name the socket itself",
            ctl.display()
        ));
    }
    let dir = match ctl.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| {
            format!(
                "the claim on fibby: cannot open its directory {}: {e}",
                dir.display()
            )
        })?;
    // SAFETY: flock takes a descriptor this function owns and a flag word.
    let rc = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(FibbyLock {
            _directory: directory,
        });
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::WouldBlock {
        Err(format!(
            "another holder agent already serves the fibby in {}: never share a fibby (a second agent would destroy the first's cards at start)",
            dir.display()
        ))
    } else {
        Err(format!("the claim on fibby: flock {}: {e}", dir.display()))
    }
}

impl Holder {
    pub fn new(config: HolderConfig, control: Box<dyn CardControl>) -> Self {
        Self {
            config,
            control,
            state: Mutex::new(HolderState::default()),
            teardown_lock: Mutex::new(()),
            fibby_lock: None,
        }
    }

    /// This holder with the claim on its fibby, kept for its lifetime.
    pub fn with_fibby_lock(mut self, lock: FibbyLock) -> Self {
        self.fibby_lock = Some(lock);
        self
    }

    /// A mint that gave up on `reader` without being sure no card exists
    /// (the destroy it tried failed, or said "no such reader" before a slow
    /// fibby had made the card): keep trying for a while, from the watcher.
    pub async fn add_suspect(&self, reader: &str) {
        self.add_suspect_for(reader, SUSPECT_FOR).await;
    }

    /// [`Self::add_suspect`] for a window of the caller's choosing (the tests').
    pub async fn add_suspect_for(&self, reader: &str, window: Duration) {
        let mut state = self.state.lock().await;
        if state.suspects.len() >= CARD_CAP {
            let (dropped, _) = state.suspects.remove(0);
            tracing::warn!(reader = %dropped, "holder: too many suspect readers; no longer retrying the oldest");
        }
        state
            .suspects
            .push((reader.to_string(), std::time::Instant::now() + window));
    }

    /// One pass over the suspect readers: destroy each; a destroy that
    /// succeeds ends the suspicion; any other answer keeps it until the
    /// deadline, when the holder says it gave up (a card that shows up later
    /// is then an orphan until the next start). Run by its own task, not the
    /// bindings sweep: each destroy against a fibby that never answers costs
    /// the control timeout, and nobody's teardown waits behind that.
    pub async fn retry_suspects(&self) {
        let suspects = std::mem::take(&mut self.state.lock().await.suspects);
        let mut keep = Vec::new();
        for (reader, deadline) in suspects {
            match self.control.destroy(&reader).await {
                Ok(()) => {
                    tracing::warn!(%reader, "holder: destroyed a card that appeared after its create had failed");
                }
                Err(_) if std::time::Instant::now() < deadline => keep.push((reader, deadline)),
                Err(e) => {
                    tracing::warn!(%reader, "holder: gave up on a reader whose create had failed, found no card in time ({e}); a card that appears later stays until the next start");
                }
            }
        }
        self.state.lock().await.suspects.extend(keep);
    }

    /// Mark `key`'s binding retiring (see [`Binding::retiring`]). `false`
    /// when there is no such binding.
    pub async fn mark_retiring(&self, key: &KeyData) -> bool {
        let mut state = self.state.lock().await;
        match state.bindings.iter_mut().find(|b| b.key == *key) {
            Some(binding) => {
                binding.retiring = true;
                true
            }
            None => false,
        }
    }

    pub fn config(&self) -> &HolderConfig {
        &self.config
    }

    pub fn control(&self) -> &dyn CardControl {
        self.control.as_ref()
    }

    /// Which binding a mint under `scope` from `peer` gets, or the refusal:
    /// an absent scope is `scope-unbound` (the holder infers none until
    /// clown#244); a name with no definition is `unknown-scope`; a fixed
    /// cgroup the caller is not inside is `not-bound-scope` (the name is a
    /// claim, the peer is the proof).
    pub fn resolve_scope(
        &self,
        peer: &PeerStatus,
        scope: &str,
    ) -> Result<(String, Option<CgroupPath>), (Status, String)> {
        if crate::holder_ext::scope_is_absent(scope) {
            return Err((
                Status::ScopeUnbound,
                "no scope named, and this holder infers none; name one of its scopes".into(),
            ));
        }
        let Some(rule) = self.config.scopes.get(scope) else {
            // The names this holder defines are the operator's to read in its
            // log, not the caller's: a peer that names a scope it is not in
            // learns nothing about the others.
            let mut known: Vec<&str> = self.config.scopes.keys().map(String::as_str).collect();
            known.sort_unstable();
            tracing::info!(scope, defined = %known.join(", "), "holder: a mint named an undefined scope");
            return Err((
                Status::UnknownScope,
                format!("scope {scope:?} is not one this holder defines"),
            ));
        };
        // An `any` scope binds to no cgroup, so it asks nothing of the peer:
        // a connection whose credentials could not be read may mint under it.
        if matches!(rule, ScopeRule::Any) {
            return Ok((scope.to_string(), None));
        }
        let peer = match peer {
            PeerStatus::Known(peer) => peer,
            PeerStatus::Unknown(why) => return Err((Status::PeerUnknown, why.clone())),
            PeerStatus::NotRead => {
                return Err((
                    Status::PeerUnknown,
                    "the connection's peer was not read".into(),
                ));
            }
        };
        let cgroup = match rule {
            // A caller in the root cgroup would bind the key to every process.
            ScopeRule::Caller if peer.cgroup.is_root() => {
                return Err((
                    Status::NotBoundScope,
                    format!(
                        "the caller ({peer}) is in the root cgroup, which contains every process, so a key bound to it would bind to no one"
                    ),
                ));
            }
            ScopeRule::Caller => peer.cgroup.clone(),
            ScopeRule::Cgroup(path) if path.contains(&peer.cgroup) => path.clone(),
            ScopeRule::Cgroup(path) => {
                // The cgroup it binds to goes to the log, not to the caller.
                tracing::info!(scope, %path, %peer, "holder: a mint named a scope its caller is not inside");
                return Err((
                    Status::NotBoundScope,
                    format!("scope {scope:?} is not the caller's scope"),
                ));
            }
            ScopeRule::Any => unreachable!("an any scope returned above"),
        };
        Ok((scope.to_string(), Some(cgroup)))
    }

    /// Whether `peer` is inside `binding`'s scope and may sign with or
    /// retire its key.
    pub fn peer_may_use(
        &self,
        binding: &Binding,
        peer: &PeerStatus,
    ) -> Result<(), (Status, String)> {
        // A key minted under an `any` scope has no cgroup: the socket it was
        // minted on is its whole boundary, so every connection may use it. A
        // key with no cgroup on a holder that is NOT built that way (the
        // startup refusals live in `build_holder`, which `Holder::new` does
        // not repeat) is refused, not trusted.
        match &binding.cgroup {
            None if self.config.socket_is_the_boundary() => {}
            None => {
                tracing::warn!(scope = %binding.scope, "holder: a key bound to no cgroup on a holder whose socket is not its boundary");
                return Err((
                    Status::NotBoundScope,
                    "the key is bound to no cgroup, and this holder's socket is not its boundary"
                        .into(),
                ));
            }
            Some(cgroup) => match peer {
                PeerStatus::Known(peer) if cgroup.contains(&peer.cgroup) => {}
                PeerStatus::Known(peer) => {
                    // The key's scope and cgroup go to the log, not to a
                    // caller outside the scope.
                    tracing::info!(scope = %binding.scope, %cgroup, %peer, "holder: a peer outside a key's scope was refused it");
                    return Err((
                        Status::NotBoundScope,
                        "the key is not bound to the caller's scope".into(),
                    ));
                }
                PeerStatus::Unknown(why) => return Err((Status::PeerUnknown, why.clone())),
                PeerStatus::NotRead => {
                    return Err((
                        Status::PeerUnknown,
                        "the connection's peer was not read".into(),
                    ));
                }
            },
        }
        // Only a peer that is inside the scope is told what state the key is
        // in: a key whose card is being destroyed is usable by no one.
        if binding.retiring {
            return Err((Status::NotBoundScope, "the key is being retired".into()));
        }
        Ok(())
    }

    /// The binding of the card whose GUID is `guid`, if this holder minted it.
    pub async fn binding_of_guid(&self, guid: &Guid) -> Option<Binding> {
        self.state
            .lock()
            .await
            .bindings
            .iter()
            .find(|b| &b.guid == guid)
            .cloned()
    }

    /// At start, destroy every card fibby holds that this holder did not mint
    /// in this run: a `piggy-holder N` reader with no binding. Bindings and
    /// the retiring mark live in memory only, so after an agent restart a card
    /// whose destroy had failed (or that nothing retired) would stay signable
    /// over fibby's PC/SC socket and fill its reader table. A holder restart
    /// loses every key by design; this makes the cards agree. Returns the
    /// readers destroyed. A listing that fails is an `Err`: the caller says
    /// whether that is fatal (it is for a holder whose socket is its boundary,
    /// where an orphan nobody can see would stay signable over fibby's PC/SC
    /// socket); a destroy that fails is logged, and the card is retried by the
    /// next start.
    pub async fn destroy_orphans(&self) -> Result<Vec<String>, String> {
        let readers = self
            .control
            .readers()
            .await
            .map_err(|e| format!("could not list fibby's cards to destroy orphans: {e}"))?;
        let bound: Vec<String> = self
            .bindings()
            .await
            .into_iter()
            .map(|b| b.reader)
            .collect();
        let mut gone = Vec::new();
        let mut stuck = Vec::new();
        for reader in readers {
            if !reader.starts_with("piggy-holder ") || bound.contains(&reader) {
                continue;
            }
            match self.control.destroy(&reader).await {
                Ok(()) => gone.push(reader),
                Err(e) if e.contains("no such reader") => {}
                Err(e) => {
                    tracing::warn!(%reader, "holder: could not destroy an orphan card: {e}");
                    stuck.push(reader);
                }
            }
        }
        if !gone.is_empty() {
            tracing::warn!(readers = %gone.join(", "), "holder: destroyed cards left over from before this start");
        }
        // An orphan that could not be destroyed is still signable over
        // fibby's PC/SC socket: said as an error, and the caller decides
        // whether that is fatal (it is for a holder whose socket is its
        // boundary).
        if !stuck.is_empty() {
            return Err(format!(
                "could not destroy the cards left over from before this start: {}",
                stuck.join(", ")
            ));
        }
        Ok(gone)
    }

    /// Whether this holder holds the claim on its fibby ([`lock_fibby`]).
    pub fn holds_fibby_lock(&self) -> bool {
        self.fibby_lock.is_some()
    }

    /// Reserve a card slot under the cap and name its reader. A reservation
    /// counts against the cap until [`Self::record`] or
    /// [`Self::release_reservation`].
    pub async fn reserve_reader(&self) -> Result<String, (Status, String)> {
        let mut state = self.state.lock().await;
        if state.live >= self.config.cap {
            return Err((
                Status::CapReached,
                format!(
                    "this holder serves its cap of {} live cards; retire one first",
                    self.config.cap
                ),
            ));
        }
        state.live += 1;
        state.next_card += 1;
        Ok(format!("piggy-holder {}", state.next_card))
    }

    /// A mint that reserved a reader and then failed gives the slot back.
    pub async fn release_reservation(&self) {
        let mut state = self.state.lock().await;
        state.live = state.live.saturating_sub(1);
    }

    pub async fn record(&self, binding: Binding) {
        self.state.lock().await.bindings.push(binding);
    }

    pub async fn binding_of(&self, key: &KeyData) -> Option<Binding> {
        self.state
            .lock()
            .await
            .bindings
            .iter()
            .find(|b| b.key == *key)
            .cloned()
    }

    pub async fn bindings(&self) -> Vec<Binding> {
        self.state.lock().await.bindings.clone()
    }

    /// Forget a binding whose card is gone; frees its slot under the cap.
    pub async fn remove(&self, key: &KeyData) -> Option<Binding> {
        let mut state = self.state.lock().await;
        let index = state.bindings.iter().position(|b| b.key == *key)?;
        state.live = state.live.saturating_sub(1);
        Some(state.bindings.remove(index))
    }

    /// The number of live cards (bound or being minted).
    pub async fn live(&self) -> usize {
        self.state.lock().await.live
    }

    /// Whether `binding`'s cgroup still exists under the configured root. A
    /// binding with no cgroup (an `any` scope) has nothing to vanish.
    pub fn cgroup_exists(&self, binding: &Binding) -> bool {
        binding
            .cgroup
            .as_ref()
            .is_none_or(|cgroup| cgroup.directory_under(&self.config.cgroup_root).is_dir())
    }
}

/// What a connection knows about its peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerStatus {
    /// Not a holder, so nothing was read.
    NotRead,
    Known(Peer),
    /// The read failed; the reason.
    Unknown(String),
}

/// A fresh random PIN for a minted card: 8 characters of `[0-9A-Za-z]`
/// from the OS entropy source, held zeroizing. The holder caches it on
/// guarded pages; the caller never sees it.
pub fn random_pin() -> Result<Zeroizing<String>, String> {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    // Rejection sampling: 248 = 4 * 62, so every accepted byte is uniform.
    const LIMIT: u8 = 248;
    let mut pin = Zeroizing::new(String::with_capacity(8));
    let mut buf = Zeroizing::new([0u8; 32]);
    while pin.len() < 8 {
        openssl::rand::rand_bytes(&mut buf[..]).map_err(|e| format!("random PIN: {e}"))?;
        for byte in buf.iter() {
            if *byte < LIMIT && pin.len() < 8 {
                pin.push(ALPHABET[(*byte % 62) as usize] as char);
            }
        }
    }
    Ok(pin)
}

/// A card as the mint leaves it.
#[derive(Debug, Clone)]
pub struct MintedCard {
    pub guid: Guid,
    pub algorithm: piggy_piv::PivAlgorithm,
    pub public_key: KeyData,
}

/// Over PC/SC, on the card fibby just created as `reader`: read slot 9A
/// and replace the factory PIN with `new_pin`. Blocking (card IO); the
/// caller runs it under the card lock in a blocking task.
pub fn provision_minted_card(reader: &str, new_pin: &str) -> Result<MintedCard, String> {
    let ctx = piggy_piv::PivContext::new().map_err(|e| format!("PC/SC: {e}"))?;
    let mut token = piggy_piv::PivToken::connect(&ctx, reader)
        .map_err(|e| format!("connect {reader:?}: {e}"))?;
    let slot = token
        .read_slot(MINTED_SLOT)
        .map_err(|e| format!("{reader:?}: read slot {MINTED_SLOT:02X}: {e}"))?;
    let card = MintedCard {
        guid: token.guid().clone(),
        algorithm: slot.algorithm(),
        public_key: slot.public_key().key_data().clone(),
    };
    let mut session = token
        .begin_pin_session()
        .map_err(|e| format!("{reader:?}: begin session: {e}"))?;
    session
        .change_pin(FACTORY_PIN, new_pin)
        .map_err(|e| format!("{reader:?}: replace the factory PIN: {e}"))?;
    Ok(card)
}

/// Destroy a minted card and forget everything about it: the card store's
/// `destroy`, the served key, the PIN, the binding.
///
/// The binding is marked RETIRING first: from then on the key is usable by no
/// one ([`Holder::peer_may_use`]) however the card reconcile loop treats a
/// card fibby still holds (it may serve the key again; it stays unusable), and
/// [`sweep_bindings`] keeps trying the destroy for as long as the mark stands.
/// The mark is explicit and never inferred from a key being absent from the
/// served set (that loop drops keys on a PC/SC blip too). A `destroy` that
/// fails leaves the card and the binding in place and is reported; "no such
/// reader" is a card already gone, which is what was wanted. One teardown at a
/// time, so a retire and the watcher's retry do not race on one reader.
pub async fn teardown(
    holder: &Holder,
    keys: &Arc<Mutex<Vec<CachedKey>>>,
    pins: &Arc<Mutex<PinCache>>,
    binding: &Binding,
    why: &str,
) -> Result<(), String> {
    let _one_at_a_time = holder.teardown_lock.lock().await;
    if !holder.mark_retiring(&binding.key).await {
        // Another teardown finished it while this one waited.
        return Ok(());
    }
    keys.lock().await.retain(|k| k.public_key != binding.key);
    pins.lock().await.forget_card(&binding.guid);
    match holder.control().destroy(&binding.reader).await {
        Ok(()) => {}
        Err(e) if e.contains("no such reader") => {}
        Err(e) => return Err(e),
    }
    holder.remove(&binding.key).await;
    tracing::info!(
        reader = %binding.reader,
        scope = %binding.scope,
        cgroup = %binding.cgroup.as_ref().map_or_else(|| "(none: any)".to_string(), ToString::to_string),
        "holder: card destroyed ({why})"
    );
    Ok(())
}

/// One pass of the teardown watcher: every binding whose cgroup directory
/// is gone, or that is marked retiring (a destroy that failed earlier), is
/// torn down. Returns the readers torn down.
pub async fn sweep_bindings(
    holder: &Holder,
    keys: &Arc<Mutex<Vec<CachedKey>>>,
    pins: &Arc<Mutex<PinCache>>,
) -> Vec<String> {
    let mut gone = Vec::new();
    for binding in holder.bindings().await {
        let why = if !holder.cgroup_exists(&binding) {
            "its scope exited"
        } else if binding.retiring {
            "a retire could not finish; destroying the card again"
        } else {
            continue;
        };
        match teardown(holder, keys, pins, &binding, why).await {
            Ok(()) => gone.push(binding.reader),
            Err(e) => tracing::warn!(
                reader = %binding.reader,
                "holder: {why}, but the card could not be destroyed ({e}); retrying"
            ),
        }
    }
    gone
}

/// The teardown watcher: sweeps every `poll_interval` for the life of the
/// agent.
pub async fn watch_bindings(
    holder: Arc<Holder>,
    keys: Arc<Mutex<Vec<CachedKey>>>,
    pins: Arc<Mutex<PinCache>>,
) {
    let interval = holder.config().poll_interval;
    // The suspect readers (a mint's failed create) in a task of their own: a
    // destroy against a fibby that never answers costs the control timeout,
    // and no caller's teardown waits behind it.
    let for_suspects = holder.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            for_suspects.retry_suspects().await;
        }
    });
    loop {
        tokio::time::sleep(interval).await;
        sweep_bindings(&holder, &keys, &pins).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// A card store that records what it was asked.
    #[derive(Default)]
    struct Recorder {
        calls: StdMutex<Vec<String>>,
        fail_destroy: bool,
        /// `destroy` answers "no such reader" (the card is already gone).
        already_gone: bool,
        /// The readers the store lists.
        readers: Vec<String>,
        /// `readers` fails (fibby cannot be listed).
        list_fails: bool,
        /// The first this-many `destroy` calls answer "no such reader" (a
        /// slow fibby that has not made the card yet), then one succeeds.
        late_after: usize,
    }

    #[ssh_agent_lib::async_trait]
    impl CardControl for Recorder {
        async fn create(&self, alg: &str, reader: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("create {alg} {reader}"));
            Ok(())
        }
        async fn readers(&self) -> Result<Vec<String>, String> {
            if self.list_fails {
                return Err("the card store is down".into());
            }
            Ok(self.readers.clone())
        }
        async fn destroy(&self, reader: &str) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("destroy {reader}"));
            // Let another task run mid-destroy, as a real card store's
            // socket round trip does: a test of two racing teardowns sees
            // the race, not a destroy that finishes before the other starts.
            tokio::task::yield_now().await;
            if self.late_after > 0 && self.calls.lock().unwrap().len() <= self.late_after {
                Err(format!("no such reader: {reader}"))
            } else if self.already_gone {
                // fibby's own words for a card it does not have.
                Err(format!("no such reader: {reader}"))
            } else if self.fail_destroy {
                Err("the card store is down".into())
            } else {
                Ok(())
            }
        }
    }

    fn cg(s: &str) -> CgroupPath {
        CgroupPath::parse(s).unwrap()
    }

    fn peer_in(cgroup: &str) -> Peer {
        Peer {
            uid: 1000,
            pid: 4242,
            cgroup: cg(cgroup),
        }
    }

    fn key(seed: u8) -> KeyData {
        KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([seed; 32]))
    }

    fn holder_with(scopes: &[(&str, ScopeRule)], root: &std::path::Path) -> Holder {
        Holder::new(
            HolderConfig {
                scopes: scopes
                    .iter()
                    .map(|(n, r)| (n.to_string(), r.clone()))
                    .collect(),
                cgroup_root: root.to_path_buf(),
                poll_interval: Duration::from_millis(10),
                cap: 2,
            },
            Box::new(Recorder::default()),
        )
    }

    fn binding(seed: u8, reader: &str, cgroup: &str) -> Binding {
        Binding {
            key: key(seed),
            guid: Guid::from_bytes(&[seed; 16]).unwrap(),
            reader: reader.into(),
            scope: "piggy-mint-v1".into(),
            cgroup: Some(cg(cgroup)),
            retiring: false,
        }
    }

    /// A card store whose calls the test can read afterwards (the holder owns
    /// its store, so the test keeps a second handle).
    struct Shared(Arc<Recorder>);

    #[ssh_agent_lib::async_trait]
    impl CardControl for Shared {
        async fn create(&self, alg: &str, reader: &str) -> Result<(), String> {
            self.0.create(alg, reader).await
        }
        async fn destroy(&self, reader: &str) -> Result<(), String> {
            self.0.destroy(reader).await
        }
        async fn readers(&self) -> Result<Vec<String>, String> {
            self.0.readers().await
        }
    }

    fn known(cgroup: &str) -> PeerStatus {
        PeerStatus::Known(peer_in(cgroup))
    }

    #[test]
    fn scope_specs_parse_and_the_name_is_opaque() {
        assert_eq!(
            parse_scope_spec("piggy-mint-v1=caller").unwrap(),
            ("piggy-mint-v1".into(), ScopeRule::Caller)
        );
        assert_eq!(
            parse_scope_spec("piggy-ca-v1=cgroup:/system.slice/piggy-ca.service").unwrap(),
            (
                "piggy-ca-v1".into(),
                ScopeRule::Cgroup(cg("/system.slice/piggy-ca.service"))
            )
        );
        // A payload-shaped name is just a name; the split is at '='.
        assert_eq!(
            parse_scope_spec("piggy-mint-v1@blake2b256-abc=caller")
                .unwrap()
                .0,
            "piggy-mint-v1@blake2b256-abc"
        );
        for bad in ["piggy-mint-v1", "=caller", "x=cgroup:relative", "x=magic"] {
            assert!(parse_scope_spec(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_absent_scope_is_unbound_and_an_undefined_one_unknown() {
        let holder = holder_with(
            &[("piggy-mint-v1", ScopeRule::Caller)],
            std::path::Path::new("/nonexistent"),
        );
        let peer = known("/user.slice/s.scope");
        assert_eq!(
            holder.resolve_scope(&peer, "").unwrap_err().0,
            Status::ScopeUnbound
        );
        let (status, detail) = holder.resolve_scope(&peer, "piggy-mint-v2").unwrap_err();
        assert_eq!(status, Status::UnknownScope);
        // Round 2, L5: the names this holder defines are the log's, not the
        // caller's.
        assert!(!detail.contains("piggy-mint-v1"), "{detail}");
    }

    #[test]
    fn caller_binds_to_the_peers_cgroup_and_a_fixed_cgroup_needs_the_peer_inside() {
        let holder = holder_with(
            &[
                ("piggy-mint-v1", ScopeRule::Caller),
                ("unit-v1", ScopeRule::Cgroup(cg("/system.slice/u.service"))),
            ],
            std::path::Path::new("/nonexistent"),
        );
        let peer = known("/user.slice/s.scope");
        assert_eq!(
            holder.resolve_scope(&peer, "piggy-mint-v1").unwrap(),
            ("piggy-mint-v1".into(), Some(cg("/user.slice/s.scope")))
        );
        // The name is a claim: a peer outside the fixed cgroup is refused.
        assert_eq!(
            holder.resolve_scope(&peer, "unit-v1").unwrap_err().0,
            Status::NotBoundScope
        );
        let inside = known("/system.slice/u.service/child");
        assert_eq!(
            holder.resolve_scope(&inside, "unit-v1").unwrap(),
            ("unit-v1".into(), Some(cg("/system.slice/u.service")))
        );
        // A cgroup rule needs a peer that was read; an unread one is refused.
        for unread in [PeerStatus::Unknown("no pid".into()), PeerStatus::NotRead] {
            for scope in ["piggy-mint-v1", "unit-v1"] {
                assert_eq!(
                    holder.resolve_scope(&unread, scope).unwrap_err().0,
                    Status::PeerUnknown,
                    "{scope} {unread:?}"
                );
            }
        }
    }

    // Shape A (a holder per session): an `any` scope binds to no cgroup and
    // reads no peer; the socket is the boundary.

    #[test]
    fn an_any_scope_binds_to_nothing_whoever_asks_even_an_unread_peer() {
        assert_eq!(
            parse_scope_spec("session=any").unwrap(),
            ("session".into(), ScopeRule::Any)
        );
        let holder = holder_with(
            &[("session", ScopeRule::Any)],
            std::path::Path::new("/nonexistent"),
        );
        for peer in [
            known("/user.slice/anything.scope"),
            PeerStatus::Unknown("no pid".into()),
            PeerStatus::NotRead,
        ] {
            assert_eq!(
                holder.resolve_scope(&peer, "session").unwrap(),
                ("session".into(), None),
                "{peer:?}"
            );
        }
        // An absent or undefined name is still refused, as for any rule.
        assert_eq!(
            holder
                .resolve_scope(&PeerStatus::NotRead, "")
                .unwrap_err()
                .0,
            Status::ScopeUnbound
        );
        assert_eq!(
            holder
                .resolve_scope(&PeerStatus::NotRead, "other")
                .unwrap_err()
                .0,
            Status::UnknownScope
        );
    }

    #[test]
    fn a_key_with_no_cgroup_is_usable_from_every_connection_of_a_holder_built_for_it() {
        let holder = holder_with(
            &[("session", ScopeRule::Any)],
            std::path::Path::new("/nonexistent"),
        );
        let mut b = binding(1, "piggy-holder 1", "/unused");
        b.cgroup = None;
        for peer in [
            known("/user.slice/a.scope"),
            known("/system.slice/other.service"),
            PeerStatus::Unknown("no pid".into()),
            PeerStatus::NotRead,
        ] {
            assert!(holder.peer_may_use(&b, &peer).is_ok(), "{peer:?}");
        }
        assert!(holder.cgroup_exists(&b), "no cgroup, so nothing to vanish");
    }

    // Round 1, L5: a binding with no cgroup is trusted only by a holder whose
    // socket is its boundary; on any other holder it is refused.
    #[test]
    fn a_key_with_no_cgroup_is_refused_by_a_holder_that_is_not_built_for_it() {
        let holder = holder_with(
            &[("piggy-mint-v1", ScopeRule::Caller)],
            std::path::Path::new("/nonexistent"),
        );
        let mut b = binding(1, "piggy-holder 1", "/unused");
        b.cgroup = None;
        for peer in [known("/user.slice/a.scope"), PeerStatus::NotRead] {
            assert_eq!(
                holder.peer_may_use(&b, &peer).unwrap_err().0,
                Status::NotBoundScope,
                "{peer:?}"
            );
        }
    }

    // Round 1, L6: the root cgroup contains every process, so no scope binds
    // to it.
    #[test]
    fn no_scope_binds_to_the_root_cgroup() {
        for spec in ["x=cgroup:/", "x=cgroup://"] {
            let err = parse_scope_spec(spec).unwrap_err();
            assert!(err.contains("root cgroup"), "{spec}: {err}");
        }
        let holder = holder_with(
            &[("piggy-mint-v1", ScopeRule::Caller)],
            std::path::Path::new("/nonexistent"),
        );
        let err = holder
            .resolve_scope(&known("/"), "piggy-mint-v1")
            .unwrap_err();
        assert_eq!(err.0, Status::NotBoundScope);
        assert!(err.1.contains("root cgroup"), "{}", err.1);
    }

    // Round 1, M1: with an `any` scope all three sockets are private, in
    // directories of their own. Round 2, L3 (nesting) and L4 (symlinks, and
    // fibby's two must be real sockets).
    #[test]
    fn the_three_sockets_of_an_any_holder_must_be_private_apart_and_real() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        // A short path: a unix socket's name is limited to about 100 bytes,
        // which the usual test directory under a long worktree path exceeds.
        let root = std::path::PathBuf::from(format!(
            "/tmp/hs{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(&root).unwrap();
        let dir = |name: &str| {
            let d = root.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            d
        };
        let agent = dir("a").join("agent.sock");
        let ctl = dir("d").join("ctl.sock");
        let pcsc = dir("p").join("pcscd.comm");
        let _ctl_socket = UnixListener::bind(&ctl).unwrap();
        let _pcsc_socket = UnixListener::bind(&pcsc).unwrap();
        assert_eq!(
            check_boundary_sockets(&agent, &ctl, Some(&pcsc), uid),
            Ok(())
        );
        // The same directory as fibby's ctl or PC/SC socket is refused.
        let same_ctl = root.join("a/ctl.sock");
        let _s1 = UnixListener::bind(&same_ctl).unwrap();
        let err = check_boundary_sockets(&agent, &same_ctl, Some(&pcsc), uid).unwrap_err();
        assert!(err.contains("own directory"), "{err}");
        let same_pcsc = root.join("a/pcscd.comm");
        let _s2 = UnixListener::bind(&same_pcsc).unwrap();
        let err = check_boundary_sockets(&agent, &ctl, Some(&same_pcsc), uid).unwrap_err();
        assert!(err.contains("own directory"), "{err}");
        // A directory UNDER the agent's is held by whoever holds the agent's.
        let nested = dir("a/fibby").join("ctl.sock");
        let _s3 = UnixListener::bind(&nested).unwrap();
        let err = check_boundary_sockets(&agent, &nested, Some(&pcsc), uid).unwrap_err();
        assert!(err.contains("or under it"), "{err}");
        // A PC/SC socket that is not named at all is refused.
        let err = check_boundary_sockets(&agent, &ctl, None, uid).unwrap_err();
        assert!(err.contains("PCSCLITE_CSOCK_NAME"), "{err}");
        // Each of the three directories must itself be private.
        for which in ["a", "d", "p"] {
            let path = root.join(which);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
            let err = check_boundary_sockets(&agent, &ctl, Some(&pcsc), uid).unwrap_err();
            assert!(err.contains("private"), "{which}: {err}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // A symlink in place of a socket (it could lead out of the private
        // directory) is refused, for fibby's two and the agent's.
        let link = root.join("d/link.sock");
        std::os::unix::fs::symlink(&ctl, &link).unwrap();
        let err = check_boundary_sockets(&agent, &link, Some(&pcsc), uid).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        let err = check_boundary_sockets(&agent, &ctl, Some(&link), uid).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        let agent_link = root.join("a/agent-link.sock");
        std::os::unix::fs::symlink(&ctl, &agent_link).unwrap();
        let err = check_boundary_sockets(&agent_link, &ctl, Some(&pcsc), uid).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
        // Fibby's two must exist and be sockets: fibby is started first.
        let missing = root.join("d/not-yet.sock");
        let err = check_boundary_sockets(&agent, &missing, Some(&pcsc), uid).unwrap_err();
        assert!(err.contains("fibby must be running"), "{err}");
        let plain = root.join("p/plain");
        std::fs::write(&plain, b"x").unwrap();
        let err = check_boundary_sockets(&agent, &ctl, Some(&plain), uid).unwrap_err();
        assert!(err.contains("not a socket"), "{err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Round 1, L3 and round 2, M1: a retire whose destroy fails leaves the
    // key usable by no one, whatever the card reconcile loop does with a card
    // fibby still holds, and the watcher destroys the card on a later pass.
    #[tokio::test]
    async fn a_failed_destroy_leaves_the_key_unusable_even_if_reconcile_serves_it_again() {
        let root = tempdir();
        let recorder = Arc::new(Recorder {
            fail_destroy: true,
            ..Recorder::default()
        });
        let failing = Holder::new(
            HolderConfig {
                scopes: [("session".to_string(), ScopeRule::Any)]
                    .into_iter()
                    .collect(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Shared(recorder.clone())),
        );
        let mut a = binding(1, "piggy-holder 1", "/unused");
        a.cgroup = None;
        failing.reserve_reader().await.unwrap();
        failing.record(a.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        let usable = |b: &Binding| failing.peer_may_use(b, &PeerStatus::NotRead).is_ok();
        assert!(usable(&failing.binding_of(&a.key).await.unwrap()));

        // The retire path: the destroy fails.
        assert!(
            teardown(&failing, &keys, &pins, &a, "retired")
                .await
                .is_err()
        );
        assert!(keys.lock().await.is_empty(), "the key is no longer served");
        let kept = failing.binding_of(&a.key).await.unwrap();
        assert!(kept.retiring, "kept, and marked, to retry");
        assert!(!usable(&kept), "a retiring key is usable by no one");

        // The reconcile loop sees the card fibby still holds and serves the
        // key again: it is still refused, because the mark is on the binding.
        keys.lock().await.push(cached(&a));
        assert!(!usable(&failing.binding_of(&a.key).await.unwrap()));

        // The watcher retries on the mark (the destroy still fails here).
        let before = recorder.calls.lock().unwrap().len();
        assert!(sweep_bindings(&failing, &keys, &pins).await.is_empty());
        assert!(recorder.calls.lock().unwrap().len() > before, "retried");

        // A holder whose destroy works finishes the job.
        let working = holder_with(&[("session", ScopeRule::Any)], &root);
        working.reserve_reader().await.unwrap();
        working
            .record(Binding {
                retiring: true,
                ..a.clone()
            })
            .await;
        let gone = sweep_bindings(&working, &keys, &pins).await;
        assert_eq!(gone, vec!["piggy-holder 1".to_string()]);
        assert!(working.bindings().await.is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Round 2, M2: "binding present, key not served" is NOT a retire. The card
    // reconcile loop drops keys on a PC/SC blip, and the sweep must not turn
    // that into destroyed cards.
    #[tokio::test]
    async fn a_key_the_reconcile_loop_dropped_is_not_destroyed_by_the_sweep() {
        let root = tempdir();
        let recorder = Arc::new(Recorder::default());
        let holder = Holder::new(
            HolderConfig {
                scopes: [("session".to_string(), ScopeRule::Any)]
                    .into_iter()
                    .collect(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Shared(recorder.clone())),
        );
        let mut a = binding(1, "piggy-holder 1", "/unused");
        a.cgroup = None;
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        // No key served: the loop dropped it (an enumeration error empties the
        // set), nobody retired anything.
        let keys = Arc::new(Mutex::new(Vec::<CachedKey>::new()));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        for _ in 0..3 {
            assert!(sweep_bindings(&holder, &keys, &pins).await.is_empty());
        }
        assert!(
            recorder.calls.lock().unwrap().is_empty(),
            "the sweep destroyed a card nobody retired"
        );
        assert_eq!(holder.bindings().await, vec![a]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Round 2, L2: a destroy that finds no such card has what it wanted.
    #[tokio::test]
    async fn a_card_that_is_already_gone_is_a_finished_teardown() {
        let root = tempdir();
        let holder = Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Recorder {
                already_gone: true,
                ..Recorder::default()
            }),
        );
        let a = binding(1, "piggy-holder 1", "/unused");
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        teardown(&holder, &keys, &pins, &a, "retired")
            .await
            .unwrap();
        assert!(holder.bindings().await.is_empty());
        assert_eq!(holder.live().await, 0, "the cap slot is free again");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Round 2, L1: two teardowns of one card (a retire and the watcher) end
    // with one destroy.
    #[tokio::test]
    async fn two_teardowns_of_one_card_destroy_it_once() {
        let root = tempdir();
        let recorder = Arc::new(Recorder::default());
        let holder = Arc::new(Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Shared(recorder.clone())),
        ));
        let a = binding(1, "piggy-holder 1", "/unused");
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        let (one, two) = tokio::join!(
            teardown(&holder, &keys, &pins, &a, "retired"),
            teardown(&holder, &keys, &pins, &a, "its scope exited"),
        );
        assert!(one.is_ok() && two.is_ok());
        assert_eq!(
            recorder.calls.lock().unwrap().len(),
            1,
            "a destroy per teardown: the lock that serialises them is gone"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Round 3, L2: a fibby that accepts a command and never answers costs a
    // failed command, not a hung teardown (which holds the teardown lock and
    // so would stall the watcher and every retire).
    #[tokio::test]
    async fn a_fibby_that_never_answers_costs_a_failed_command_not_a_hung_one() {
        let dir = std::path::PathBuf::from(format!("/tmp/hc{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let silent = std::thread::spawn(move || {
            // Accept, read nothing, say nothing, hold the connection.
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            drop(stream);
        });
        let control = FibbyControl::new(&path).with_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let err = control.destroy("piggy-holder 1").await.unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}: {err}",
            started.elapsed()
        );
        assert!(!err.is_empty());
        silent.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Round 3, L3: bindings are memory only, so at start the cards of an
    // earlier run are destroyed: every `piggy-holder N` reader with no
    // binding, and nothing else.
    #[tokio::test]
    async fn at_start_every_unbound_piggy_holder_card_is_destroyed_and_nothing_else() {
        let root = tempdir();
        let recorder = Arc::new(Recorder {
            readers: vec![
                "Virtual PCD piggy fibby 00 00".into(),
                "piggy-holder 3".into(),
                "piggy-holder 7".into(),
                "piggy-holder 9".into(),
            ],
            ..Recorder::default()
        });
        let holder = Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Shared(recorder.clone())),
        );
        // `piggy-holder 9` was minted in this run.
        holder.reserve_reader().await.unwrap();
        holder.record(binding(1, "piggy-holder 9", "/unused")).await;
        let gone = holder.destroy_orphans().await.unwrap();
        assert_eq!(gone, ["piggy-holder 3", "piggy-holder 7"]);
        assert_eq!(
            *recorder.calls.lock().unwrap(),
            ["destroy piggy-holder 3", "destroy piggy-holder 7"]
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Follow-up (4th read, 2): a fibby belongs to one holder agent; a second
    // claim on the same control socket is a refusal, not a convention.
    #[test]
    fn a_second_holder_on_one_fibby_is_refused_and_a_released_claim_is_free_again() {
        let root = std::path::PathBuf::from(format!("/tmp/pgfibby{}", std::process::id()));
        let dir_a = root.join("a");
        let dir_b = root.join("b");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();
        let first = lock_fibby(&dir_a.join("ctl.sock")).unwrap();
        // The same DIRECTORY is the same fibby, whatever the socket's name or
        // the spelling of the path to it (the claim is on the inode).
        for spelled in [
            dir_a.join("ctl.sock"),
            dir_a.join("other.sock"),
            dir_a.join("../a/ctl.sock"),
        ] {
            let err = lock_fibby(&spelled)
                .err()
                .expect("a second claim is refused");
            assert!(err.contains("never share a fibby"), "{spelled:?}: {err}");
        }
        // Another fibby (another directory) is another claim.
        let _second_fibby = lock_fibby(&dir_b.join("ctl.sock")).unwrap();
        // The agent ending (the claim dropped) frees it.
        drop(first);
        assert!(lock_fibby(&dir_a.join("ctl.sock")).is_ok());
        // A directory that cannot be opened is an error, not "no claim".
        let err = lock_fibby(&root.join("missing/ctl.sock")).err().unwrap();
        assert!(err.contains("cannot open"), "{err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Follow-up review, 6: a mint that gave up on a reader (its create failed)
    // may find the card appear late; the watcher keeps trying the destroy for
    // a while, stops once it finds the card, and stops for good when its
    // window (SUSPECT_FOR, a time, not a count of passes) runs out.
    #[tokio::test]
    async fn a_suspect_reader_is_retried_until_its_card_is_found_or_its_window_runs_out() {
        let holder_over = |recorder: &Arc<Recorder>| {
            Holder::new(
                HolderConfig {
                    scopes: HashMap::new(),
                    cgroup_root: "/nonexistent".into(),
                    poll_interval: Duration::from_millis(10),
                    cap: CARD_CAP,
                },
                Box::new(Shared(recorder.clone())),
            )
        };
        // The card appears after two "no such reader" answers.
        let late = Arc::new(Recorder {
            late_after: 2,
            ..Recorder::default()
        });
        let holder = holder_over(&late);
        holder.add_suspect("piggy-holder 5").await;
        for _ in 0..6 {
            holder.retry_suspects().await;
        }
        assert_eq!(
            late.calls.lock().unwrap().len(),
            3,
            "two misses, then the destroy that found the card, then no more"
        );
        // A card that never appears: tried for the window, and no longer.
        let never = Arc::new(Recorder {
            already_gone: true,
            ..Recorder::default()
        });
        let holder = holder_over(&never);
        holder
            .add_suspect_for("piggy-holder 6", Duration::from_millis(150))
            .await;
        for _ in 0..4 {
            holder.retry_suspects().await;
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let inside_the_window = never.calls.lock().unwrap().len();
        assert!(inside_the_window >= 3, "{inside_the_window}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        holder.retry_suspects().await; // the pass that finds the window over
        let at_expiry = never.calls.lock().unwrap().len();
        for _ in 0..4 {
            holder.retry_suspects().await;
        }
        assert_eq!(
            never.calls.lock().unwrap().len(),
            at_expiry,
            "tried again after its window had run out"
        );
        // The list is capped: the oldest is dropped, the newest kept.
        let capped = Arc::new(Recorder::default());
        let holder = holder_over(&capped);
        for n in 0..(CARD_CAP + 3) {
            holder.add_suspect(&format!("piggy-holder {n}")).await;
        }
        holder.retry_suspects().await;
        assert_eq!(capped.calls.lock().unwrap().len(), CARD_CAP);
        assert_eq!(
            capped.calls.lock().unwrap().first().unwrap(),
            "destroy piggy-holder 3",
            "the three oldest were dropped"
        );
    }

    // Second read, (c): an orphan that could not be destroyed is an error (the
    // caller makes it fatal for a holder whose socket is its boundary); one that
    // is already gone is not.
    #[tokio::test]
    async fn an_orphan_that_cannot_be_destroyed_is_an_error_not_a_log_line() {
        let over = |recorder: Recorder| {
            Holder::new(
                HolderConfig {
                    scopes: HashMap::new(),
                    cgroup_root: "/nonexistent".into(),
                    poll_interval: Duration::from_millis(10),
                    cap: CARD_CAP,
                },
                Box::new(recorder),
            )
        };
        let stuck = over(Recorder {
            readers: vec!["piggy-holder 3".into(), "piggy-holder 4".into()],
            fail_destroy: true,
            ..Recorder::default()
        });
        let err = stuck.destroy_orphans().await.unwrap_err();
        assert!(
            err.contains("piggy-holder 3") && err.contains("piggy-holder 4"),
            "{err}"
        );
        let gone = over(Recorder {
            readers: vec!["piggy-holder 3".into()],
            already_gone: true,
            ..Recorder::default()
        });
        assert_eq!(gone.destroy_orphans().await.unwrap(), Vec::<String>::new());
    }

    // Second read, (f): a symlink where fibby's control socket should be is
    // refused by every holder.
    #[test]
    fn a_symlinked_control_socket_is_refused() {
        let root = std::path::PathBuf::from(format!("/tmp/pglink{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real.sock");
        std::fs::write(&real, b"").unwrap();
        let link = root.join("ctl.sock");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = lock_fibby(&link).err().expect("refused");
        assert!(err.contains("is a symlink"), "{err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // Follow-up (4th read, 6): a listing that fails is an error, so a holder
    // whose socket is its boundary can refuse to start over cards it cannot
    // see; nothing is destroyed on a guess.
    #[tokio::test]
    async fn a_failed_listing_is_an_error_and_destroys_nothing() {
        let recorder = Arc::new(Recorder {
            list_fails: true,
            readers: vec!["piggy-holder 3".into()],
            ..Recorder::default()
        });
        let holder = Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: "/nonexistent".into(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Shared(recorder.clone())),
        );
        let err = holder.destroy_orphans().await.unwrap_err();
        assert!(err.contains("could not list"), "{err}");
        assert!(recorder.calls.lock().unwrap().is_empty());
    }

    // Follow-up (4th read, 5): a destroy that times out leaves the binding
    // marked retiring and the key unserved (the watcher retries it).
    #[tokio::test]
    async fn a_destroy_that_times_out_leaves_the_binding_retiring() {
        let dir = std::path::PathBuf::from(format!("/tmp/hd{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let silent = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
            drop(stream);
        });
        let holder = Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: "/nonexistent".into(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(FibbyControl::new(&path).with_timeout(Duration::from_millis(200))),
        );
        let a = binding(1, "piggy-holder 1", "/unused");
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        assert!(
            teardown(&holder, &keys, &pins, &a, "retired")
                .await
                .is_err()
        );
        assert!(holder.binding_of(&a.key).await.unwrap().retiring);
        assert!(keys.lock().await.is_empty());
        silent.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Round 3, L5: a peer outside the scope is told nothing about the key's
    // state, not even that it is being retired.
    #[test]
    fn a_peer_outside_the_scope_is_not_told_the_key_is_retiring() {
        let holder = holder_with(&[], std::path::Path::new("/nonexistent"));
        let mut b = binding(1, "piggy-holder 1", "/user.slice/a.scope");
        b.retiring = true;
        let outside = holder
            .peer_may_use(&b, &known("/user.slice/b.scope"))
            .unwrap_err();
        assert!(!outside.1.contains("retir"), "{}", outside.1);
        let inside = holder
            .peer_may_use(&b, &known("/user.slice/a.scope"))
            .unwrap_err();
        assert!(inside.1.contains("being retired"), "{}", inside.1);
    }

    #[tokio::test]
    async fn the_sweep_never_tears_down_a_key_that_has_no_cgroup() {
        let root = tempdir();
        let holder = Arc::new(Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Recorder::default()),
        ));
        let mut a = binding(1, "piggy-holder 1", "/gone.scope");
        a.cgroup = None;
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        assert!(sweep_bindings(&holder, &keys, &pins).await.is_empty());
        assert_eq!(holder.bindings().await, vec![a]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_holder_with_an_any_scope_has_only_any_scopes() {
        let cfg = |scopes: &[(&str, ScopeRule)]| HolderConfig {
            scopes: scopes
                .iter()
                .map(|(n, r)| (n.to_string(), r.clone()))
                .collect(),
            cgroup_root: "/sys/fs/cgroup".into(),
            poll_interval: Duration::from_secs(1),
            cap: 1,
        };
        assert!(
            cfg(&[("a", ScopeRule::Any), ("b", ScopeRule::Any)])
                .check_scopes_agree()
                .is_ok()
        );
        assert!(
            cfg(&[("a", ScopeRule::Caller), ("b", ScopeRule::Caller)])
                .check_scopes_agree()
                .is_ok()
        );
        assert!(
            cfg(&[("a", ScopeRule::Any), ("b", ScopeRule::Caller)])
                .check_scopes_agree()
                .is_err()
        );
        assert!(
            cfg(&[("a", ScopeRule::Any), ("b", ScopeRule::Cgroup(cg("/x")))])
                .check_scopes_agree()
                .is_err()
        );
        assert!(cfg(&[("a", ScopeRule::Any)]).socket_is_the_boundary());
        assert!(!cfg(&[("a", ScopeRule::Caller)]).socket_is_the_boundary());
    }

    #[test]
    fn the_private_socket_check_wants_the_agents_own_directory_with_no_group_or_other_bits() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let dir = tempdir();
        let sock = dir.join("agent.sock");
        for (mode, ok) in [
            (0o700, true),
            (0o500, true),
            (0o750, false),
            (0o710, false),
            (0o770, false),
            (0o755, false),
            (0o701, false),
        ] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                check_private_socket_dir(&sock, uid).is_ok(),
                ok,
                "mode {mode:o}"
            );
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Not the agent's directory: owned by another uid (any uid but ours).
        let err = check_private_socket_dir(&sock, uid.wrapping_add(1)).unwrap_err();
        assert!(err.contains("owned by uid"), "{err}");
        // No such directory, and the socket's directory a file.
        assert!(check_private_socket_dir(&dir.join("no/such/agent.sock"), uid).is_err());
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(check_private_socket_dir(&file.join("agent.sock"), uid).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_sibling_may_not_use_a_bound_key_and_an_unread_peer_may_not_either() {
        let holder = holder_with(&[], std::path::Path::new("/nonexistent"));
        let b = binding(1, "piggy-holder 1", "/user.slice/a.scope");
        assert!(
            holder
                .peer_may_use(&b, &PeerStatus::Known(peer_in("/user.slice/a.scope")))
                .is_ok()
        );
        assert!(
            holder
                .peer_may_use(&b, &PeerStatus::Known(peer_in("/user.slice/a.scope/sub")))
                .is_ok()
        );
        assert_eq!(
            holder
                .peer_may_use(&b, &PeerStatus::Known(peer_in("/user.slice/b.scope")))
                .unwrap_err()
                .0,
            Status::NotBoundScope
        );
        assert_eq!(
            holder
                .peer_may_use(&b, &PeerStatus::Unknown("no pid".into()))
                .unwrap_err()
                .0,
            Status::PeerUnknown
        );
        assert_eq!(
            holder.peer_may_use(&b, &PeerStatus::NotRead).unwrap_err().0,
            Status::PeerUnknown
        );
    }

    #[tokio::test]
    async fn the_cap_counts_reservations_and_frees_on_release_and_remove() {
        let holder = holder_with(&[], std::path::Path::new("/nonexistent"));
        let first = holder.reserve_reader().await.unwrap();
        let second = holder.reserve_reader().await.unwrap();
        assert_ne!(first, second);
        assert_eq!(
            holder.reserve_reader().await.unwrap_err().0,
            Status::CapReached
        );
        holder.release_reservation().await;
        let third = holder.reserve_reader().await.unwrap();
        assert_eq!(third, "piggy-holder 3", "reader names never repeat");
        holder.record(binding(3, &third, "/a")).await;
        assert_eq!(holder.live().await, 2);
        assert!(holder.remove(&key(3)).await.is_some());
        assert_eq!(holder.live().await, 1);
        assert!(holder.remove(&key(3)).await.is_none());
    }

    #[tokio::test]
    async fn a_binding_whose_cgroup_vanishes_is_torn_down_and_one_that_stays_is_kept() {
        let root = tempdir();
        std::fs::create_dir_all(root.join("user.slice/a.scope")).unwrap();
        std::fs::create_dir_all(root.join("user.slice/b.scope")).unwrap();
        let holder = Arc::new(Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Recorder::default()),
        ));
        let a = binding(1, "piggy-holder 1", "/user.slice/a.scope");
        let b = binding(2, "piggy-holder 2", "/user.slice/b.scope");
        holder.reserve_reader().await.unwrap();
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        holder.record(b.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a), cached(&b)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        pins.lock()
            .await
            .cache_verified(&a.guid, MINTED_SLOT, "aaaaaaaa");
        pins.lock()
            .await
            .cache_verified(&b.guid, MINTED_SLOT, "bbbbbbbb");

        assert!(sweep_bindings(&holder, &keys, &pins).await.is_empty());

        std::fs::remove_dir(root.join("user.slice/a.scope")).unwrap();
        assert_eq!(
            sweep_bindings(&holder, &keys, &pins).await,
            vec!["piggy-holder 1".to_string()]
        );
        assert_eq!(holder.bindings().await, vec![b.clone()]);
        assert_eq!(holder.live().await, 1);
        let served: Vec<KeyData> = keys
            .lock()
            .await
            .iter()
            .map(|k| k.public_key.clone())
            .collect();
        assert_eq!(served, vec![b.key.clone()]);
        assert!(
            pins.lock().await.lookup(&a.guid, MINTED_SLOT).is_none(),
            "the PIN went with the card"
        );
        assert!(pins.lock().await.lookup(&b.guid, MINTED_SLOT).is_some());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn a_destroy_that_fails_keeps_the_binding_for_the_next_sweep() {
        let root = tempdir();
        let holder = Holder::new(
            HolderConfig {
                scopes: HashMap::new(),
                cgroup_root: root.clone(),
                poll_interval: Duration::from_millis(10),
                cap: CARD_CAP,
            },
            Box::new(Recorder {
                fail_destroy: true,
                ..Recorder::default()
            }),
        );
        let a = binding(1, "piggy-holder 1", "/gone.scope");
        holder.reserve_reader().await.unwrap();
        holder.record(a.clone()).await;
        let keys = Arc::new(Mutex::new(vec![cached(&a)]));
        let pins = Arc::new(Mutex::new(PinCache::new()));
        assert!(sweep_bindings(&holder, &keys, &pins).await.is_empty());
        // The binding stays for the next sweep, marked retiring; the key is
        // unserved at once (a card that cannot be destroyed yet signs for no
        // one).
        assert_eq!(
            holder.bindings().await,
            vec![Binding {
                retiring: true,
                ..a
            }]
        );
        assert_eq!(keys.lock().await.len(), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_random_pin_is_eight_alphanumerics_and_differs_each_time() {
        let a = random_pin().unwrap();
        let b = random_pin().unwrap();
        for pin in [&a, &b] {
            assert_eq!(pin.len(), 8);
            assert!(
                pin.chars().all(|c| c.is_ascii_alphanumeric()),
                "{}",
                pin.as_str()
            );
        }
        assert_ne!(a.as_str(), b.as_str());
    }

    fn cached(binding: &Binding) -> CachedKey {
        CachedKey {
            guid: binding.guid.clone(),
            reader_name: binding.reader.clone(),
            slot_id: MINTED_SLOT,
            algorithm: piggy_piv::PivAlgorithm::Ed25519,
            public_key: binding.key.clone(),
            comment: format!("holder:{}", binding.reader),
            pin_policy: Some(piggy_piv::PinPolicy::Never),
        }
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "piggy-holder-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
