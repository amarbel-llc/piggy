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
}

/// Parse one `--scope NAME=RULE`: `NAME=caller` or `NAME=cgroup:/path`.
/// The name is opaque (it may hold `@`); the split is at the first `=`.
pub fn parse_scope_spec(spec: &str) -> Result<(String, ScopeRule), String> {
    let Some((name, rule)) = spec.split_once('=') else {
        return Err(format!(
            "--scope {spec:?}: want NAME=caller or NAME=cgroup:/path"
        ));
    };
    if name.is_empty() {
        return Err(format!("--scope {spec:?}: the scope name is empty"));
    }
    let rule = match rule {
        "caller" => ScopeRule::Caller,
        other => match other.strip_prefix("cgroup:") {
            Some(path) => CgroupPath::parse(path)
                .map(ScopeRule::Cgroup)
                .ok_or_else(|| {
                    format!("--scope {spec:?}: {path:?} is not an absolute cgroup path")
                })?,
            None => {
                return Err(format!(
                    "--scope {spec:?}: unknown rule {other:?}; want caller or cgroup:/path"
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

/// A minted key and what it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub key: KeyData,
    pub guid: Guid,
    /// The reader fibby serves the card as.
    pub reader: String,
    pub scope: String,
    pub cgroup: CgroupPath,
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
}

/// fibby's control socket (piggy#130, #382 item 6): one line in, one reply
/// out, `ok …` or `err …`.
pub struct FibbyControl {
    socket: PathBuf,
}

impl FibbyControl {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// One command, as `fibby ctl` sends it: a line, then read to EOF. A
    /// plain blocking socket on a blocking task; the exchange is tiny.
    async fn command(&self, line: &str) -> Result<String, String> {
        let socket = self.socket.clone();
        let line = line.to_string();
        tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let mut stream = std::os::unix::net::UnixStream::connect(&socket)
                .map_err(|e| format!("connect {}: {e}", socket.display()))?;
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
}

#[derive(Default)]
struct HolderState {
    bindings: Vec<Binding>,
    /// Cards reserved by a mint in progress plus the live bindings; what
    /// the cap is checked against.
    live: usize,
    next_card: u64,
}

/// The holder: configuration, the live bindings, and the card store.
pub struct Holder {
    config: HolderConfig,
    control: Box<dyn CardControl>,
    state: Mutex<HolderState>,
}

impl Holder {
    pub fn new(config: HolderConfig, control: Box<dyn CardControl>) -> Self {
        Self {
            config,
            control,
            state: Mutex::new(HolderState::default()),
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
        peer: &Peer,
        scope: &str,
    ) -> Result<(String, CgroupPath), (Status, String)> {
        if crate::holder_ext::scope_is_absent(scope) {
            return Err((
                Status::ScopeUnbound,
                "no scope named, and this holder infers none; name one of its scopes".into(),
            ));
        }
        let Some(rule) = self.config.scopes.get(scope) else {
            let mut known: Vec<&str> = self.config.scopes.keys().map(String::as_str).collect();
            known.sort_unstable();
            return Err((
                Status::UnknownScope,
                format!(
                    "scope {scope:?} is not one this holder defines (it defines: {})",
                    if known.is_empty() {
                        "none".to_string()
                    } else {
                        known.join(", ")
                    }
                ),
            ));
        };
        let cgroup = match rule {
            ScopeRule::Caller => peer.cgroup.clone(),
            ScopeRule::Cgroup(path) if path.contains(&peer.cgroup) => path.clone(),
            ScopeRule::Cgroup(path) => {
                return Err((
                    Status::NotBoundScope,
                    format!(
                        "scope {scope:?} binds to {path}, and the caller ({peer}) is not inside it"
                    ),
                ));
            }
        };
        Ok((scope.to_string(), cgroup))
    }

    /// Whether `peer` is inside `binding`'s scope and may sign with or
    /// retire its key.
    pub fn peer_may_use(
        &self,
        binding: &Binding,
        peer: &PeerStatus,
    ) -> Result<(), (Status, String)> {
        match peer {
            PeerStatus::Known(peer) if binding.cgroup.contains(&peer.cgroup) => Ok(()),
            PeerStatus::Known(peer) => Err((
                Status::NotBoundScope,
                format!(
                    "the key is bound to scope {:?} ({}), and the caller ({peer}) is not inside it",
                    binding.scope, binding.cgroup
                ),
            )),
            PeerStatus::Unknown(why) => Err((Status::PeerUnknown, why.clone())),
            PeerStatus::NotRead => Err((
                Status::PeerUnknown,
                "the connection's peer was not read".into(),
            )),
        }
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

    /// Whether `binding`'s cgroup still exists under the configured root.
    pub fn cgroup_exists(&self, binding: &Binding) -> bool {
        binding
            .cgroup
            .directory_under(&self.config.cgroup_root)
            .is_dir()
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
/// `destroy`, the served key, the PIN, the binding. A `destroy` that fails
/// leaves the binding in place (the card is still there) and is reported.
pub async fn teardown(
    holder: &Holder,
    keys: &Arc<Mutex<Vec<CachedKey>>>,
    pins: &Arc<Mutex<PinCache>>,
    binding: &Binding,
    why: &str,
) -> Result<(), String> {
    holder.control().destroy(&binding.reader).await?;
    keys.lock().await.retain(|k| k.public_key != binding.key);
    pins.lock().await.forget_card(&binding.guid);
    holder.remove(&binding.key).await;
    tracing::info!(
        reader = %binding.reader,
        scope = %binding.scope,
        cgroup = %binding.cgroup,
        "holder: card destroyed ({why})"
    );
    Ok(())
}

/// One pass of the teardown watcher: every binding whose cgroup directory
/// is gone is torn down. Returns the readers torn down.
pub async fn sweep_bindings(
    holder: &Holder,
    keys: &Arc<Mutex<Vec<CachedKey>>>,
    pins: &Arc<Mutex<PinCache>>,
) -> Vec<String> {
    let mut gone = Vec::new();
    for binding in holder.bindings().await {
        if holder.cgroup_exists(&binding) {
            continue;
        }
        match teardown(holder, keys, pins, &binding, "its scope exited").await {
            Ok(()) => gone.push(binding.reader),
            Err(e) => tracing::warn!(
                reader = %binding.reader,
                "holder: the scope exited but the card could not be destroyed ({e}); retrying"
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
        async fn destroy(&self, reader: &str) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("destroy {reader}"));
            if self.fail_destroy {
                Err("no such reader".into())
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
            cgroup: cg(cgroup),
        }
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
        let peer = peer_in("/user.slice/s.scope");
        assert_eq!(
            holder.resolve_scope(&peer, "").unwrap_err().0,
            Status::ScopeUnbound
        );
        let (status, detail) = holder.resolve_scope(&peer, "piggy-mint-v2").unwrap_err();
        assert_eq!(status, Status::UnknownScope);
        assert!(detail.contains("piggy-mint-v1"), "{detail}");
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
        let peer = peer_in("/user.slice/s.scope");
        assert_eq!(
            holder.resolve_scope(&peer, "piggy-mint-v1").unwrap(),
            ("piggy-mint-v1".into(), cg("/user.slice/s.scope"))
        );
        // The name is a claim: a peer outside the fixed cgroup is refused.
        assert_eq!(
            holder.resolve_scope(&peer, "unit-v1").unwrap_err().0,
            Status::NotBoundScope
        );
        let inside = peer_in("/system.slice/u.service/child");
        assert_eq!(
            holder.resolve_scope(&inside, "unit-v1").unwrap(),
            ("unit-v1".into(), cg("/system.slice/u.service"))
        );
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
        assert_eq!(holder.bindings().await, vec![a]);
        assert_eq!(keys.lock().await.len(), 1);
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
