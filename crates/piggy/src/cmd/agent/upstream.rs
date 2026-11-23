//! Upstream SSH-agent proxying for `piggy agent` (piggy#215).
//!
//! Ported from amarbel-llc/ssh-agent-mux `src/lib.rs` (the identity-merge
//! and pubkey→socket routing core), adapted to the crates.io
//! ssh-agent-lib 0.5 shapes piggy already uses (`Identity.pubkey`,
//! `SignRequest.pubkey`) rather than the mux's ssh-agent-lib fork
//! (`Identity.credential`). The mux repo remains the standalone
//! multiplexer; piggy carries this port so the agent can serve native
//! PIV keys and proxy everything else on one `SSH_AUTH_SOCK`.
//!
//! Covers #215 steps 1, 2, and 5: identity listing, sign routing,
//! extension forwarding (query union, best-effort fan-out,
//! first-success forwarding), lock/unlock fan-out, `add_identity`
//! routing to the `--add-new-keys-to` upstream, and the
//! `upstream-status@piggy` self-report `piggy health` reads.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ssh_agent_lib::{
    agent::Session,
    client::Client,
    error::AgentError,
    proto::{AddIdentity, AddIdentityConstrained, Extension, Identity, SignRequest},
};
use ssh_key::{Signature, public::KeyData};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// The most upstream connections the pool holds open at once, across every
/// upstream and every client (piggy#326). A request beyond it fails at once
/// instead of opening another socket, so neither a burst of clients nor an
/// upstream that leads back into this agent (each hop holding its sockets
/// open while it waits on the next) can exhaust the agent's descriptors.
/// Far above what clients need: one listing holds one per upstream.
pub const MAX_UPSTREAM_CONNECTIONS: usize = 64;

/// The piggy-private extension `piggy health` uses to ask a running
/// agent about its upstreams (piggy#215 step 5). Implemented ONLY by
/// piggy; the upstreams themselves are probed with plain
/// `request_identities`, so they need nothing. Advertised in `query`
/// (and answered) only when upstreams are configured — its absence
/// tells health there is nothing to check. Response payload: a JSON
/// array of [`UpstreamStatus`].
pub const UPSTREAM_STATUS_EXT: &str = "upstream-status@piggy";

/// How long a listing with every upstream unreachable keeps redialing
/// before it answers the outage (piggy#333); `--upstream-grace`.
pub const DEFAULT_OUTAGE_GRACE: Duration = Duration::from_secs(3);

/// The longest pause between redials inside the outage grace.
const MAX_REDIAL_BACKOFF: Duration = Duration::from_secs(1);

/// How long a proxy waits for the agent that holds a key to answer a sign.
/// A sign can sit behind a PIN dialog and a touch (a certificate always
/// does), so `--agent-timeout`'s probe-sized default (5 s) does not apply
/// (`--sign-wait`). A sign goes to the one upstream that holds the key and is
/// never retried on another after a timeout (a second request would raise a
/// second prompt), so a long wait delays no other upstream.
pub const SIGN_UPSTREAM_WAIT: Duration = Duration::from_secs(60);

/// How many signs may be queued at one upstream, the one being answered
/// included. A person answers one dialog at a time and the signs go to the
/// card's machine one at a time; past this many a sign fails at once instead
/// of holding the front. The queue has its own budget, so it never takes a
/// listing's connection.
pub const MAX_QUEUED_SIGNS_PER_UPSTREAM: usize = 64;

/// One upstream's sign queue: the lock is the turn (tokio's is first come,
/// first served) and the semaphore the depth.
#[derive(Debug)]
struct SignQueue {
    turn: Mutex<()>,
    depth: Arc<Semaphore>,
    capacity: usize,
}

impl SignQueue {
    fn new(depth: usize) -> Self {
        Self {
            turn: Mutex::new(()),
            depth: Arc::new(Semaphore::new(depth)),
            capacity: depth,
        }
    }
}

/// The longest a sign waits in the queue for its turn, however many are ahead.
pub const MAX_QUEUE_WAIT: Duration = Duration::from_secs(600);

/// Resolves when a sign's client has hung up; a fresh future per use. Given
/// to a sign so it can leave the queue, never to take back a sent request.
pub type Hangup =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

/// The refusal for certificate-shaped data an upstream has not said it gates.
fn gate_refusal(upstream: &Upstream, name: &str) -> AgentError {
    AgentError::Other(
        format!(
            "refusing to relay certificate-shaped data: the agent that holds the key does not \
             advertise {name}, so it may sign a certificate with a key that is not a certificate \
             authority's slot (upstream {})",
            upstream.name
        )
        .into(),
    )
}

/// A connection's claim on its one pending sign, released on drop (every
/// path: answered, failed, timed out, cancelled).
struct OwnerClaim {
    owner: u64,
    pending: Arc<std::sync::Mutex<std::collections::HashSet<u64>>>,
}

impl Drop for OwnerClaim {
    fn drop(&mut self) {
        if self.owner != 0 {
            // A poisoned lock still holds the set: release the claim anyway,
            // and never panic in a drop.
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.owner);
        }
    }
}

/// One upstream's health as self-reported by the agent (the
/// [`UPSTREAM_STATUS_EXT`] payload element).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamStatus {
    pub name: String,
    pub reachable: bool,
    /// Identities the upstream served on the probe; 0 when unreachable.
    pub keys: usize,
    /// Unix seconds at which the upstream entered its current state
    /// (reachable or not), as this agent observed it (piggy#333). Absent
    /// from agents predating it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// Why the probe failed, when unreachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// What the pool last saw of one upstream: whether it answered, and
/// since when.
#[derive(Clone, Debug, Default)]
struct UpstreamState {
    reachable: Option<bool>,
    since: Option<std::time::SystemTime>,
}

impl UpstreamState {
    fn record(&mut self, reachable: bool) {
        if self.reachable != Some(reachable) {
            self.reachable = Some(reachable);
            self.since = Some(std::time::SystemTime::now());
        }
    }
}

/// A failure no answer came back for (connect, IO, a disconnect), which a
/// redial may cure, as opposed to the upstream refusing.
fn is_transport_failure(e: &AgentError) -> bool {
    matches!(
        e,
        AgentError::IO(_) | AgentError::Proto(ssh_agent_lib::proto::ProtoError::IO(_))
    )
}

/// One configured upstream agent (`--upstream NAME=PATH`). The name is a
/// human handle for logs (and `piggy health` check points); the
/// socket path is the routing target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub name: String,
    pub path: PathBuf,
}

/// Parse a `--upstream` spec of the form `NAME=SOCKET_PATH`.
pub fn parse_upstream_spec(spec: &str) -> Result<Upstream, String> {
    let (name, path) = spec
        .split_once('=')
        .ok_or_else(|| format!("invalid --upstream spec {spec:?}: expected NAME=SOCKET_PATH"))?;
    if name.is_empty() {
        return Err(format!("invalid --upstream spec {spec:?}: empty name"));
    }
    if path.is_empty() {
        return Err(format!(
            "invalid --upstream spec {spec:?}: empty socket path"
        ));
    }
    Ok(Upstream {
        name: name.to_string(),
        path: PathBuf::from(path),
    })
}

/// `path` with its directory resolved (symlinks, `..`), the file name kept as
/// given: a socket that does not exist yet still compares.
fn resolved_socket_path(path: &std::path::Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => {
            let dir = if dir.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                dir
            };
            std::fs::canonicalize(dir)
                .map(|dir| dir.join(name))
                .unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// Parse and validate a full `--upstream` flag list: every spec must be
/// `NAME=SOCKET_PATH` and names must be unique (they become log labels
/// and, later, `piggy health` check points).
pub fn parse_upstream_specs(specs: &[String]) -> Result<Vec<Upstream>, String> {
    let mut upstreams: Vec<Upstream> = Vec::new();
    for spec in specs {
        let up = parse_upstream_spec(spec)?;
        if upstreams.iter().any(|u| u.name == up.name) {
            return Err(format!("duplicate --upstream name {:?}", up.name));
        }
        upstreams.push(up);
    }
    Ok(upstreams)
}

/// A pool of upstream agents the piggy agent proxies for keys it does not
/// serve natively.
///
/// `known_keys` maps each upstream-served pubkey to the index of its
/// owning upstream; it is rebuilt on every [`UpstreamPool::list_identities`]
/// and refreshed on a [`UpstreamPool::sign`] cache miss (same shape as the
/// mux's `refresh_identities` / `get_agent_sock_for_pubkey`). The map is
/// behind an `Arc` so every per-connection clone of the agent shares one
/// routing cache.
///
/// Every upstream interaction (connect, list, sign) is bounded by
/// `timeout`; a dead or slow upstream degrades to "no keys from that
/// upstream" on listing and an error on signing — it never wedges the
/// agent or the other upstreams. When EVERY upstream is down, the
/// listing a client sees is an outage, not an empty key list
/// ([`UpstreamPool::list_identities_or_outage`], piggy#333).
#[derive(Clone, Debug)]
pub struct UpstreamPool {
    upstreams: Vec<Upstream>,
    timeout: Duration,
    /// How long a sign is waited for: a PIN dialog and a touch are a person's
    /// time, not a probe's.
    sign_wait: Duration,
    /// The cap on a sign's wait in the queue ([`MAX_QUEUE_WAIT`]).
    max_queue_wait: Duration,
    /// Per upstream, in configured order; shared by every clone.
    sign_queues: Arc<Vec<Arc<SignQueue>>>,
    /// The connections that have a sign pending (one each).
    pending_owners: Arc<std::sync::Mutex<std::collections::HashSet<u64>>>,
    /// How long a listing that finds every upstream down redials before
    /// it reports the outage.
    outage_grace: Duration,
    /// Per upstream, in configured order; shared by every clone.
    states: Arc<std::sync::Mutex<Vec<UpstreamState>>>,
    known_keys: Arc<Mutex<HashMap<KeyData, usize>>>,
    /// Index of the upstream `add_identity` requests are routed to
    /// (`--add-new-keys-to`). `None` refuses adds — piggy's native keys
    /// live on the card, so without a designated software agent there
    /// is nowhere for an added key to go.
    add_new_keys_to: Option<usize>,
    /// One permit per open upstream connection, shared by every clone of
    /// the pool; see [`MAX_UPSTREAM_CONNECTIONS`].
    connections: Arc<Semaphore>,
}

/// An open upstream connection, holding its share of
/// [`MAX_UPSTREAM_CONNECTIONS`] until it is dropped.
struct UpstreamConnection {
    client: Client<UnixStream>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl std::ops::Deref for UpstreamConnection {
    type Target = Client<UnixStream>;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl std::ops::DerefMut for UpstreamConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

impl UpstreamPool {
    pub fn new(upstreams: Vec<Upstream>, timeout: Duration) -> Self {
        Self::with_connection_limit(upstreams, timeout, MAX_UPSTREAM_CONNECTIONS)
    }

    fn with_connection_limit(upstreams: Vec<Upstream>, timeout: Duration, limit: usize) -> Self {
        let states = vec![UpstreamState::default(); upstreams.len()];
        let sign_queues = (0..upstreams.len())
            .map(|_| Arc::new(SignQueue::new(MAX_QUEUED_SIGNS_PER_UPSTREAM)))
            .collect();
        Self {
            upstreams,
            timeout,
            sign_wait: SIGN_UPSTREAM_WAIT,
            max_queue_wait: MAX_QUEUE_WAIT,
            sign_queues: Arc::new(sign_queues),
            pending_owners: Arc::default(),
            outage_grace: DEFAULT_OUTAGE_GRACE,
            states: Arc::new(std::sync::Mutex::new(states)),
            known_keys: Arc::new(Mutex::new(HashMap::new())),
            add_new_keys_to: None,
            connections: Arc::new(Semaphore::new(limit)),
        }
    }

    /// How long a sign is waited for (default [`SIGN_UPSTREAM_WAIT`]).
    pub fn with_sign_wait(mut self, wait: Duration) -> Self {
        self.sign_wait = wait;
        self
    }

    /// How long a listing that finds every upstream down redials before it
    /// reports the outage (`--upstream-grace`).
    pub fn with_outage_grace(mut self, grace: Duration) -> Self {
        self.outage_grace = grace;
        self
    }

    fn record(&self, upstream: &Upstream, reachable: bool) {
        if let Some(idx) = self.upstreams.iter().position(|u| u.name == upstream.name) {
            self.states.lock().expect("upstream states lock")[idx].record(reachable);
        }
    }

    /// The configured upstream whose socket is `socket`, the agent's own
    /// listening socket: proxying to it would send every request back into
    /// the agent, without end (piggy#326). Paths are compared with their
    /// directories resolved, so a symlinked runtime directory still matches.
    pub fn upstream_at(&self, socket: &std::path::Path) -> Option<&str> {
        let own = resolved_socket_path(socket);
        self.upstreams
            .iter()
            .find(|u| resolved_socket_path(&u.path) == own)
            .map(|u| u.name.as_str())
    }

    /// Designate the upstream that receives `add_identity` requests
    /// (`--add-new-keys-to NAME`). Errors when `name` matches no
    /// configured upstream — a startup error, not a runtime one.
    pub fn with_add_new_keys_to(mut self, name: &str) -> Result<Self, String> {
        match self.upstreams.iter().position(|u| u.name == name) {
            Some(idx) => {
                self.add_new_keys_to = Some(idx);
                Ok(self)
            }
            None => Err(format!(
                "--add-new-keys-to {name:?} matches no --upstream name"
            )),
        }
    }

    /// An empty pool: the no-`--upstream` configuration. All proxy paths
    /// are skipped when the pool is empty, keeping the agent's behavior
    /// byte-identical to the pre-#215 agent.
    pub fn empty() -> Self {
        Self::new(Vec::new(), Duration::from_secs(1))
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    /// Number of configured upstreams (the `agent-mode@piggy` report).
    pub fn len(&self) -> usize {
        self.upstreams.len()
    }

    /// Connect to one upstream socket, timeout-bounded, within the pool's
    /// connection limit: past it the connect fails at once.
    async fn connect(&self, upstream: &Upstream) -> Result<UpstreamConnection, AgentError> {
        let permit = Arc::clone(&self.connections)
            .try_acquire_owned()
            .map_err(|_| {
                AgentError::Other(
                    format!(
                        "upstream {}: the pool's upstream connections are all open; not opening \
                         another (is an upstream leading back into this agent?)",
                        upstream.name
                    )
                    .into(),
                )
            })?;
        self.open(upstream, Some(permit)).await
    }

    /// The sign queue of `upstream`: its signs wait here for their turn, on
    /// their own budget, so a sign waiting on a person never takes a
    /// listing's connection.
    fn sign_queue(&self, upstream: &Upstream) -> Option<Arc<SignQueue>> {
        self.upstreams
            .iter()
            .position(|u| u.name == upstream.name)
            .and_then(|i| self.sign_queues.get(i).cloned())
    }

    /// A connection's one pending sign. `owner` 0 is nobody's (tests, and a
    /// caller that does not say), and is never refused.
    fn claim_owner(&self, owner: u64) -> Result<OwnerClaim, AgentError> {
        if owner != 0
            && !self
                .pending_owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(owner)
        {
            return Err(AgentError::Other(
                "this connection already has a sign pending at the card's machine".into(),
            ));
        }
        Ok(OwnerClaim {
            owner,
            pending: Arc::clone(&self.pending_owners),
        })
    }

    /// How many signs may be queued at one upstream, counting the one being
    /// answered (default [`MAX_QUEUED_SIGNS_PER_UPSTREAM`]); more fail at once.
    pub fn with_max_queued_signs(mut self, depth: usize) -> Self {
        self.sign_queues = Arc::new(
            (0..self.upstreams.len())
                .map(|_| Arc::new(SignQueue::new(depth)))
                .collect(),
        );
        self
    }

    async fn open(
        &self,
        upstream: &Upstream,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<UpstreamConnection, AgentError> {
        let stream = timeout(self.timeout, UnixStream::connect(&upstream.path))
            .await
            .map_err(|_| {
                AgentError::Other(format!("upstream {}: connect timed out", upstream.name).into())
            })?
            .map_err(AgentError::IO)?;
        Ok(UpstreamConnection {
            client: Client::new(stream),
            _permit: permit,
        })
    }

    /// List every upstream's identities in configured order, rebuilding
    /// the pubkey→upstream routing map. Per-upstream failures (absent
    /// socket, timeout, protocol error) are logged and skipped so one
    /// dead upstream cannot hide another's keys — this method never
    /// errors, it degrades to fewer identities.
    ///
    /// The upstreams are probed IN PARALLEL and the routing map is swapped
    /// in only afterwards, so (a) the listing costs the slowest upstream,
    /// not the sum — a hung backing no longer adds its full timeout to
    /// every `ssh` on the box — and (b) the map's lock is never held across
    /// upstream IO, so concurrent clients' listings don't serialize behind
    /// one slow upstream (the #105 severity-amplifier shape, which this
    /// pool briefly reintroduced).
    pub async fn list_identities(&self) -> Vec<Identity> {
        self.list_once().await.0
    }

    /// [`Self::list_identities`], except that when every upstream is down
    /// it redials with backoff for up to the outage grace and, if none
    /// answers, fails naming each upstream's error (piggy#333). An empty
    /// list would tell a client "no such key" during what is an outage. An
    /// upstream that answers with no keys is an answer, not an outage.
    pub async fn list_identities_or_outage(&self) -> Result<Vec<Identity>, String> {
        let deadline = tokio::time::Instant::now() + self.outage_grace;
        let mut backoff = Duration::from_millis(100);
        loop {
            let (identities, failures) = self.list_once().await;
            let Some(failures) = failures else {
                return Ok(identities);
            };
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "every upstream agent is unreachable: {}",
                    failures.join("; ")
                ));
            }
            tokio::time::sleep(backoff.min(deadline - now)).await;
            backoff = (backoff * 2).min(MAX_REDIAL_BACKOFF);
        }
    }

    /// One listing pass, rebuilding the routing map. The second value is
    /// each upstream's failure when EVERY upstream failed, else `None`.
    async fn list_once(&self) -> (Vec<Identity>, Option<Vec<String>>) {
        let listed = self.list_all_upstreams().await;
        let failures: Vec<String> = listed
            .iter()
            .zip(&self.upstreams)
            .filter_map(|(r, u)| r.as_ref().err().map(|e| format!("{}: {e}", u.name)))
            .collect();
        let all_failed = !listed.is_empty() && failures.len() == listed.len();
        let mut known_keys: HashMap<KeyData, usize> = HashMap::new();
        let mut identities = Vec::new();
        for (idx, upstream_ids) in listed.into_iter().enumerate() {
            let Ok(upstream_ids) = upstream_ids else {
                continue;
            };
            // A key served by more than one upstream (the proxy-only
            // role's posh + RemoteForward'd backings both forward the
            // same workstation agent, FDR 0001) is offered ONCE and
            // routed to the FIRST upstream that listed it — the same
            // first-wins order the listing has, so a sign goes where the
            // offered identity came from. (It used to be listed twice and
            // routed last-wins.)
            for id in upstream_ids {
                if known_keys.contains_key(&id.pubkey) {
                    continue;
                }
                known_keys.insert(id.pubkey.clone(), idx);
                identities.push(id);
            }
        }
        *self.known_keys.lock().await = known_keys;
        (identities, all_failed.then_some(failures))
    }

    /// `request_identities` against every upstream concurrently, each
    /// bounded by `timeout`. Result is in configured-upstream order;
    /// `Err` = why that upstream was unreachable / failed / timed out
    /// (logged). Shared by the listing and the `status()` self-report.
    async fn list_all_upstreams(&self) -> Vec<Result<Vec<Identity>, String>> {
        self.for_each_upstream_parallel(|pool, upstream| async move {
            pool.list_one_upstream(&upstream).await
        })
        .await
        .into_iter()
        .map(|r| r.unwrap_or_else(|| Err("upstream task failed".into())))
        .collect()
    }

    /// Run `f` against every upstream CONCURRENTLY (one task each; `f`
    /// is responsible for its own per-call timeout via `connect` /
    /// `timeout`) and return the results in configured-upstream order.
    /// `None` = the task itself failed (panicked/cancelled), which is
    /// logged; per-upstream IO failures are `f`'s to represent. This is
    /// what keeps every multi-upstream operation — listing, status,
    /// query union, the best-effort fan-outs — at the cost of the
    /// slowest upstream rather than the sum.
    async fn for_each_upstream_parallel<T, Fut>(
        &self,
        f: impl Fn(UpstreamPool, Upstream) -> Fut,
    ) -> Vec<Option<T>>
    where
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut tasks = tokio::task::JoinSet::new();
        for (idx, upstream) in self.upstreams.iter().cloned().enumerate() {
            let fut = f(self.clone(), upstream);
            tasks.spawn(async move { (idx, fut.await) });
        }
        let mut out: Vec<Option<T>> = (0..self.upstreams.len()).map(|_| None).collect();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((idx, v)) => out[idx] = Some(v),
                Err(e) => tracing::warn!("upstream task failed: {e}"),
            }
        }
        out
    }

    async fn list_one_upstream(&self, upstream: &Upstream) -> Result<Vec<Identity>, String> {
        let listed = async {
            let mut client = self.connect(upstream).await?;
            timeout(self.timeout, client.request_identities())
                .await
                .map_err(|_| AgentError::Other("request_identities timed out".into()))?
        }
        .await;
        self.record(upstream, listed.is_ok());
        match listed {
            Ok(ids) => {
                tracing::debug!(
                    upstream = %upstream.name,
                    keys = ids.len(),
                    "listed upstream identities"
                );
                Ok(ids)
            }
            Err(e) => {
                tracing::warn!(upstream = %upstream.name, "skipping unreachable upstream: {e}");
                Err(e.to_string())
            }
        }
    }

    /// Route a sign request to the upstream that owns `request.pubkey`.
    /// On a routing-map miss the identities are refreshed once (the key
    /// may have appeared since the last listing) before giving up. The
    /// map lock is only ever held for the lookups, never across IO.
    ///
    /// A sign whose upstream could not be CONNECTED to is retried once after
    /// a fresh listing, which redials every upstream and may route the key to
    /// another backing that serves it (piggy#333). Nothing else is: a
    /// refusal is the upstream's answer, and once the request may be on the
    /// wire a failure or a timeout is final for it (a human may be at the
    /// dialog).
    pub async fn sign(&self, request: SignRequest) -> Result<Signature, AgentError> {
        self.sign_as(request, 0).await
    }

    /// [`Self::sign`] for one client connection (`owner`, never 0 for a real
    /// one): a connection has one sign pending at a time. Signs for one
    /// upstream are QUEUED in arrival order and sent one at a time (a person
    /// answers one dialog at a time, and the card agent serializes on the card
    /// anyway). A sign waits for its answer at most the sign wait, and in the
    /// queue at most (the signs ahead of it + 1) sign waits, capped at
    /// [`MAX_QUEUE_WAIT`]: each sign ahead takes at most one sign wait, so a
    /// line of legitimate signs is not failed for being long.
    pub async fn sign_as(&self, request: SignRequest, owner: u64) -> Result<Signature, AgentError> {
        self.sign_gated(request, owner, None, None).await
    }

    /// A shorter cap on the queue wait, for the tests.
    #[cfg(test)]
    pub fn with_max_queue_wait(mut self, cap: Duration) -> Self {
        self.max_queue_wait = cap;
        self
    }

    /// [`Self::sign_as`] for data that only an upstream that applies the
    /// certificate authority gate may be sent (`require_extension`, the name it
    /// advertises). The upstream a connect-failure retry re-routes to is
    /// checked again: a new route is not covered by the check made for the
    /// first.
    pub async fn sign_gated(
        &self,
        request: SignRequest,
        owner: u64,
        require_extension: Option<&str>,
        hangup: Option<&Hangup>,
    ) -> Result<Signature, AgentError> {
        let _claim = self.claim_owner(owner)?;
        let mut idx = self.known_keys.lock().await.get(&request.pubkey).copied();
        if idx.is_none() {
            self.list_identities().await;
            idx = self.known_keys.lock().await.get(&request.pubkey).copied();
        }
        let Some(idx) = idx else {
            return Err(AgentError::Other(
                "no upstream agent holds the requested key".into(),
            ));
        };
        let upstream = self.upstreams[idx].clone();
        // The gate is checked on the upstream the sign is sent to, not on a
        // fresh lookup of the key: a listing racing this sign cannot swap the
        // route between the check and the send.
        if let Some(name) = require_extension {
            if !self.upstream_advertises(idx, name).await {
                return Err(gate_refusal(&upstream, name));
            }
        }

        tracing::debug!(upstream = %upstream.name, "routing sign request to upstream");
        match self.sign_on(&upstream, request.clone(), hangup).await {
            Err((e, true)) => {
                tracing::warn!(
                    upstream = %upstream.name,
                    "could not connect to sign ({e}); redialing and retrying once"
                );
                self.list_identities().await;
                let idx = self.known_keys.lock().await.get(&request.pubkey).copied();
                let Some(idx) = idx else {
                    return Err(e);
                };
                let upstream = self.upstreams[idx].clone();
                if let Some(name) = require_extension {
                    if !self.upstream_advertises(idx, name).await {
                        return Err(gate_refusal(&upstream, name));
                    }
                }
                self.sign_on(&upstream, request, hangup)
                    .await
                    .map_err(|(e, _)| e)
            }
            answered => answered.map_err(|(e, _)| e),
        }
    }

    /// One sign round-trip. The flag on an error is true only when the
    /// request provably never left (the connect failed): the one failure a
    /// redial may cure and a re-send cannot double.
    async fn sign_on(
        &self,
        upstream: &Upstream,
        request: SignRequest,
        hangup: Option<&Hangup>,
    ) -> Result<Signature, (AgentError, bool)> {
        // Wait in line for this upstream: a place in the queue (not the
        // upstream's fault when none is free, and not retried), then our turn.
        let queue = self.sign_queue(upstream);
        let _place = queue
            .as_ref()
            .map(|q| q.depth.clone().try_acquire_owned())
            .transpose()
            .map_err(|_| {
                (
                    AgentError::Other(
                        format!(
                            "upstream {}: {} signs are already queued at the card's machine; \
                             not queueing another",
                            upstream.name,
                            queue.as_ref().map_or(0, |q| q.capacity)
                        )
                        .into(),
                    ),
                    false,
                )
            })?;
        // The signs ahead of this one: the places taken, ours excluded. Taking
        // a place and reading the count are two steps, so a sign arriving in
        // between is counted too: the count can only be too high, which only
        // lengthens this sign's queue wait (it never fails one early).
        let ahead = queue.as_ref().map_or(0, |q| {
            q.capacity
                .saturating_sub(q.depth.available_permits())
                .saturating_sub(1)
        });
        let queue_wait = self
            .sign_wait
            .saturating_mul(u32::try_from(ahead + 1).unwrap_or(u32::MAX))
            .min(self.max_queue_wait.max(self.sign_wait));
        // Wait for the turn, and give the place up if the client hangs up
        // first: a queued sign has reached nobody. Once the request is SENT
        // below, a hangup changes nothing here: the turn is kept until the
        // answer or the sign wait, so abandoned requests cannot stack at the
        // card agent faster than it answers them.
        let _turn = match &queue {
            Some(q) => {
                let turn = timeout(queue_wait, q.turn.lock());
                let gone = async {
                    match hangup {
                        Some(hangup) => hangup().await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    turn = turn => Some(turn.map_err(|_| {
                        (
                            AgentError::Other(
                                format!(
                                    "upstream {}: waited {:.1} s in the queue for the card's \
                                     machine ({ahead} sign(s) were ahead)",
                                    upstream.name,
                                    queue_wait.as_secs_f64()
                                )
                                .into(),
                            ),
                            false,
                        )
                    })?),
                    () = gone => return Err((
                        AgentError::Other(
                            "the client hung up while its sign was queued at the card's machine"
                                .into(),
                        ),
                        false,
                    )),
                }
            }
            None => None,
        };
        let mut client = self.open(upstream, None).await.map_err(|e| {
            self.record(upstream, false);
            (e, true)
        })?;
        match timeout(self.sign_wait, client.sign(request)).await {
            Ok(Ok(signature)) => {
                self.record(upstream, true);
                Ok(signature)
            }
            // Final: the request may have been delivered (see `sign_as`).
            Ok(Err(e)) => {
                self.record(upstream, !is_transport_failure(&e));
                Err((e, false))
            }
            // Not retried: the upstream may still be waiting on a human (a
            // PIN or a touch), and a second request would prompt again.
            Err(_) => Err((
                AgentError::Other(
                    format!(
                        "upstream {}: sign request timed out after {} s waiting for the card's \
                         machine (a PIN or a touch may be pending there)",
                        upstream.name,
                        self.sign_wait.as_secs()
                    )
                    .into(),
                ),
                false,
            )),
        }
    }

    /// Forward an extension request to the ONE upstream that listed
    /// `pubkey`, and relay its answer unchanged. `None` when no upstream
    /// holds the key (after one refresh of the routing map, as [`Self::sign`]
    /// does).
    ///
    /// Unlike [`Self::forward_extension`] this never tries a second upstream:
    /// the request may put a prompt in front of a human, and a refusal or a
    /// cancel from the upstream that owns the key is an answer, not a reason
    /// to ask another. `wait` replaces the pool's request timeout for the
    /// same reason: the human needs longer than a probe does.
    ///
    /// The outer `Err` is this pool failing to get an answer at all (the
    /// upstream could not be reached, or said nothing within `wait`); the
    /// inner result is whatever the upstream answered, a failure included.
    /// The caller needs the difference: only the second is the upstream's
    /// to relay.
    pub async fn forward_extension_for_key(
        &self,
        pubkey: &KeyData,
        request: Extension,
        wait: Duration,
    ) -> Option<Result<Result<Option<Extension>, AgentError>, String>> {
        let mut idx = self.known_keys.lock().await.get(pubkey).copied();
        if idx.is_none() {
            self.list_identities().await;
            idx = self.known_keys.lock().await.get(pubkey).copied();
        }
        let upstream = self.upstreams[idx?].clone();
        tracing::debug!(
            upstream = %upstream.name,
            extension = %request.name,
            "routing extension to the upstream that holds the key"
        );
        let answer = async {
            let mut client = self
                .connect(&upstream)
                .await
                .map_err(|e| format!("upstream {}: {e}", upstream.name))?;
            timeout(wait, client.extension(request))
                .await
                .map_err(|_| format!("upstream {}: no answer within {wait:?}", upstream.name))
        };
        Some(answer.await)
    }

    /// Whether the upstream at `idx` advertises the extension `name` in its
    /// answer to `query`: False when it cannot be reached or does not answer,
    /// and when its answer does not list the name: a front only trusts what it
    /// was told, now. `idx` is the upstream a sign has ALREADY been routed to:
    /// a concurrent listing cannot swap the route between this check and the
    /// send, because the check is made on the upstream the send goes to.
    async fn upstream_advertises(&self, idx: usize, name: &str) -> bool {
        let upstream = self.upstreams[idx].clone();
        let query = Extension {
            name: "query".into(),
            details: Vec::new().into(),
        };
        match self.extension_on(&upstream, query).await {
            // A piggy card agent answers with flat length-prefixed names, the
            // shape pivy's parser expects; other agents wrap them in one
            // string. The shared decoder reads both (the lane that signs a
            // certificate through a front found `parse_message` read only
            // the wrapped one).
            Ok(Some(response)) => {
                crate::agent_client::decode_query_response(response.details.as_ref())
                    .is_ok_and(|names| names.iter().any(|e| e == name))
            }
            _ => false,
        }
    }

    /// Union of the extension names the upstreams advertise, gathered by
    /// forwarding the client's `query` request to each. Per-upstream
    /// degrade: an unreachable upstream or an unparseable response just
    /// contributes no names. May contain duplicates across upstreams —
    /// the caller merges into its own name list with a contains-check.
    pub async fn query_extension_names(&self, request: &Extension) -> Vec<String> {
        let request = request.clone();
        self.for_each_upstream_parallel(move |pool, upstream| {
            let request = request.clone();
            async move {
                let response = match pool.extension_on(&upstream, request).await {
                    Ok(Some(ext)) => ext,
                    Ok(None) => return Vec::new(),
                    Err(e) => {
                        tracing::debug!(upstream = %upstream.name, "query skipped: {e}");
                        return Vec::new();
                    }
                };
                match response.parse_message::<ssh_agent_lib::proto::extension::QueryResponse>() {
                    Ok(Some(qr)) => qr.extensions,
                    Ok(None) => Vec::new(),
                    Err(e) => {
                        tracing::debug!(upstream = %upstream.name, "unparseable query response: {e}");
                        Vec::new()
                    }
                }
            }
        })
        .await
        .into_iter()
        .flatten()
        .flatten()
        .collect()
    }

    /// Forward an extension request to each upstream in configured
    /// order; the first successful response wins. Any per-upstream
    /// error (unsupported, unreachable, timeout) tries the next;
    /// exhaustion returns the generic agent failure, matching what a
    /// no-upstream agent answers for an unknown extension.
    pub async fn forward_extension(
        &self,
        request: Extension,
    ) -> Result<Option<Extension>, AgentError> {
        for upstream in &self.upstreams {
            match self.extension_on(upstream, request.clone()).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::debug!(
                        upstream = %upstream.name,
                        extension = %request.name,
                        "extension not served here: {e}"
                    );
                }
            }
        }
        Err(AgentError::Failure)
    }

    /// Best-effort fan-out of an extension to every upstream
    /// (session-bind: constraint-enforcing software agents should see
    /// the binding). Failures are logged, never propagated — piggy's
    /// native acceptance is the authoritative answer.
    pub async fn fan_out_extension(&self, request: &Extension) {
        let request = request.clone();
        self.for_each_upstream_parallel(move |pool, upstream| {
            let request = request.clone();
            async move {
                if let Err(e) = pool.extension_on(&upstream, request.clone()).await {
                    tracing::debug!(
                        upstream = %upstream.name,
                        extension = %request.name,
                        "fan-out skipped: {e}"
                    );
                }
            }
        })
        .await;
    }

    /// Best-effort lock fan-out. Failures are logged, never propagated:
    /// a dead upstream's keys are unservable anyway, and the native
    /// lock (PIN drop) already succeeded.
    pub async fn lock_all(&self, key: &str) {
        self.lock_fan_out(key, true).await;
    }

    /// Best-effort unlock fan-out; mirrors [`UpstreamPool::lock_all`].
    /// Note the payload reaches every upstream — identical to today's
    /// deployment, where the mux forwards `ssh-add -X` to all upstreams.
    pub async fn unlock_all(&self, key: &str) {
        self.lock_fan_out(key, false).await;
    }

    async fn lock_fan_out(&self, key: &str, locked: bool) {
        let key = key.to_string();
        self.for_each_upstream_parallel(move |pool, upstream| {
            let key = key.clone();
            async move {
                if let Err(e) = pool.lock_on(&upstream, key, locked).await {
                    let op = if locked { "lock" } else { "unlock" };
                    tracing::warn!(upstream = %upstream.name, "{op} fan-out failed: {e}");
                }
            }
        })
        .await;
    }

    /// Route an `add_identity` to the `--add-new-keys-to` upstream. The
    /// added key is NOT cached into the routing map — the next listing
    /// (or a sign-miss refresh) picks it up.
    pub async fn add_identity(&self, identity: AddIdentity) -> Result<(), AgentError> {
        let upstream = self.add_target()?;
        tracing::debug!(upstream = %upstream.name, "routing add_identity to upstream");
        let mut client = self.connect(upstream).await?;
        timeout(self.timeout, client.add_identity(identity))
            .await
            .map_err(|_| {
                AgentError::Other(
                    format!("upstream {}: add_identity timed out", upstream.name).into(),
                )
            })?
    }

    /// Constrained variant of [`UpstreamPool::add_identity`]; the
    /// constraints are forwarded verbatim (the upstream enforces them).
    pub async fn add_identity_constrained(
        &self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        let upstream = self.add_target()?;
        tracing::debug!(upstream = %upstream.name, "routing add_identity_constrained to upstream");
        let mut client = self.connect(upstream).await?;
        timeout(self.timeout, client.add_identity_constrained(identity))
            .await
            .map_err(|_| {
                AgentError::Other(
                    format!(
                        "upstream {}: add_identity_constrained timed out",
                        upstream.name
                    )
                    .into(),
                )
            })?
    }

    fn add_target(&self) -> Result<&Upstream, AgentError> {
        self.add_new_keys_to
            .map(|idx| &self.upstreams[idx])
            .ok_or_else(|| {
                AgentError::Other(
                    "no --add-new-keys-to upstream configured; refusing to add a key".into(),
                )
            })
    }

    /// Probe every upstream with a plain `request_identities` and
    /// report reachability + key count (the [`UPSTREAM_STATUS_EXT`]
    /// payload). Read-only, PIN-free, never errors — an unreachable
    /// upstream reports `reachable: false`.
    pub async fn status(&self) -> Vec<UpstreamStatus> {
        let listed = self.list_all_upstreams().await;
        let states = self.states.lock().expect("upstream states lock").clone();
        listed
            .into_iter()
            .zip(&self.upstreams)
            .zip(states)
            .map(|((ids, upstream), state)| UpstreamStatus {
                name: upstream.name.clone(),
                reachable: ids.is_ok(),
                keys: ids.as_ref().map_or(0, |ids| ids.len()),
                since: state.since.and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                }),
                last_error: ids.err(),
            })
            .collect()
    }

    /// One timeout-bounded extension round-trip against one upstream.
    async fn extension_on(
        &self,
        upstream: &Upstream,
        request: Extension,
    ) -> Result<Option<Extension>, AgentError> {
        let mut client = self.connect(upstream).await?;
        timeout(self.timeout, client.extension(request))
            .await
            .map_err(|_| {
                AgentError::Other(format!("upstream {}: extension timed out", upstream.name).into())
            })?
    }

    /// One timeout-bounded lock (`locked` = true) or unlock round-trip.
    async fn lock_on(
        &self,
        upstream: &Upstream,
        key: String,
        locked: bool,
    ) -> Result<(), AgentError> {
        let mut client = self.connect(upstream).await?;
        let fut = async {
            if locked {
                client.lock(key).await
            } else {
                client.unlock(key).await
            }
        };
        timeout(self.timeout, fut).await.map_err(|_| {
            AgentError::Other(format!("upstream {}: lock/unlock timed out", upstream.name).into())
        })?
    }
}

#[cfg(test)]
pub(super) mod test_support {
    //! In-process stub upstream agent for unit tests: a `Session` with
    //! fixed identities and a canned signature, served over a real unix
    //! socket via ssh-agent-lib's blanket `Agent` impl for
    //! `Clone + Session`.

    use super::*;
    use ssh_key::Algorithm;

    #[derive(Clone)]
    pub struct StubUpstream {
        pub identities: Vec<Identity>,
        pub signature: Signature,
        /// Extension names this stub advertises via `query` and serves
        /// (echoed back); anything else errors like an unsupporting agent.
        pub extensions: Vec<String>,
        /// Observable call log ("ext:<name>", "lock:<key>", …), shared
        /// across per-connection clones so tests can assert fan-out.
        pub events: Arc<std::sync::Mutex<Vec<String>>>,
        /// A wedged agent: accepts the connection but never answers
        /// `request_identities` (the hung-not-dead upstream the pool's
        /// timeout exists for).
        pub hang_identities: bool,
        /// Answer every sign with SSH_AGENT_FAILURE.
        pub refuse_sign: bool,
        /// Answer a sign only after this long: a human at a PIN prompt and a
        /// touch.
        pub sign_delay: Option<Duration>,
        /// Never answer a sign.
        pub hang_sign: bool,
        /// Signs being answered right now, and the most there ever were at
        /// once (shared by every connection's clone).
        pub live_signs: Arc<std::sync::atomic::AtomicUsize>,
        pub peak_concurrent_signs: Arc<std::sync::atomic::AtomicUsize>,
        /// The data of every sign, in the order the stub saw them.
        pub sign_log: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        /// Hung signs whose handler was dropped (the connection went away and
        /// the library cancelled it).
        pub cancelled_signs: Arc<std::sync::atomic::AtomicUsize>,
        /// Remove this socket file once `query` has been answered: the next
        /// connect fails (an upstream that is there for the gate check and
        /// gone for the send).
        pub unlink_after_query: Option<PathBuf>,
        /// A proxying agent: answers `request_identities` by listing this
        /// pool, as piggy's own agent does. Pointed at the stub's own
        /// socket it is the cycle piggy#326 guards against.
        pub relay: Option<UpstreamPool>,
    }

    impl StubUpstream {
        pub fn new(identities: Vec<Identity>) -> Self {
            Self {
                identities,
                signature: canned_signature(),
                extensions: Vec::new(),
                events: Arc::new(std::sync::Mutex::new(Vec::new())),
                hang_identities: false,
                refuse_sign: false,
                sign_delay: None,
                hang_sign: false,
                live_signs: Arc::default(),
                peak_concurrent_signs: Arc::default(),
                sign_log: Arc::default(),
                cancelled_signs: Arc::default(),
                unlink_after_query: None,
                relay: None,
            }
        }

        pub fn slow_sign(mut self, delay: Duration) -> Self {
            self.sign_delay = Some(delay);
            self
        }

        pub fn gone_after_query(mut self, socket: PathBuf) -> Self {
            self.unlink_after_query = Some(socket);
            self
        }

        pub fn hanging_sign(mut self) -> Self {
            self.hang_sign = true;
            self
        }

        pub fn refusing_sign(mut self) -> Self {
            self.refuse_sign = true;
            self
        }

        pub fn relaying_to(mut self, pool: UpstreamPool) -> Self {
            self.relay = Some(pool);
            self
        }

        pub fn with_extensions(mut self, names: &[&str]) -> Self {
            self.extensions = names.iter().map(|s| s.to_string()).collect();
            self
        }

        pub fn hanging(mut self) -> Self {
            self.hang_identities = true;
            self
        }

        fn record(&self, event: String) {
            self.events.lock().expect("stub events lock").push(event);
        }
    }

    /// The fixed signature every stub sign returns; tests assert on it to
    /// prove the response came from the stub, not piggy's native path.
    pub fn canned_signature() -> Signature {
        Signature::new(Algorithm::Ed25519, vec![0x5A; 64]).expect("static ed25519 sig shape")
    }

    #[ssh_agent_lib::async_trait]
    impl Session for StubUpstream {
        async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
            if self.hang_identities {
                std::future::pending::<()>().await;
            }
            if let Some(pool) = &self.relay {
                return Ok(pool.list_identities().await);
            }
            Ok(self.identities.clone())
        }

        async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
            self.record("sign".into());
            self.sign_log
                .lock()
                .expect("stub sign log")
                .push(request.data.clone());
            if self.hang_sign {
                struct Cancelled(Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for Cancelled {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                let _cancelled = Cancelled(self.cancelled_signs.clone());
                std::future::pending::<()>().await;
            }
            use std::sync::atomic::Ordering::SeqCst;
            let now = self.live_signs.fetch_add(1, SeqCst) + 1;
            self.peak_concurrent_signs.fetch_max(now, SeqCst);
            if let Some(delay) = self.sign_delay {
                tokio::time::sleep(delay).await;
            }
            self.live_signs.fetch_sub(1, SeqCst);
            if self.refuse_sign {
                return Err(AgentError::Failure);
            }
            Ok(self.signature.clone())
        }

        async fn extension(&mut self, request: Extension) -> Result<Option<Extension>, AgentError> {
            self.record(format!("ext:{}", request.name));
            if request.name == "query" {
                let qr = ssh_agent_lib::proto::extension::QueryResponse {
                    extensions: self.extensions.clone(),
                };
                let answer = Extension::new_message(qr)?;
                if let Some(path) = &self.unlink_after_query {
                    let _ = std::fs::remove_file(path);
                }
                return Ok(Some(answer));
            }
            if self.extensions.iter().any(|n| n == request.name.as_str()) {
                return Ok(Some(Extension {
                    name: request.name,
                    details: b"stub-echo".to_vec().into(),
                }));
            }
            Err(AgentError::Failure)
        }

        async fn lock(&mut self, key: String) -> Result<(), AgentError> {
            self.record(format!("lock:{key}"));
            Ok(())
        }

        async fn unlock(&mut self, key: String) -> Result<(), AgentError> {
            self.record(format!("unlock:{key}"));
            Ok(())
        }

        async fn add_identity(&mut self, _identity: AddIdentity) -> Result<(), AgentError> {
            self.record("add_identity".into());
            Ok(())
        }

        async fn add_identity_constrained(
            &mut self,
            identity: AddIdentityConstrained,
        ) -> Result<(), AgentError> {
            self.record(format!(
                "add_identity_constrained:{}",
                identity.constraints.len()
            ));
            Ok(())
        }
    }

    /// Serve `stub` on a fresh socket under `/tmp` — deliberately NOT
    /// the honored TMPDIR: in this repo that lives inside the worktree,
    /// and a leftover socket file there breaks any later
    /// `builtins.getFlake`-style path copy of the tree (nix cannot
    /// store socket files). `/tmp` also keeps the path under AF_UNIX's
    /// sun_path limit. Returns the socket path; the listener task lives
    /// until the test runtime drops.
    pub fn spawn_stub(tag: &str, stub: StubUpstream) -> PathBuf {
        let path = stub_socket_path(tag);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind stub upstream socket");
        tokio::spawn(ssh_agent_lib::agent::listen(listener, stub));
        path
    }

    /// Where [`spawn_stub`] binds the stub tagged `tag`, known before it is
    /// spawned so a stub can be given a pool that points back at itself.
    pub fn stub_socket_path(tag: &str) -> PathBuf {
        PathBuf::from("/tmp").join(format!("pgup{}-{tag}.sock", std::process::id()))
    }

    /// An upstream that accepts every connection and closes it at once:
    /// each request on it fails with a broken pipe or a reset, as the
    /// flapping upstream of piggy#326 did.
    pub fn spawn_closing_upstream(tag: &str) -> PathBuf {
        let path = stub_socket_path(tag);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind closing upstream");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        path
    }

    /// This process's open descriptors.
    #[cfg(target_os = "linux")]
    pub fn open_descriptors() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .count()
    }

    pub fn upstream_identity(seed: u8, comment: &str) -> Identity {
        Identity {
            pubkey: KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([seed; 32])),
            comment: comment.to_string(),
        }
    }

    /// A syntactically valid Ed25519 add_identity request (fixed seed).
    pub fn test_add_identity() -> AddIdentity {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[7u8; 32]);
        AddIdentity {
            credential: ssh_agent_lib::proto::Credential::Key {
                privkey: ssh_key::private::KeypairData::Ed25519(keypair),
                comment: "test-add".into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    // -------- parse_upstream_spec --------

    #[test]
    fn parse_spec_ok() {
        let up = parse_upstream_spec("launchd=/tmp/l.sock").unwrap();
        assert_eq!(up.name, "launchd");
        assert_eq!(up.path, PathBuf::from("/tmp/l.sock"));
    }

    #[test]
    fn parse_spec_path_may_contain_equals() {
        // Only the FIRST '=' splits; paths with '=' survive.
        let up = parse_upstream_spec("a=/tmp/x=y.sock").unwrap();
        assert_eq!(up.path, PathBuf::from("/tmp/x=y.sock"));
    }

    #[test]
    fn parse_spec_rejects_missing_equals() {
        let err = parse_upstream_spec("launchd").unwrap_err();
        assert!(err.contains("expected NAME=SOCKET_PATH"), "{err}");
    }

    #[test]
    fn parse_spec_rejects_empty_name() {
        let err = parse_upstream_spec("=/tmp/l.sock").unwrap_err();
        assert!(err.contains("empty name"), "{err}");
    }

    #[test]
    fn parse_spec_rejects_empty_path() {
        let err = parse_upstream_spec("launchd=").unwrap_err();
        assert!(err.contains("empty socket path"), "{err}");
    }

    #[test]
    fn parse_specs_accepts_unique_names() {
        let specs = vec!["a=/tmp/a.sock".to_string(), "b=/tmp/b.sock".to_string()];
        let ups = parse_upstream_specs(&specs).unwrap();
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].name, "a");
        assert_eq!(ups[1].name, "b");
    }

    #[test]
    fn parse_specs_rejects_duplicate_names() {
        let specs = vec!["a=/tmp/a.sock".to_string(), "a=/tmp/b.sock".to_string()];
        let err = parse_upstream_specs(&specs).unwrap_err();
        assert!(err.contains("duplicate --upstream name"), "{err}");
    }

    // -------- UpstreamPool over an in-process stub --------

    fn pool_of(paths: Vec<(&str, PathBuf)>) -> UpstreamPool {
        let upstreams = paths
            .into_iter()
            .map(|(name, path)| Upstream {
                name: name.into(),
                path,
            })
            .collect();
        UpstreamPool::new(upstreams, Duration::from_secs(5))
    }

    #[tokio::test]
    async fn empty_pool_is_empty_and_lists_nothing() {
        let pool = UpstreamPool::empty();
        assert!(pool.is_empty());
        assert!(pool.list_identities().await.is_empty());
    }

    #[tokio::test]
    async fn list_identities_returns_upstream_keys_in_order() {
        let stub = StubUpstream::new(vec![
            upstream_identity(0xA1, "up-key-1"),
            upstream_identity(0xA2, "up-key-2"),
        ]);
        let path = spawn_stub("list", stub);
        let pool = pool_of(vec![("stub", path)]);

        let ids = pool.list_identities().await;
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].comment, "up-key-1");
        assert_eq!(ids[1].comment, "up-key-2");
    }

    #[tokio::test]
    async fn list_identities_skips_dead_upstream_keeps_live_one() {
        let stub = StubUpstream::new(vec![upstream_identity(0xB1, "live-key")]);
        let live = spawn_stub("degrade", stub);
        let dead = PathBuf::from("/tmp/pgup-nonexistent.sock");

        // Dead upstream FIRST: its failure must not mask the live one.
        let pool = pool_of(vec![("dead", dead), ("live", live)]);
        let ids = pool.list_identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "live-key");
    }

    /// Two HUNG upstreams (accept, never answer) listed before a live one:
    /// the listing must still surface the live key, and must cost about
    /// ONE timeout, not one per hung upstream — the upstreams are probed
    /// in parallel. Also pins that `status()` reports the hung ones as
    /// unreachable. Real-time test (no paused clock): the timeout is
    /// 300 ms, so a sequential probe would take ≥ 600 ms.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn listing_costs_slowest_upstream_not_the_sum() {
        let hung1 = spawn_stub("hang1", StubUpstream::new(vec![]).hanging());
        let hung2 = spawn_stub("hang2", StubUpstream::new(vec![]).hanging());
        let live = spawn_stub(
            "hang-live",
            StubUpstream::new(vec![upstream_identity(0xF1, "live-key")]),
        );
        let pool = UpstreamPool::new(
            vec![
                Upstream {
                    name: "hung1".into(),
                    path: hung1,
                },
                Upstream {
                    name: "hung2".into(),
                    path: hung2,
                },
                Upstream {
                    name: "live".into(),
                    path: live,
                },
            ],
            Duration::from_millis(300),
        );

        let started = std::time::Instant::now();
        let ids = pool.list_identities().await;
        let elapsed = started.elapsed();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "live-key");
        assert!(
            elapsed < Duration::from_millis(550),
            "listing took {elapsed:?}: upstreams are being probed sequentially"
        );

        let statuses = pool.status().await;
        assert_eq!(
            statuses.iter().map(|s| s.reachable).collect::<Vec<_>>(),
            vec![false, false, true]
        );
        assert_eq!(statuses[2].keys, 1);
    }

    /// FDR 0001: two backings serving the SAME key (posh + the
    /// RemoteForward'd socket both forward one workstation agent) — the
    /// key is offered once and a sign for it is routed to the FIRST
    /// upstream that listed it, consistent with the listing order.
    #[tokio::test]
    async fn same_key_on_two_upstreams_listed_once_and_routed_first_wins() {
        let first = StubUpstream::new(vec![upstream_identity(0xE1, "shared-key")]);
        let first_events = first.events.clone();
        let second = StubUpstream::new(vec![upstream_identity(0xE1, "shared-key")]);
        let second_events = second.events.clone();
        let p1 = spawn_stub("dup-first", first);
        let p2 = spawn_stub("dup-second", second);
        let pool = pool_of(vec![("first", p1), ("second", p2)]);

        let ids = pool.list_identities().await;
        assert_eq!(ids.len(), 1, "shared key must be offered once: {ids:?}");

        pool.sign(SignRequest {
            pubkey: upstream_identity(0xE1, "shared-key").pubkey,
            data: b"payload".to_vec(),
            flags: 0,
        })
        .await
        .unwrap();
        assert!(first_events.lock().unwrap().iter().any(|e| e == "sign"));
        assert!(
            !second_events.lock().unwrap().iter().any(|e| e == "sign"),
            "sign must route to the first-listed upstream, not last-wins"
        );
    }

    #[tokio::test]
    async fn sign_routes_to_owning_upstream() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC1, "sign-key")]);
        let path = spawn_stub("sign", stub);
        let pool = pool_of(vec![("stub", path)]);

        // No prior list_identities: sign must self-refresh on the miss.
        let sig = pool
            .sign(SignRequest {
                pubkey: upstream_identity(0xC1, "sign-key").pubkey,
                data: b"payload".to_vec(),
                flags: 0,
            })
            .await
            .unwrap();
        assert_eq!(sig, canned_signature());
    }

    fn sign_request(seed: u8, comment: &str) -> SignRequest {
        SignRequest {
            pubkey: upstream_identity(seed, comment).pubkey,
            data: b"payload".to_vec(),
            flags: 0,
        }
    }

    fn one_upstream_pool(path: PathBuf, sign_wait: Duration) -> UpstreamPool {
        UpstreamPool::new(
            vec![Upstream {
                name: "stub".into(),
                path,
            }],
            Duration::from_secs(2),
        )
        .with_sign_wait(sign_wait)
    }

    /// Review R2, R3: signs for one upstream are QUEUED and sent one at a
    /// time, not refused past a small cap: five real concurrent signs (parallel
    /// fetches) all succeed, and the person is never asked about two at once.
    #[tokio::test]
    async fn concurrent_signs_queue_and_reach_the_upstream_one_at_a_time() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC4, "queue-key")])
            .slow_sign(Duration::from_millis(120));
        let peak = stub.peak_concurrent_signs.clone();
        let path = spawn_stub("sign-queue", stub);
        let pool = one_upstream_pool(path, Duration::from_secs(10));
        pool.list_identities().await;
        let mut signs = Vec::new();
        for owner in 1..=5u64 {
            let pool = pool.clone();
            signs.push(tokio::spawn(async move {
                pool.sign_as(sign_request(0xC4, "queue-key"), owner).await
            }));
        }
        for sign in signs {
            sign.await
                .unwrap()
                .expect("a queued sign is sent in its turn");
        }
        assert_eq!(
            peak.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "two signs were at the card's machine at once"
        );
    }

    /// A listing is not behind signs waiting on a person.
    #[tokio::test]
    async fn a_listing_is_not_behind_a_waiting_sign() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC6, "list-key")]).hanging_sign();
        let path = spawn_stub("sign-list", stub);
        let pool = one_upstream_pool(path, Duration::from_secs(3));
        pool.list_identities().await;
        let waiting = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.sign_as(sign_request(0xC6, "list-key"), 1).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        assert_eq!(pool.list_identities().await.len(), 1);
        assert!(started.elapsed() < Duration::from_secs(1));
        waiting.abort();
    }

    /// The queue is bounded: past its depth a sign fails at once, naming
    /// the queue; a sign that timed out frees its place.
    #[tokio::test]
    async fn a_full_queue_fails_fast_and_a_timed_out_sign_frees_its_place() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC7, "full-key")]).hanging_sign();
        let path = spawn_stub("sign-full", stub);
        let pool = one_upstream_pool(path, Duration::from_millis(400)).with_max_queued_signs(2);
        pool.list_identities().await;
        let mut signs = Vec::new();
        for owner in 1..=4u64 {
            let pool = pool.clone();
            signs.push(tokio::spawn(async move {
                pool.sign_as(sign_request(0xC7, "full-key"), owner).await
            }));
        }
        let mut full = 0;
        for sign in signs {
            let err = sign.await.unwrap().unwrap_err().to_string();
            if err.contains("signs are already queued") {
                full += 1;
            }
        }
        assert_eq!(full, 2, "the two past the queue depth fail at once");
        // The places are free again: the next sign is queued and times out in
        // the ordinary way instead of being refused.
        let err = pool
            .sign_as(sign_request(0xC7, "full-key"), 9)
            .await
            .unwrap_err()
            .to_string();
        assert!(!err.contains("already queued"), "{err}");
    }

    /// One connection has one sign at a time.
    #[tokio::test]
    async fn a_connection_has_one_sign_pending_at_a_time() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC8, "own-key")])
            .slow_sign(Duration::from_millis(400));
        let path = spawn_stub("sign-owner", stub);
        let pool = one_upstream_pool(path, Duration::from_secs(5));
        pool.list_identities().await;
        let first = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.sign_as(sign_request(0xC8, "own-key"), 7).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let err = pool
            .sign_as(sign_request(0xC8, "own-key"), 7)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("already has a sign pending"), "{err}");
        first.await.unwrap().expect("the first sign is unharmed");
        // Another connection, and the same one afterwards, are fine.
        pool.sign_as(sign_request(0xC8, "own-key"), 8)
            .await
            .unwrap();
        pool.sign_as(sign_request(0xC8, "own-key"), 7)
            .await
            .unwrap();
    }

    /// Review R1: once the request may be on the wire, a failure is final: a
    /// relay that drops while the person is at the dialog must not make the
    /// front re-send the sign (to the same or another upstream) and raise a
    /// second prompt.
    #[tokio::test]
    async fn a_sign_that_may_have_been_sent_is_never_sent_again() {
        let dropping = spawn_closing_upstream("sign-dropped");
        let good = StubUpstream::new(vec![upstream_identity(0xC9, "sent-key")]);
        let good_events = good.events.clone();
        let pool = UpstreamPool::new(
            vec![
                Upstream {
                    name: "dropping".into(),
                    path: dropping,
                },
                Upstream {
                    name: "good".into(),
                    path: spawn_stub("sign-sent-good", good),
                },
            ],
            Duration::from_secs(2),
        );
        // The key was listed on the first upstream earlier.
        pool.known_keys
            .lock()
            .await
            .insert(upstream_identity(0xC9, "sent-key").pubkey, 0);
        let err = pool.sign_as(sign_request(0xC9, "sent-key"), 1).await;
        assert!(err.is_err());
        assert!(
            !good_events.lock().unwrap().iter().any(|e| e == "sign"),
            "the sign was sent to another upstream after it may have been delivered"
        );
    }

    /// Review M2: a sign that times out is NOT sent to another upstream that
    /// lists the same key: it may still be waiting on a person there, and a
    /// second request would raise a second prompt.
    #[tokio::test]
    async fn a_timed_out_sign_is_not_tried_on_another_upstream() {
        let hung = StubUpstream::new(vec![upstream_identity(0xC5, "twin")]).hanging_sign();
        let good = StubUpstream::new(vec![upstream_identity(0xC5, "twin")]);
        let good_events = good.events.clone();
        let pool = UpstreamPool::new(
            vec![
                Upstream {
                    name: "first".into(),
                    path: spawn_stub("twin-hung", hung),
                },
                Upstream {
                    name: "second".into(),
                    path: spawn_stub("twin-good", good),
                },
            ],
            Duration::from_secs(2),
        )
        .with_sign_wait(Duration::from_millis(400));
        let err = pool
            .sign(SignRequest {
                pubkey: upstream_identity(0xC5, "twin").pubkey,
                data: b"payload".to_vec(),
                flags: 0,
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("upstream first"), "{err}");
        assert!(err.contains("card's machine"), "{err}");
        assert!(
            !good_events.lock().unwrap().iter().any(|e| e == "sign"),
            "the second upstream was asked to sign"
        );
    }

    /// Fourth read, 3: the queue wait is not one sign-wait for the whole
    /// line. Five legitimate signs each taking most of a sign wait all
    /// succeed (the old rule failed the fifth in the queue).
    #[tokio::test]
    async fn a_long_line_of_signs_that_each_answer_in_time_all_succeed() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD2, "line-key")])
            .slow_sign(Duration::from_millis(250));
        let path = spawn_stub("sign-line", stub);
        let pool = one_upstream_pool(path, Duration::from_millis(500));
        pool.list_identities().await;
        let mut signs = Vec::new();
        for owner in 1..=5u64 {
            let pool = pool.clone();
            signs.push(tokio::spawn(async move {
                pool.sign_as(sign_request(0xD2, "line-key"), owner).await
            }));
        }
        for (i, sign) in signs.into_iter().enumerate() {
            sign.await
                .unwrap()
                .unwrap_or_else(|e| panic!("sign {} of 5 failed in the line: {e}", i + 1));
        }
    }

    /// Signs reach the upstream in the order they arrived.
    #[tokio::test]
    async fn signs_are_sent_in_arrival_order() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD3, "order-key")])
            .slow_sign(Duration::from_millis(60));
        let log = stub.sign_log.clone();
        let path = spawn_stub("sign-order", stub);
        let pool = one_upstream_pool(path, Duration::from_secs(10));
        pool.list_identities().await;
        let mut signs = Vec::new();
        for owner in 1..=4u8 {
            let pool = pool.clone();
            signs.push(tokio::spawn(async move {
                let mut request = sign_request(0xD3, "order-key");
                request.data = vec![owner];
                pool.sign_as(request, u64::from(owner)).await
            }));
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        for sign in signs {
            sign.await.unwrap().unwrap();
        }
        assert_eq!(
            *log.lock().unwrap(),
            vec![vec![1], vec![2], vec![3], vec![4]]
        );
    }

    /// A sign past the queue's depth fails FAST (not after a wait) and says how
    /// deep the queue is.
    #[tokio::test]
    async fn a_sign_past_the_queue_depth_fails_at_once_and_names_the_depth() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD4, "fast-key")]).hanging_sign();
        let path = spawn_stub("sign-fast", stub);
        let pool = one_upstream_pool(path, Duration::from_secs(5)).with_max_queued_signs(1);
        pool.list_identities().await;
        let holder = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.sign_as(sign_request(0xD4, "fast-key"), 1).await })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        let started = std::time::Instant::now();
        let err = pool
            .sign_as(sign_request(0xD4, "fast-key"), 2)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "{:?}",
            started.elapsed()
        );
        assert!(err.contains("1 signs are already queued"), "{err}");
        holder.abort();
    }

    /// A sign that waits too long in the queue says so (and how many were
    /// ahead), distinctly from one that was sent and not answered.
    #[tokio::test]
    async fn a_sign_that_waits_too_long_in_the_queue_says_so() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD5, "wait-key")]).hanging_sign();
        let path = spawn_stub("sign-queued", stub);
        let pool = one_upstream_pool(path, Duration::from_millis(300));
        pool.list_identities().await;
        let first = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.sign_as(sign_request(0xD5, "wait-key"), 1).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        let err = pool
            .sign_as(sign_request(0xD5, "wait-key"), 2)
            .await
            .unwrap_err()
            .to_string();
        // One sign is ahead: it may wait two sign waits (0.6 s) for its turn,
        // and the sign ahead times out at 0.3 s, so this one gets its turn
        // and is sent: its error is the sent-and-unanswered one.
        assert!(err.contains("sign request timed out"), "{err}");
        let err_first = first.await.unwrap().unwrap_err().to_string();
        assert!(err_first.contains("sign request timed out"), "{err_first}");
    }

    /// Release on cancellation: a queued sign that is dropped (its client
    /// went) gives its place back at once.
    #[tokio::test]
    async fn a_cancelled_queued_sign_gives_its_place_back() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD6, "cancel-key")]).hanging_sign();
        let path = spawn_stub("sign-cancel", stub);
        let pool = one_upstream_pool(path, Duration::from_secs(5)).with_max_queued_signs(2);
        pool.list_identities().await;
        let mut held = Vec::new();
        for owner in 1..=2u64 {
            let pool = pool.clone();
            held.push(tokio::spawn(async move {
                pool.sign_as(sign_request(0xD6, "cancel-key"), owner).await
            }));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Full: a third is refused at once.
        let err = pool
            .sign_as(sign_request(0xD6, "cancel-key"), 3)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("already queued"), "{err}");
        // The queued one goes away: its place is free, and its owner may sign.
        held.pop().unwrap().abort();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let third = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.sign_as(sign_request(0xD6, "cancel-key"), 3).await })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !third.is_finished(),
            "the third sign took the freed place and is queued"
        );
        third.abort();
        held.pop().unwrap().abort();
    }

    /// EVIDENCE about ssh-agent-lib 0.5 (fourth read, 4): the server side
    /// does NOT drop a handler when its connection closes (it reads nothing
    /// while a handler runs). The front closes its connection to the upstream
    /// when an answer times out, and the upstream's handler for that sign
    /// lives on: the card agent's dialog is not cancelled by it, and a client
    /// that hangs up on a front is not seen by the library either (so the
    /// front watches its client's socket itself: `listener::peer_closed`).
    /// If the library ever cancels handlers, this fails and the watch can go.
    #[tokio::test]
    async fn the_library_does_not_cancel_a_handler_when_its_connection_closes() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD7, "close-key")]).hanging_sign();
        let cancelled = stub.cancelled_signs.clone();
        let path = spawn_stub("sign-close", stub);
        let pool = one_upstream_pool(path, Duration::from_millis(300));
        pool.list_identities().await;
        let err = pool
            .sign_as(sign_request(0xD7, "close-key"), 1)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            cancelled.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "ssh-agent-lib now cancels a handler whose connection closed: drop the hangup watch"
        );
    }

    /// A sign that waits past the queue's cap says so, and how many signs were
    /// ahead of it (the wait is capped: with a cap below the sign wait it can
    /// run out before the sign ahead has been answered).
    #[tokio::test]
    async fn the_queue_timeout_says_how_long_and_how_many_were_ahead() {
        // Three hung signs, each 500 ms to its answer, queue cap 600 ms (the
        // cap never goes below one sign wait): the third (two ahead) is out of
        // patience at about 660 ms, well before its turn (the first two take
        // 1000 ms between them): a margin of about 340 ms on a slow host.
        let stub = StubUpstream::new(vec![upstream_identity(0xDA, "cap-key")]).hanging_sign();
        let path = spawn_stub("sign-cap", stub);
        let pool = one_upstream_pool(path, Duration::from_millis(500))
            .with_max_queue_wait(Duration::from_millis(600));
        pool.list_identities().await;
        let mut signs = Vec::new();
        for owner in 1..=3u64 {
            let pool = pool.clone();
            signs.push(tokio::spawn(async move {
                pool.sign_as(sign_request(0xDA, "cap-key"), owner).await
            }));
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let mut errs = Vec::new();
        for sign in signs {
            errs.push(sign.await.unwrap().unwrap_err().to_string());
        }
        assert!(errs[0].contains("sign request timed out"), "{}", errs[0]);
        assert!(
            errs[2].contains(
                "waited 0.6 s in the queue for the card's machine (2 sign(s) were ahead)"
            ),
            "{}",
            errs[2]
        );
    }

    /// Fifth read, M1: a client that hangs up while its sign is queued gives its
    /// place up and its request is never sent; one that hangs up after the
    /// request was sent keeps its turn until the answer or the sign wait.
    #[tokio::test]
    async fn a_hangup_only_frees_a_sign_that_has_not_been_sent() {
        let stub = StubUpstream::new(vec![upstream_identity(0xDB, "hang-key")]).hanging_sign();
        let log = stub.sign_log.clone();
        let path = spawn_stub("sign-hangup-pool", stub);
        let pool = one_upstream_pool(path, Duration::from_millis(900));
        pool.list_identities().await;
        let after = |ms: u64| -> Hangup {
            Arc::new(move || {
                Box::pin(tokio::time::sleep(Duration::from_millis(ms)))
                    as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            })
        };
        // A: sent at once, its client hangs up at 150 ms: it is NOT dropped.
        let a = {
            let pool = pool.clone();
            let hangup = after(150);
            tokio::spawn(async move {
                pool.sign_gated(sign_request(0xDB, "hang-key"), 1, None, Some(&hangup))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        // B: queued behind A, its client hangs up at 150 ms: it leaves, unsent.
        let b = {
            let pool = pool.clone();
            let hangup = after(150);
            tokio::spawn(async move {
                pool.sign_gated(sign_request(0xDB, "hang-key"), 2, None, Some(&hangup))
                    .await
            })
        };
        let b_err = tokio::time::timeout(Duration::from_millis(600), b)
            .await
            .expect("a queued sign leaves when its client hangs up")
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(b_err.contains("hung up"), "{b_err}");
        assert!(
            !a.is_finished(),
            "a sent sign was dropped by its client's hangup"
        );
        assert_eq!(log.lock().unwrap().len(), 1, "B reached the upstream");
        let a_err = a.await.unwrap().unwrap_err().to_string();
        assert!(a_err.contains("timed out"), "{a_err}");
    }

    /// Fourth read, 5: a connect-failure retry that re-routes the sign to
    /// another upstream is checked against the certificate gate again.
    #[tokio::test]
    async fn a_rerouted_gated_sign_is_checked_against_the_gate_again() {
        let ext = crate::operator_act::SSH_CA_GATE_EXT;
        for (advertises, expect_signed) in [(false, false), (true, true)] {
            let mut other = StubUpstream::new(vec![upstream_identity(0xD8, "gate-key")]);
            if advertises {
                other = other.with_extensions(&[ext]);
            }
            let other_events = other.events.clone();
            // The first upstream advertises the gate when asked, then is gone
            // when the sign connects: the sign is re-routed to `other`.
            let first_path = stub_socket_path(&format!("sign-gate-first-{advertises}"));
            let first = StubUpstream::new(vec![upstream_identity(0xD8, "gate-key")])
                .with_extensions(&[ext])
                .gone_after_query(first_path.clone());
            let first_path = {
                let _ = spawn_stub(&format!("sign-gate-first-{advertises}"), first);
                first_path
            };
            let pool = UpstreamPool::new(
                vec![
                    Upstream {
                        name: "gone".into(),
                        path: first_path,
                    },
                    Upstream {
                        name: "other".into(),
                        path: spawn_stub(&format!("sign-gate-{advertises}"), other),
                    },
                ],
                Duration::from_secs(2),
            );
            // The first check was made for the upstream listed first.
            pool.known_keys
                .lock()
                .await
                .insert(upstream_identity(0xD8, "gate-key").pubkey, 0);
            let result = pool
                .sign_gated(sign_request(0xD8, "gate-key"), 1, Some(ext), None)
                .await;
            let signed = other_events.lock().unwrap().iter().any(|e| e == "sign");
            assert_eq!(signed, expect_signed, "advertises={advertises}: {result:?}");
            assert_eq!(result.is_ok(), expect_signed);
            if !expect_signed {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("does not advertise"),
                    "the refusal says why"
                );
            }
        }
    }

    /// A sign can sit behind a PIN dialog and a touch (a certificate always
    /// does): it is waited for as long as a person needs, not for the
    /// pool's probe-sized timeout (the slot-83 certificate through a front,
    /// refused after 5 s on a real card).
    #[tokio::test]
    async fn a_sign_waits_for_a_human_longer_than_the_pool_timeout() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC2, "slow-key")])
            .slow_sign(Duration::from_millis(700));
        let path = spawn_stub("sign-slow", stub);
        let pool = UpstreamPool::new(
            vec![Upstream {
                name: "stub".into(),
                path,
            }],
            Duration::from_millis(250),
        );
        let sig = pool
            .sign(SignRequest {
                pubkey: upstream_identity(0xC2, "slow-key").pubkey,
                data: b"payload".to_vec(),
                flags: 0,
            })
            .await
            .expect("the sign is waited for");
        assert_eq!(sig, canned_signature());
    }

    /// The wait is bounded: an upstream that never answers is a timeout,
    /// not retried (a second request would prompt again).
    #[tokio::test]
    async fn a_sign_that_is_never_answered_times_out_after_the_sign_wait() {
        let stub = StubUpstream::new(vec![upstream_identity(0xC3, "hung-key")]).hanging_sign();
        let events = stub.events.clone();
        let path = spawn_stub("sign-hung", stub);
        let pool = UpstreamPool::new(
            vec![Upstream {
                name: "stub".into(),
                path,
            }],
            Duration::from_millis(200),
        )
        .with_sign_wait(Duration::from_millis(600));
        let started = std::time::Instant::now();
        let err = pool
            .sign(SignRequest {
                pubkey: upstream_identity(0xC3, "hung-key").pubkey,
                data: b"payload".to_vec(),
                flags: 0,
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sign request timed out"), "{err}");
        assert!(started.elapsed() >= Duration::from_millis(600));
        let signs = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| *e == "sign")
            .count();
        assert_eq!(signs, 1, "a timed-out sign is not retried");
    }

    #[tokio::test]
    async fn sign_unknown_key_errors_after_refresh() {
        let stub = StubUpstream::new(vec![upstream_identity(0xD1, "held-key")]);
        let path = spawn_stub("unknown", stub);
        let pool = pool_of(vec![("stub", path)]);

        let err = pool
            .sign(SignRequest {
                pubkey: upstream_identity(0xEE, "not-held").pubkey,
                data: b"payload".to_vec(),
                flags: 0,
            })
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("no upstream agent holds"),
            "unexpected error: {err}"
        );
    }

    // -------- extension forwarding (#215 step 2) --------

    fn query_request() -> Extension {
        Extension {
            name: "query".into(),
            details: Vec::new().into(),
        }
    }

    fn named_request(name: &str) -> Extension {
        Extension {
            name: name.into(),
            details: Vec::new().into(),
        }
    }

    #[tokio::test]
    async fn query_names_unions_across_upstreams() {
        let a = StubUpstream::new(vec![]).with_extensions(&["foo@example", "bar@example"]);
        let b = StubUpstream::new(vec![]).with_extensions(&["bar@example", "baz@example"]);
        let pool = pool_of(vec![("a", spawn_stub("qa", a)), ("b", spawn_stub("qb", b))]);

        let names = pool.query_extension_names(&query_request()).await;
        for want in ["foo@example", "bar@example", "baz@example"] {
            assert!(names.iter().any(|n| n == want), "missing {want}: {names:?}");
        }
    }

    #[tokio::test]
    async fn forward_extension_first_supporting_upstream_wins() {
        // First upstream does NOT support the extension (errors); the
        // second does. The forward must skip to the second.
        let a = StubUpstream::new(vec![]);
        let b = StubUpstream::new(vec![]).with_extensions(&["special@example"]);
        let a_events = a.events.clone();
        let pool = pool_of(vec![("a", spawn_stub("fa", a)), ("b", spawn_stub("fb", b))]);

        let resp = pool
            .forward_extension(named_request("special@example"))
            .await
            .unwrap()
            .expect("echo response");
        assert_eq!(resp.name.as_str(), "special@example");
        // The first upstream was actually tried (and refused).
        assert!(
            a_events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e == "ext:special@example"),
            "first upstream never saw the request"
        );
    }

    #[tokio::test]
    async fn forward_extension_exhaustion_is_failure() {
        let a = StubUpstream::new(vec![]);
        let pool = pool_of(vec![("a", spawn_stub("fx", a))]);
        let err = pool
            .forward_extension(named_request("unsupported@example"))
            .await
            .unwrap_err();
        assert!(matches!(err, AgentError::Failure), "got {err:?}");
    }

    #[tokio::test]
    async fn lock_unlock_fan_out_to_every_upstream() {
        let a = StubUpstream::new(vec![]);
        let b = StubUpstream::new(vec![]);
        let (a_events, b_events) = (a.events.clone(), b.events.clone());
        let pool = pool_of(vec![("a", spawn_stub("la", a)), ("b", spawn_stub("lb", b))]);

        pool.unlock_all("sekrit").await;
        pool.lock_all("sekrit").await;

        for events in [a_events, b_events] {
            let events = events.lock().unwrap();
            assert!(events.iter().any(|e| e == "unlock:sekrit"), "{events:?}");
            assert!(events.iter().any(|e| e == "lock:sekrit"), "{events:?}");
        }
    }

    #[tokio::test]
    async fn add_identity_routes_only_to_designated_upstream() {
        let a = StubUpstream::new(vec![]);
        let b = StubUpstream::new(vec![]);
        let (a_events, b_events) = (a.events.clone(), b.events.clone());
        let pool = pool_of(vec![("a", spawn_stub("aa", a)), ("b", spawn_stub("ab", b))])
            .with_add_new_keys_to("b")
            .unwrap();

        pool.add_identity(test_add_identity()).await.unwrap();

        assert!(
            !a_events.lock().unwrap().iter().any(|e| e == "add_identity"),
            "non-designated upstream received the add"
        );
        assert!(
            b_events.lock().unwrap().iter().any(|e| e == "add_identity"),
            "designated upstream never received the add"
        );
    }

    #[tokio::test]
    async fn add_identity_without_target_refuses() {
        let a = StubUpstream::new(vec![]);
        let pool = pool_of(vec![("a", spawn_stub("ar", a))]);
        let err = pool.add_identity(test_add_identity()).await.unwrap_err();
        assert!(
            format!("{err}").contains("no --add-new-keys-to"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn status_reports_reachable_and_dead_upstreams_in_order() {
        let live = StubUpstream::new(vec![upstream_identity(0xE1, "k")]);
        let live_path = spawn_stub("st", live);
        let dead = PathBuf::from("/tmp/pgup-nonexistent.sock");
        let pool = pool_of(vec![("live", live_path), ("dead", dead)]);

        let st = pool.status().await;
        let shape: Vec<_> = st
            .iter()
            .map(|s| (s.name.as_str(), s.reachable, s.keys))
            .collect();
        assert_eq!(shape, vec![("live", true, 1), ("dead", false, 0)]);
    }

    /// piggy#333: the self-report carries when each upstream's current
    /// state began and, for a down one, why — so a session can tell an
    /// outage from a missing key, and how long it has lasted.
    #[tokio::test]
    async fn status_reports_since_and_last_error() {
        let live_path = spawn_stub("st-since", StubUpstream::new(vec![]));
        let dead = PathBuf::from("/tmp/pgup-nonexistent-since.sock");
        let pool = pool_of(vec![("live", live_path), ("dead", dead)]);

        let first = pool.status().await;
        assert!(first[0].since.is_some(), "{first:?}");
        assert_eq!(first[0].last_error, None);
        assert!(first[1].since.is_some(), "{first:?}");
        let err = first[1].last_error.as_deref().unwrap_or_default();
        assert!(err.contains("No such file"), "{err:?}");

        // A second probe in the same state keeps the state's start time.
        let second = pool.status().await;
        assert_eq!(second[1].since, first[1].since);
    }

    /// Agents predating piggy#333 report no `since`/`last_error`; a new
    /// health must still parse their payload, and an old one ours.
    #[test]
    fn upstream_status_payload_is_compatible_both_ways() {
        let old: Vec<UpstreamStatus> =
            serde_json::from_str(r#"[{"name":"a","reachable":true,"keys":2}]"#).unwrap();
        assert_eq!(old[0].since, None);
        assert_eq!(old[0].last_error, None);

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Pre333 {
            name: String,
            reachable: bool,
            keys: usize,
        }
        let reachable = UpstreamStatus {
            name: "a".into(),
            reachable: true,
            keys: 2,
            since: None,
            last_error: None,
        };
        let json = serde_json::to_string(&reachable).unwrap();
        serde_json::from_str::<Pre333>(&json).expect("unset fields are not serialized");
    }

    // -------- total upstream outage (piggy#333) --------

    fn pool_with_grace(paths: Vec<(&str, PathBuf)>, grace: Duration) -> UpstreamPool {
        pool_of(paths).with_outage_grace(grace)
    }

    /// Every upstream unreachable: the listing is an outage, not "no keys",
    /// once the grace is spent redialing.
    #[tokio::test]
    async fn every_upstream_down_is_an_outage_after_the_grace() {
        let pool = pool_with_grace(
            vec![
                ("a", PathBuf::from("/tmp/pgup-nonexistent-a.sock")),
                ("b", PathBuf::from("/tmp/pgup-nonexistent-b.sock")),
            ],
            Duration::from_millis(400),
        );
        let started = std::time::Instant::now();
        let err = pool.list_identities_or_outage().await.unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(400),
            "gave up after {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        let msg = err.to_string();
        assert!(msg.contains("every upstream agent is unreachable"), "{msg}");
        assert!(msg.contains("a:") && msg.contains("b:"), "{msg}");
    }

    /// An upstream that answers with zero keys is an answer, not an outage.
    #[tokio::test]
    async fn a_live_upstream_with_no_keys_is_not_an_outage() {
        let live = spawn_stub("no-keys", StubUpstream::new(vec![]));
        let pool = pool_with_grace(
            vec![
                ("dead", PathBuf::from("/tmp/pgup-nonexistent-nk.sock")),
                ("live", live),
            ],
            Duration::from_secs(5),
        );
        let started = std::time::Instant::now();
        assert!(pool.list_identities_or_outage().await.unwrap().is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited out the grace"
        );
    }

    /// An upstream that comes back within the grace is redialed and its
    /// keys answered.
    #[tokio::test]
    async fn an_upstream_back_within_the_grace_is_redialed() {
        let path = stub_socket_path("comeback");
        let _ = std::fs::remove_file(&path);
        let pool = pool_with_grace(vec![("comeback", path)], Duration::from_secs(3));
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            spawn_stub(
                "comeback",
                StubUpstream::new(vec![upstream_identity(0xA7, "back")]),
            );
        });
        let ids = pool.list_identities_or_outage().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "back");
    }

    fn shared_sign_request() -> SignRequest {
        SignRequest {
            pubkey: upstream_identity(0xE7, "shared").pubkey,
            data: b"payload".to_vec(),
            flags: 0,
        }
    }

    /// The upstream a key was routed to goes away between the listing and
    /// the sign; the sign re-lists and goes to the other backing that
    /// serves the same key (posh + RemoteForward, FDR 0001).
    #[tokio::test]
    async fn a_sign_whose_upstream_died_is_retried_on_the_live_one() {
        let first = spawn_stub(
            "retry-first",
            StubUpstream::new(vec![upstream_identity(0xE7, "shared")]),
        );
        let second = StubUpstream::new(vec![upstream_identity(0xE7, "shared")]);
        let second_events = second.events.clone();
        let second = spawn_stub("retry-second", second);
        let pool = pool_of(vec![("first", first.clone()), ("second", second)]);

        pool.list_identities().await;
        std::fs::remove_file(&first).unwrap();

        let sig = pool.sign(shared_sign_request()).await.unwrap();
        assert_eq!(sig, canned_signature());
        assert!(second_events.lock().unwrap().iter().any(|e| e == "sign"));
    }

    /// A refusal from the upstream is its answer: no retry.
    #[tokio::test]
    async fn a_refused_sign_is_not_retried() {
        let refusing = StubUpstream::new(vec![upstream_identity(0xE7, "shared")]).refusing_sign();
        let events = refusing.events.clone();
        let pool = pool_of(vec![("refusing", spawn_stub("refusing", refusing))]);

        pool.sign(shared_sign_request()).await.unwrap_err();
        let signs = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| *e == "sign")
            .count();
        assert_eq!(signs, 1);
    }

    // -------- descriptor safety (piggy#326) --------
    //
    // Descriptor counts are process-wide and other tests run alongside, so
    // the bounds below are loose: they separate "settles back" from
    // "grows with every request", not one descriptor from two.

    /// An upstream that accepts and closes at once, listed many times, must
    /// leave the pool's descriptors where they started: each failed request
    /// closes its socket.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_closing_upstream_does_not_grow_descriptors() {
        let path = spawn_closing_upstream("closing");
        let pool = pool_of(vec![("closing", path)]);
        pool.list_identities().await; // warm the runtime's own descriptors
        let before = open_descriptors();
        for _ in 0..200 {
            assert!(pool.list_identities().await.is_empty());
        }
        let after = open_descriptors();
        assert!(
            after < before + 50,
            "200 failed requests took descriptors from {before} to {after}"
        );
    }

    /// An upstream that leads back into a proxy (here a relaying stub whose
    /// pool lists its own socket) recurses until the pool's connection
    /// limit cuts it; the listing then answers, the descriptors the cycle
    /// held never climb far, and they come back. Without the limit the
    /// cycle recurses until the process runs out of descriptors, which is
    /// what took the agent down in piggy#326; the peak catches that.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_upstream_cycle_is_cut_by_the_connection_limit() {
        const LIMIT: usize = 16;
        let path = stub_socket_path("cycle");
        let pool = UpstreamPool::with_connection_limit(
            vec![Upstream {
                name: "cycle".into(),
                path: path.clone(),
            }],
            Duration::from_secs(5),
            LIMIT,
        );
        spawn_stub("cycle", StubUpstream::new(vec![]).relaying_to(pool.clone()));
        let before = open_descriptors();
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(before));
        let sampling = {
            let peak = Arc::clone(&peak);
            tokio::spawn(async move {
                loop {
                    peak.fetch_max(open_descriptors(), std::sync::atomic::Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };

        let listed = timeout(Duration::from_secs(10), pool.list_identities())
            .await
            .expect("a cyclic upstream must not wedge the listing");
        sampling.abort();
        assert!(listed.is_empty(), "{listed:?}");
        let peak = peak.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            peak < before + 200,
            "the cycle drove descriptors from {before} to {peak} before it was cut"
        );

        // Each hop's sockets close as the cycle unwinds; give the stub's
        // per-connection tasks a moment to see the hangups.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after = open_descriptors();
        assert!(
            after < before + 50,
            "the cut cycle left descriptors at {after} (from {before})"
        );
        assert_eq!(
            pool.connections.available_permits(),
            LIMIT,
            "every upstream connection the cycle opened must be closed"
        );
    }

    #[test]
    fn upstream_at_finds_the_agents_own_socket() {
        let dir = std::env::temp_dir();
        let pool = UpstreamPool::new(
            vec![Upstream {
                name: "own".into(),
                path: dir.join("pgup-own.sock"),
            }],
            Duration::from_secs(1),
        );
        // The same socket reached through `..` still matches: the
        // directory is resolved, and the socket need not exist yet.
        assert_eq!(
            pool.upstream_at(&dir.join(".").join("pgup-own.sock")),
            Some("own")
        );
        assert_eq!(pool.upstream_at(&dir.join("pgup-other.sock")), None);
    }

    #[test]
    fn with_add_new_keys_to_rejects_unknown_name() {
        let pool = UpstreamPool::new(
            vec![Upstream {
                name: "a".into(),
                path: PathBuf::from("/tmp/a.sock"),
            }],
            Duration::from_secs(1),
        );
        let err = pool.with_add_new_keys_to("nope").unwrap_err();
        assert!(err.contains("matches no --upstream name"), "{err}");
    }
}
