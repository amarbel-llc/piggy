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

/// One upstream's health as self-reported by the agent (the
/// [`UPSTREAM_STATUS_EXT`] payload element).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamStatus {
    pub name: String,
    pub reachable: bool,
    /// Identities the upstream served on the probe; 0 when unreachable.
    pub keys: usize,
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
/// agent or the other upstreams.
#[derive(Clone, Debug)]
pub struct UpstreamPool {
    upstreams: Vec<Upstream>,
    timeout: Duration,
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
    _permit: OwnedSemaphorePermit,
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
        Self {
            upstreams,
            timeout,
            known_keys: Arc::new(Mutex::new(HashMap::new())),
            add_new_keys_to: None,
            connections: Arc::new(Semaphore::new(limit)),
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
        let listed = self.list_all_upstreams().await;
        let mut known_keys: HashMap<KeyData, usize> = HashMap::new();
        let mut identities = Vec::new();
        for (idx, upstream_ids) in listed.into_iter().enumerate() {
            let Some(upstream_ids) = upstream_ids else {
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
        identities
    }

    /// `request_identities` against every upstream concurrently, each
    /// bounded by `timeout`. Result is in configured-upstream order;
    /// `None` = that upstream was unreachable / failed / timed out
    /// (logged). Shared by the listing and the `status()` self-report.
    async fn list_all_upstreams(&self) -> Vec<Option<Vec<Identity>>> {
        self.for_each_upstream_parallel(|pool, upstream| async move {
            pool.list_one_upstream(&upstream).await
        })
        .await
        .into_iter()
        .map(Option::flatten)
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

    async fn list_one_upstream(&self, upstream: &Upstream) -> Option<Vec<Identity>> {
        let mut client = match self.connect(upstream).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(upstream = %upstream.name, "skipping unreachable upstream: {e}");
                return None;
            }
        };
        match timeout(self.timeout, client.request_identities()).await {
            Ok(Ok(ids)) => {
                tracing::debug!(
                    upstream = %upstream.name,
                    keys = ids.len(),
                    "listed upstream identities"
                );
                Some(ids)
            }
            Ok(Err(e)) => {
                tracing::warn!(upstream = %upstream.name, "request_identities failed: {e}");
                None
            }
            Err(_) => {
                tracing::warn!(upstream = %upstream.name, "request_identities timed out");
                None
            }
        }
    }

    /// Route a sign request to the upstream that owns `request.pubkey`.
    /// On a routing-map miss the identities are refreshed once (the key
    /// may have appeared since the last listing) before giving up. The
    /// map lock is only ever held for the lookups, never across IO.
    pub async fn sign(&self, request: SignRequest) -> Result<Signature, AgentError> {
        let mut idx = self.known_keys.lock().await.get(&request.pubkey).copied();
        if idx.is_none() {
            self.list_identities().await;
            idx = self.known_keys.lock().await.get(&request.pubkey).copied();
        }
        let upstream = match idx {
            Some(idx) => self.upstreams[idx].clone(),
            None => {
                return Err(AgentError::Other(
                    "no upstream agent holds the requested key".into(),
                ));
            }
        };

        tracing::debug!(upstream = %upstream.name, "routing sign request to upstream");
        let mut client = self.connect(&upstream).await?;
        timeout(self.timeout, client.sign(request))
            .await
            .map_err(|_| {
                AgentError::Other(
                    format!("upstream {}: sign request timed out", upstream.name).into(),
                )
            })?
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
        self.list_all_upstreams()
            .await
            .into_iter()
            .zip(&self.upstreams)
            .map(|(ids, upstream)| UpstreamStatus {
                name: upstream.name.clone(),
                reachable: ids.is_some(),
                keys: ids.map_or(0, |ids| ids.len()),
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
                relay: None,
            }
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

        async fn sign(&mut self, _request: SignRequest) -> Result<Signature, AgentError> {
            self.record("sign".into());
            Ok(self.signature.clone())
        }

        async fn extension(&mut self, request: Extension) -> Result<Option<Extension>, AgentError> {
            self.record(format!("ext:{}", request.name));
            if request.name == "query" {
                let qr = ssh_agent_lib::proto::extension::QueryResponse {
                    extensions: self.extensions.clone(),
                };
                return Ok(Some(Extension::new_message(qr)?));
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
        assert_eq!(
            st,
            vec![
                UpstreamStatus {
                    name: "live".into(),
                    reachable: true,
                    keys: 1,
                },
                UpstreamStatus {
                    name: "dead".into(),
                    reachable: false,
                    keys: 0,
                },
            ]
        );
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
