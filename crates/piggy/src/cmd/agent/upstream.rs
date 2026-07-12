//! Upstream SSH-agent proxying for `piggy agent` (piggy#215 step 1).
//!
//! Ported from amarbel-llc/ssh-agent-mux `src/lib.rs` (the identity-merge
//! and pubkey→socket routing core), adapted to the crates.io
//! ssh-agent-lib 0.5 shapes piggy already uses (`Identity.pubkey`,
//! `SignRequest.pubkey`) rather than the mux's ssh-agent-lib fork
//! (`Identity.credential`). The mux repo remains the standalone
//! multiplexer; piggy carries this port so the agent can serve native
//! PIV keys and proxy everything else on one `SSH_AUTH_SOCK`.
//!
//! Scope here is deliberately step 1 of the #215 umbrella: identity
//! listing and sign routing. Extension forwarding, lock/unlock fan-out,
//! and `add_identity` routing are step 2.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ssh_agent_lib::{
    agent::Session,
    client::Client,
    error::AgentError,
    proto::{Identity, SignRequest},
};
use ssh_key::{Signature, public::KeyData};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// One configured upstream agent (`--upstream NAME=PATH`). The name is a
/// human handle for logs (and, later, `piggy health` check points); the
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
#[derive(Clone)]
pub struct UpstreamPool {
    upstreams: Vec<Upstream>,
    timeout: Duration,
    known_keys: Arc<Mutex<HashMap<KeyData, usize>>>,
}

impl UpstreamPool {
    pub fn new(upstreams: Vec<Upstream>, timeout: Duration) -> Self {
        Self {
            upstreams,
            timeout,
            known_keys: Arc::new(Mutex::new(HashMap::new())),
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

    /// Connect to one upstream socket, timeout-bounded.
    async fn connect(&self, upstream: &Upstream) -> Result<Client<UnixStream>, AgentError> {
        let stream = timeout(self.timeout, UnixStream::connect(&upstream.path))
            .await
            .map_err(|_| {
                AgentError::Other(format!("upstream {}: connect timed out", upstream.name).into())
            })?
            .map_err(AgentError::IO)?;
        Ok(Client::new(stream))
    }

    /// List every upstream's identities in configured order, rebuilding
    /// the pubkey→upstream routing map. Per-upstream failures (absent
    /// socket, timeout, protocol error) are logged and skipped so one
    /// dead upstream cannot hide another's keys — this method never
    /// errors, it degrades to fewer identities.
    pub async fn list_identities(&self) -> Vec<Identity> {
        let mut known_keys = self.known_keys.lock().await;
        self.refresh_identities(&mut known_keys).await
    }

    async fn refresh_identities(&self, known_keys: &mut HashMap<KeyData, usize>) -> Vec<Identity> {
        known_keys.clear();
        let mut identities = Vec::new();
        for (idx, upstream) in self.upstreams.iter().enumerate() {
            let mut client = match self.connect(upstream).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(upstream = %upstream.name, "skipping unreachable upstream: {e}");
                    continue;
                }
            };
            let upstream_ids = match timeout(self.timeout, client.request_identities()).await {
                Ok(Ok(ids)) => ids,
                Ok(Err(e)) => {
                    tracing::warn!(upstream = %upstream.name, "request_identities failed: {e}");
                    continue;
                }
                Err(_) => {
                    tracing::warn!(upstream = %upstream.name, "request_identities timed out");
                    continue;
                }
            };
            tracing::debug!(
                upstream = %upstream.name,
                keys = upstream_ids.len(),
                "listed upstream identities"
            );
            for id in &upstream_ids {
                known_keys.insert(id.pubkey.clone(), idx);
            }
            identities.extend(upstream_ids);
        }
        identities
    }

    /// Route a sign request to the upstream that owns `request.pubkey`.
    /// On a routing-map miss the identities are refreshed once (the key
    /// may have appeared since the last listing) before giving up.
    pub async fn sign(&self, request: SignRequest) -> Result<Signature, AgentError> {
        let upstream = {
            let mut known_keys = self.known_keys.lock().await;
            let idx = match known_keys.get(&request.pubkey) {
                Some(idx) => Some(*idx),
                None => {
                    self.refresh_identities(&mut known_keys).await;
                    known_keys.get(&request.pubkey).copied()
                }
            };
            match idx {
                Some(idx) => self.upstreams[idx].clone(),
                None => {
                    return Err(AgentError::Other(
                        "no upstream agent holds the requested key".into(),
                    ));
                }
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
    }

    impl StubUpstream {
        pub fn new(identities: Vec<Identity>) -> Self {
            Self {
                identities,
                signature: canned_signature(),
            }
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
            Ok(self.identities.clone())
        }

        async fn sign(&mut self, _request: SignRequest) -> Result<Signature, AgentError> {
            Ok(self.signature.clone())
        }
    }

    /// Serve `stub` on a fresh socket under the test tmpdir; returns the
    /// socket path. The listener task lives until the test's runtime is
    /// dropped; the socket file is left for the tmpdir to reap.
    pub fn spawn_stub(tag: &str, stub: StubUpstream) -> PathBuf {
        let path = std::env::temp_dir().join(format!("pgup{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind stub upstream socket");
        tokio::spawn(ssh_agent_lib::agent::listen(listener, stub));
        path
    }

    pub fn upstream_identity(seed: u8, comment: &str) -> Identity {
        Identity {
            pubkey: KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([seed; 32])),
            comment: comment.to_string(),
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
        let dead = std::env::temp_dir().join("pgup-nonexistent.sock");

        // Dead upstream FIRST: its failure must not mask the live one.
        let pool = pool_of(vec![("dead", dead), ("live", live)]);
        let ids = pool.list_identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "live-key");
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
}
