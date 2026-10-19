//! SSH-agent session state for `piggy agent`.
//!
//! Ported from the original `pivy-agent/src/agent.rs`; `PivyAgent` renamed
//! to `PiggyAgent` and the `pivy_piv` crate dependency relabelled to
//! `piggy_piv`. No behavioural changes.

use std::sync::Arc;
use tokio::sync::Mutex;

use ssh_agent_lib::{
    agent::Session,
    error::AgentError,
    proto::{AddIdentity, AddIdentityConstrained, Extension, Identity, SignRequest, signature},
};
use ssh_key::{Algorithm, PublicKey, Signature, public::KeyData};

use piggy_box::piv_box::{EcCurve, PivBox};
use piggy_piv::{Guid, PivAlgorithm, PivContext, PivError};
use zeroize::{Zeroize, Zeroizing};

use super::pins::{PinCache, PinSource};
use super::upstream::UpstreamPool;

/// Extra PIN prompts after the first one, on `PinIncorrect`, within a single
/// agent request — matching the C pivy-agent's one-retry behaviour (initial
/// attempt + one retry = 2 card PIN attempts max). Kept low because every
/// wrong attempt decrements the card's PIN retry counter (piggy#142).
const PIN_RETRY_LIMIT: u32 = 1;

/// The lowest remaining PIN-retry count at which the agent will still risk a
/// speculative `ssh-add -X` offer against a card (piggy#245). Attempting an
/// offered PIN that is wrong for a card one try from lockout would brick it;
/// below this the offer is dropped and the user is re-prompted instead. `2`
/// guarantees a wrong offer never drives a card to 0 — the offer is tried at
/// most once per card (`PinCache::offered_rejected_by`), so it can cost at
/// most one retry, and never the last one.
const MIN_RETRIES_FOR_OFFERED_PIN: u8 = 2;

/// Whether a card's remaining-retry query permits attempting an offered PIN.
/// A query error is treated as "not safe": without a confirmed count the
/// agent does not risk the offer.
fn offered_retries_ok(remaining: Result<u8, PivError>) -> bool {
    matches!(remaining, Ok(n) if n >= MIN_RETRIES_FOR_OFFERED_PIN)
}

/// Cached key info from a PIV token (populated at startup)
#[derive(Clone)]
pub struct CachedKey {
    pub guid: Guid,
    /// The PCSC reader this card is on. Used by the piggy#248 event path to
    /// map a changed-reader name back to the served card whose debounce to
    /// collapse (`reconcile_once`).
    pub reader_name: String,
    pub slot_id: u8,
    pub algorithm: PivAlgorithm,
    pub public_key: KeyData,
    pub comment: String,
}

#[derive(Clone)]
pub struct PiggyAgent {
    keys: Arc<Mutex<Vec<CachedKey>>>,
    /// Per-card PIN cache (piggy#177): verified PINs keyed by GUID plus the
    /// not-yet-verified `ssh-add -X` offer. Shared with the probe loop.
    pins: Arc<Mutex<PinCache>>,
    /// Serializes on-demand askpass prompts so a burst of concurrent ops
    /// that all need the PIN forks at most one dialog (piggy#58).
    prompt_lock: Arc<Mutex<()>>,
    /// Serializes the card section (PCSC connect → SELECT/CHUID → txn →
    /// VERIFY → sign/ECDH → teardown) across concurrent requests
    /// (piggy#213). Each handler opens its own connection and ends its
    /// PIN-verified session with a card reset, so without this an N-wide
    /// request burst races: one request's teardown/reset lands between
    /// another's VERIFY and its crypto op, and the loser is actively
    /// refused ("agent refused operation") instead of queued. tokio's
    /// Mutex is FIFO, so a burst completes serially in arrival order —
    /// the in-process analogue of the C agent's card-txn queue (#110).
    /// PIN prompts stay OUTSIDE this lock (a human at an askpass dialog
    /// must not stall the whole card queue; see `ensure_pin`).
    card_lock: Arc<Mutex<()>>,
    /// Upstream agents proxied for keys piggy does not serve natively
    /// (piggy#215, `--upstream`): their identities are offered after the
    /// native PIV keys, and sign requests for them are routed to the
    /// owning upstream. Empty without `--upstream`, making every proxy
    /// path a no-op (pre-#215 behavior).
    upstreams: UpstreamPool,
    /// `--proxy-only` (eng#295): this agent serves no card by design.
    /// Only consulted by the `agent-mode@piggy` self-report — the
    /// request paths don't branch on it (an empty native key set
    /// already routes everything upstream).
    proxy_only: bool,
    /// `--event-driven` (piggy#248): whether the event-driven presence watch
    /// is running. Consulted only by the `agent-mode@piggy` self-report so
    /// `piggy health` can surface the presence-detection mode.
    event_driven: bool,
    /// `--service-name` (piggy#162): the service unit / launchd label this
    /// agent runs under, relayed in the `agent-mode@piggy` self-report so
    /// `piggy health` probes the right unit. `None` = not told; health
    /// falls back to the platform default.
    service_name: Option<String>,
}

/// A PIN acquired for a card op, plus whether it came from an on-demand
/// prompt (and so should be cached only after a successful on-card verify).
struct AcquiredPin {
    pin: Zeroizing<String>,
    fresh: bool,
    /// True only for the speculative `ssh-add -X` offer (piggy#245). A
    /// prompted PIN and an offered PIN are both `fresh`, but only the
    /// offer is guarded against driving a low-retry card toward lockout —
    /// a prompted PIN is the user deliberately trying THIS card and must
    /// stay usable even at one retry.
    offered: bool,
}

impl PiggyAgent {
    pub fn new(keys: Vec<CachedKey>) -> Self {
        Self {
            keys: Arc::new(Mutex::new(keys)),
            pins: Arc::new(Mutex::new(PinCache::new())),
            prompt_lock: Arc::new(Mutex::new(())),
            card_lock: Arc::new(Mutex::new(())),
            upstreams: UpstreamPool::empty(),
            proxy_only: false,
            event_driven: false,
            service_name: None,
        }
    }

    /// Configure the upstream proxy pool (piggy#215, `--upstream`).
    pub fn with_upstream_pool(mut self, pool: UpstreamPool) -> Self {
        self.upstreams = pool;
        self
    }

    /// Mark this agent proxy-only (`--proxy-only`, eng#295) for the
    /// `agent-mode@piggy` self-report.
    pub fn with_proxy_only(mut self, proxy_only: bool) -> Self {
        self.proxy_only = proxy_only;
        self
    }

    /// Record whether the event-driven presence watch is running
    /// (`--event-driven`, piggy#248) for the `agent-mode@piggy` self-report.
    pub fn with_event_driven(mut self, event_driven: bool) -> Self {
        self.event_driven = event_driven;
        self
    }

    /// Set the service unit / launchd label this agent runs under
    /// (`--service-name`, piggy#162), relayed in the `agent-mode@piggy`
    /// self-report so `piggy health` probes the right unit.
    pub fn with_service_name(mut self, service: Option<String>) -> Self {
        self.service_name = service;
        self
    }

    pub fn pin_handle(&self) -> Arc<Mutex<PinCache>> {
        self.pins.clone()
    }

    /// Shared handle to the #213 card lock, so the background reconcile loop
    /// (piggy#244) can `try_lock` it around its own card access and never race
    /// an in-flight request (piggy#214).
    pub fn card_lock_handle(&self) -> Arc<Mutex<()>> {
        self.card_lock.clone()
    }

    /// Shared handle to the agent's served key set. The identity/sign handlers
    /// read this live, so writing into it (e.g. from the piggy#175 recovery
    /// loop) makes the agent serve the new keys without a restart.
    pub fn keys_handle(&self) -> Arc<Mutex<Vec<CachedKey>>> {
        self.keys.clone()
    }

    fn find_key(keys: &[CachedKey], pubkey: &KeyData) -> Option<CachedKey> {
        keys.iter().find(|k| k.public_key == *pubkey).cloned()
    }

    /// Acquire the PIV PIN for an op on `guid`: the cached PIN if one is
    /// present, otherwise prompt the user on demand via SSH_ASKPASS (#58),
    /// mirroring the C pivy-agent's "get PIN at first use".
    ///
    /// The prompt is taken OUTSIDE any PC/SC transaction: it can block on a
    /// human for many seconds, and holding the card txn across it would
    /// wedge the card (the pivy#105 concern). Concurrent requests serialize
    /// on `prompt_lock` so a burst forks at most one dialog; the returned
    /// `fresh` flag tells the caller to cache the PIN only after an on-card
    /// verify succeeds (so a wrong prompted PIN is never cached). `op` is a
    /// short request label propagated as `PIGGY_ASKPASS_CONTEXT`.
    async fn ensure_pin(&self, op: &str, guid: &Guid) -> Result<AcquiredPin, AgentError> {
        // piggy#177: the cache is per-card. A hit verified on THIS card is
        // trusted (fresh: false); the `ssh-add -X` offer has not verified
        // anywhere yet, so it rides the fresh=true path — cached for this
        // card only after its on-card verify succeeds, and never re-offered
        // to a card that rejects it (`forget_pin` records the rejection).
        let from_cache = |cache: &PinCache| {
            cache.lookup(guid).map(|(pin, source)| AcquiredPin {
                pin,
                fresh: source == PinSource::Offered,
                offered: source == PinSource::Offered,
            })
        };
        if let Some(acq) = from_cache(&*self.pins.lock().await) {
            return Ok(acq);
        }
        // No cached PIN; serialize prompts and re-check (another request may
        // have just prompted and cached one while we waited).
        let _prompt_guard = self.prompt_lock.lock().await;
        if let Some(acq) = from_cache(&*self.pins.lock().await) {
            return Ok(acq);
        }
        let prompt = format!("Enter PIN for token {}", guid.short_id());
        let context = format!("piggy-agent:{op}:{}", guid.short_id());
        let prompt_start = std::time::Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            crate::card_oracle::run_askpass(&prompt, Some(&context))
        })
        .await
        .map_err(|e| AgentError::Other(format!("askpass task: {e}").into()))
        .and_then(|r| r.map_err(|e| AgentError::Other(e.to_string().into())));
        // stats-me: `piggy.agent.pin_prompt.<result>` + duration. Fires once
        // per on-demand prompt (so a wrong-PIN retry, piggy#142, emits twice).
        crate::stats::agent_op(
            "pin_prompt",
            crate::stats::outcome_of(&result),
            prompt_start.elapsed(),
        );
        Ok(AcquiredPin {
            pin: result?,
            fresh: true,
            offered: false,
        })
    }

    /// Cache a freshly-prompted (or freshly-promoted `ssh-add -X`) PIN for
    /// `guid` after its on-card verify succeeded.
    async fn cache_pin(&self, guid: &Guid, acquired: &AcquiredPin) {
        if acquired.fresh {
            self.pins
                .lock()
                .await
                .cache_verified(guid, acquired.pin.as_str());
        }
    }

    /// Drop `guid`'s cached PIN so the next `ensure_pin` re-prompts, and
    /// stop offering the `ssh-add -X` PIN to it. Called on a `PinIncorrect`
    /// retry: a freshly-prompted wrong PIN was never cached, but a stale
    /// cached PIN that the card now rejects must be cleared before the
    /// re-prompt (piggy#142). Other cards' verified PINs are untouched
    /// (piggy#177).
    async fn forget_pin(&self, guid: &Guid) {
        self.pins.lock().await.forget_for(guid);
    }
}

#[ssh_agent_lib::async_trait]
impl Session for PiggyAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let start = std::time::Instant::now();
        let res = self.request_identities_inner().await;
        crate::stats::agent_op(
            "request_identities",
            crate::stats::outcome_of(&res),
            start.elapsed(),
        );
        res
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let start = std::time::Instant::now();
        let pubkey = request.pubkey.clone();
        let res = self.sign_inner(request).await;
        crate::stats::agent_op("sign", crate::stats::outcome_of(&res), start.elapsed());
        if let Err(err) = &res {
            // piggy#178: a refused/failed sign otherwise returns
            // SSH_AGENT_FAILURE with no journal trace — the only evidence is
            // ssh's client-side error. Log the slot, key fingerprint/comment,
            // and underlying cause so a refusal is explainable directly from
            // `journalctl --user -u piggy-agent`. The key lookup is best-effort:
            // a refusal at find_cached_key (key not served) leaves it absent.
            let cached = self.find_cached_key(&pubkey).await.ok();
            let refusal = describe_sign_refusal(cached.as_ref(), &pubkey, err);
            tracing::warn!(
                slot = %refusal.slot,
                fingerprint = %refusal.fingerprint,
                comment = %refusal.comment,
                cause = %refusal.cause,
                "refused signing operation"
            );
        }
        res
    }

    async fn lock(&mut self, key: String) -> Result<(), AgentError> {
        let start = std::time::Instant::now();
        let res = self.lock_inner(key).await;
        crate::stats::agent_op("lock", crate::stats::outcome_of(&res), start.elapsed());
        res
    }

    async fn unlock(&mut self, key: String) -> Result<(), AgentError> {
        let start = std::time::Instant::now();
        let res = self.unlock_inner(key).await;
        crate::stats::agent_op("unlock", crate::stats::outcome_of(&res), start.elapsed());
        res
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let start = std::time::Instant::now();
        // Label the metric with the extension name (bare, so it matches
        // the C agent: e.g. ecdh@joyent.com -> piggy.agent.ecdh_joyent_com).
        let op = extension.name.as_str().to_owned();
        let res = self.extension_inner(extension).await;
        crate::stats::agent_op(&op, crate::stats::outcome_of(&res), start.elapsed());
        res
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        let start = std::time::Instant::now();
        let res = self.add_identity_inner(identity).await;
        crate::stats::agent_op(
            "add_identity",
            crate::stats::outcome_of(&res),
            start.elapsed(),
        );
        res
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        let start = std::time::Instant::now();
        let res = self.add_identity_constrained_inner(identity).await;
        crate::stats::agent_op(
            "add_identity_constrained",
            crate::stats::outcome_of(&res),
            start.elapsed(),
        );
        res
    }
}

impl PiggyAgent {
    async fn request_identities_inner(&mut self) -> Result<Vec<Identity>, AgentError> {
        let mut identities: Vec<Identity> = {
            let keys = self.keys.lock().await;
            keys.iter()
                .map(|k| Identity {
                    pubkey: k.public_key.clone(),
                    comment: k.comment.clone(),
                })
                .collect()
        };
        // piggy#215: offer upstream keys AFTER the native PIV keys (ssh
        // tries identities in offer order, and native keys must win). A
        // pubkey served both natively and by an upstream is offered once,
        // as the native entry.
        if !self.upstreams.is_empty() {
            for id in self.upstreams.list_identities().await {
                if identities.iter().any(|n| n.pubkey == id.pubkey) {
                    continue;
                }
                identities.push(id);
            }
        }
        Ok(identities)
    }

    async fn sign_inner(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        // An operator act is only ever signed by `operator-act@piggy`, which
        // shows its text first (RFC 0012 §2.7); the same bytes arriving here
        // would be signed unseen. Checked before routing, so a key held by
        // an upstream that lacks this rule is covered too.
        crate::operator_act::refuse_operator_act_signed_data(&request.data)
            .map_err(|refusal| AgentError::Other(refusal.into()))?;

        let key = match self.find_cached_key(&request.pubkey).await {
            Ok(key) => key,
            // piggy#215: not a native key — with upstreams configured,
            // route the request to the upstream that owns it. Proxied
            // signs deliberately bypass `card_lock`: they never touch
            // the card, so they must not queue behind it.
            Err(e) => {
                if self.upstreams.is_empty() {
                    return Err(e);
                }
                return self.upstreams.sign(request).await;
            }
        };

        // Prepare data for signing (independent of the card session).
        let sign_data = prepare_sign_data(key.algorithm, &request.data, request.flags)?;

        // Acquire-verify-sign with a bounded re-prompt on a wrong PIN (#142).
        // The PIN is acquired (cached or prompted) OUTSIDE the transaction —
        // the prompt must not be held across the card txn (piggy#105) — then
        // verify+sign are bracketed in one PC/SC transaction (piggy#56). On
        // PinIncorrect we forget the PIN and re-loop, re-prompting outside a
        // fresh transaction.
        let mut attempt = 0u32;
        loop {
            let acquired = if key.slot_id != 0x9E {
                Some(self.ensure_pin("sign", &key.guid).await?)
            } else {
                None
            };

            // One request on the card at a time (piggy#213); dropped at the
            // end of the loop body, so a wrong-PIN re-prompt runs unlocked.
            let _card_guard = self.card_lock.lock().await;
            let mut token = reconnect_to_token(&key.guid)?;
            // The session drops at end of scope: ResetCard if a PIN was
            // verified, LeaveCard for the 9E no-PIN path.
            let mut session = token
                .begin_pin_session()
                .map_err(|e| AgentError::Other(e.to_string().into()))?;

            if let Some(acq) = &acquired {
                // piggy#245: never spend a low-retry card's last tries on a
                // speculative ssh-add -X offer. Drop the offer for this card
                // (forget_pin records the rejection) and re-prompt instead;
                // a prompted PIN is unguarded and stays usable at 1 retry.
                if acq.offered && !offered_retries_ok(session.pin_retries_remaining()) {
                    self.forget_pin(&key.guid).await;
                    continue;
                }
                match session.verify_pin(&acq.pin) {
                    Ok(()) => self.cache_pin(&key.guid, acq).await,
                    Err(PivError::PinIncorrect { .. }) if attempt < PIN_RETRY_LIMIT => {
                        attempt += 1;
                        self.forget_pin(&key.guid).await;
                        continue;
                    }
                    Err(e) => return Err(AgentError::Other(e.to_string().into())),
                }
            }

            let sig_bytes = session
                .sign_prehash(key.slot_id, &sign_data)
                .map_err(|e| AgentError::Other(e.to_string().into()))?;
            return to_ssh_signature(key.algorithm, &sig_bytes, request.flags);
        }
    }

    async fn lock_inner(&mut self, key: String) -> Result<(), AgentError> {
        self.pins.lock().await.clear();
        // piggy#215: best-effort fan-out so upstream agents lock too —
        // the same reach `ssh-add -x` had through the mux. A dead
        // upstream's keys are unservable anyway, so its failure never
        // fails the native lock.
        if !self.upstreams.is_empty() {
            self.upstreams.lock_all(&key).await;
        }
        Ok(())
    }

    async fn unlock_inner(&mut self, key: String) -> Result<(), AgentError> {
        // piggy#177: an `ssh-add -X` PIN arrives with no card attached to
        // it — it becomes the OFFER, tried once per card and promoted to
        // that card's verified PIN when its on-card verify succeeds.
        self.pins.lock().await.offer(&key);
        // piggy#215: mirror of lock_inner's fan-out. The payload (for
        // piggy, the PIN) reaches every upstream — identical to today's
        // mux, which forwards `ssh-add -X` to all upstreams.
        if !self.upstreams.is_empty() {
            self.upstreams.unlock_all(&key).await;
        }
        Ok(())
    }

    async fn add_identity_inner(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        // piggy#215: piggy's native keys live on the card, so an added
        // software key can only go to the --add-new-keys-to upstream;
        // without one configured, refuse (the pool errors identically
        // when it has no target).
        self.upstreams.add_identity(identity).await
    }

    async fn add_identity_constrained_inner(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.upstreams.add_identity_constrained(identity).await
    }

    async fn extension_inner(
        &mut self,
        extension: Extension,
    ) -> Result<Option<Extension>, AgentError> {
        match extension.name.as_str() {
            "query" => {
                let mut supported: Vec<String> = [
                    "query",
                    "session-bind@openssh.com",
                    "pin-status@joyent.com",
                    "ecdh@joyent.com",
                    "ecdh-rebox@joyent.com",
                    "ykpiv-attest@joyent.com",
                    // eng#295: the role self-report `piggy health` reads.
                    // Always advertised — every Rust agent has a mode.
                    super::mode::AGENT_MODE_EXT,
                ]
                .iter()
                .map(|s| s.to_string())
                .collect();
                // RFC 0012 §2.8: a card agent serves operator acts itself. A
                // proxy-only agent advertises the extension only when an
                // upstream does, which the union below takes care of.
                if !self.proxy_only {
                    supported.push(crate::operator_act::EXTENSION.to_string());
                }
                // piggy#215: with upstreams configured, advertise the
                // self-reporting status extension (piggy health's probe
                // target — its absence means "nothing to check") and
                // union in the names the upstreams advertise, after the
                // native names and without duplicates. The flat
                // length-prefixed encoding below is unchanged — it's
                // what pivy's query parser expects (#119/#123).
                if !self.upstreams.is_empty() {
                    supported.push(super::upstream::UPSTREAM_STATUS_EXT.to_string());
                    for name in self.upstreams.query_extension_names(&extension).await {
                        if !supported.contains(&name) {
                            supported.push(name);
                        }
                    }
                }
                let mut buf = Vec::new();
                for name in &supported {
                    let bytes = name.as_bytes();
                    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    buf.extend_from_slice(bytes);
                }
                Ok(Some(Extension {
                    name: "query".into(),
                    details: buf.into(),
                }))
            }
            "session-bind@openssh.com" => {
                // Accept natively (unchanged) and best-effort fan out so
                // constraint-enforcing upstream agents see the binding;
                // upstream failures never fail the accept (#215).
                if !self.upstreams.is_empty() {
                    self.upstreams.fan_out_extension(&extension).await;
                }
                Ok(None)
            }
            "pin-status@joyent.com" => {
                let has_pin: u8 = if self.pins.lock().await.has_any() {
                    1
                } else {
                    0
                };
                let has_card: u8 = if !self.keys.lock().await.is_empty() {
                    1
                } else {
                    0
                };
                Ok(Some(Extension {
                    name: "pin-status@joyent.com".into(),
                    details: vec![has_pin, has_card].into(),
                }))
            }
            // The three piggy-native card extensions. Served natively when
            // the requested card key is in the cached set; when it is NOT
            // (a native miss) and upstreams are configured, the request is
            // forwarded to them first-success-wins — the same fallthrough
            // `sign` has for non-native keys. This is what lets a
            // proxy-only `piggy agent` (no card, upstreams only — the
            // remote-host role) front a forwarded card-backed agent for
            // `piggy pass show` decrypts (eng#295). Without upstreams the
            // miss is the refusal it always was.
            "ecdh@joyent.com" | "ecdh-rebox@joyent.com" | "ykpiv-attest@joyent.com" => {
                let details = extension.details.clone().into_bytes();
                let native = match extension.name.as_str() {
                    "ecdh@joyent.com" => self.handle_ecdh(&details).await,
                    "ecdh-rebox@joyent.com" => self.handle_ecdh_rebox(&details).await,
                    _ => self.handle_attest(&details).await,
                };
                match native {
                    Ok(resp) => Ok(resp),
                    Err(NativeExtError::Agent(e)) => Err(e),
                    Err(NativeExtError::KeyNotNative(_)) if !self.upstreams.is_empty() => {
                        tracing::debug!(
                            extension = %extension.name,
                            "card key not served natively; forwarding to upstreams"
                        );
                        self.upstreams.forward_extension(extension).await
                    }
                    Err(NativeExtError::KeyNotNative(msg)) => Err(AgentError::Other(msg.into())),
                }
            }
            // RFC 0012: an operator act. Every outcome the agent decides
            // itself is a status inside a named response, so a caller can
            // tell a refusal from an agent that predates the extension; a
            // request for a key held upstream is relayed as it came back.
            n if n == crate::operator_act::EXTENSION => {
                let details = extension.details.clone().into_bytes();
                match self.handle_operator_act(&details, extension).await {
                    OperatorActAnswer::Local(response) => Ok(Some(Extension {
                        name: crate::operator_act::EXTENSION.into(),
                        details: response.encode().into(),
                    })),
                    OperatorActAnswer::Relayed(answer) => answer,
                }
            }
            // eng#295: self-report the agent's role so `piggy health` can
            // shape its plan (a proxy-only agent has no card to check).
            n if n == super::mode::AGENT_MODE_EXT => {
                let mode = super::mode::AgentMode {
                    proxy_only: self.proxy_only,
                    native_keys: self.keys.lock().await.len(),
                    upstreams: self.upstreams.len(),
                    service: self.service_name.clone(),
                    event_driven: self.event_driven,
                };
                let json = serde_json::to_vec(&mode)
                    .map_err(|e| AgentError::Other(format!("agent-mode: {e}").into()))?;
                Ok(Some(Extension {
                    name: super::mode::AGENT_MODE_EXT.into(),
                    details: json.into(),
                }))
            }
            // piggy#215 step 5: self-report per-upstream reachability
            // for `piggy health`. Only answered when upstreams are
            // configured — otherwise it falls through to the refusal
            // below, exactly like any other unknown name.
            n if n == super::upstream::UPSTREAM_STATUS_EXT && !self.upstreams.is_empty() => {
                let statuses = self.upstreams.status().await;
                let json = serde_json::to_vec(&statuses)
                    .map_err(|e| AgentError::Other(format!("upstream-status: {e}").into()))?;
                Ok(Some(Extension {
                    name: super::upstream::UPSTREAM_STATUS_EXT.into(),
                    details: json.into(),
                }))
            }
            // piggy#215: an extension piggy doesn't serve natively is
            // forwarded to the upstreams (first success wins); without
            // upstreams, refuse exactly as before.
            _ if !self.upstreams.is_empty() => self.upstreams.forward_extension(extension).await,
            _ => Err(AgentError::from(
                ssh_agent_lib::proto::ProtoError::UnsupportedCommand { command: 27 },
            )),
        }
    }
}

/// Failure of a piggy-native card extension (`ecdh`, `ecdh-rebox`,
/// `ykpiv-attest`), split so `extension_inner` can tell a *native miss* —
/// the requested card key is simply not one this agent serves, which with
/// upstreams configured means "forward it" — from a genuine error in a
/// request the agent does own (malformed payload, card failure, wrong
/// PIN), which must never be retried against an upstream.
enum NativeExtError {
    /// The card key is not in the native cached set. Carries the message
    /// surfaced when there is no upstream to forward to.
    KeyNotNative(&'static str),
    Agent(AgentError),
}

impl From<AgentError> for NativeExtError {
    fn from(e: AgentError) -> Self {
        NativeExtError::Agent(e)
    }
}

/// How long a proxy waits for the agent that holds the card to answer an
/// operator act. The operator reads a text, types a PIN and touches the
/// card in that time, so the pool's probe-sized `--agent-timeout` does not
/// apply.
const OPERATOR_ACT_UPSTREAM_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// The answer to an `operator-act@piggy` request: one this agent decided, or
/// the upstream's own answer relayed unchanged (RFC 0012 §2.8).
enum OperatorActAnswer {
    Local(crate::operator_act::Response),
    Relayed(Result<Option<Extension>, AgentError>),
}

/// Check that the card attests `slot`'s key as an operator-act key (RFC 0012
/// §2.4): the attestation is for `requested`, states PIN always and touch
/// always, and is signed by the card's F9 certificate. The policy is read
/// from the card on every request; nothing configured or cached stands in
/// for it. `Err` is the `detail` of a `refused-policy` answer.
fn check_operator_act_attestation(
    token: &piggy_piv::PivToken,
    slot: u8,
    requested: &KeyData,
) -> Result<(), String> {
    let attestation = token
        .yk_attest(slot)
        .map_err(|e| format!("slot {slot:02X}: the card did not attest the key ({e})"))?;
    let (pin, touch) = piggy_piv::attest::parse_policy(&attestation)
        .map_err(|e| format!("slot {slot:02X}: the attestation states no policy ({e})"))?;
    let policy = piggy_piv::KeyPolicy { pin, touch };
    if !policy.serves_operator_acts() {
        return Err(format!("slot {slot:02X}: {policy}"));
    }
    let (_, attested_key) = piggy_piv::cert::extract_public_key(&attestation)
        .map_err(|e| format!("slot {slot:02X}: unreadable attestation ({e})"))?;
    if attested_key.key_data() != requested {
        return Err(format!(
            "slot {slot:02X}: the attestation is for a different key"
        ));
    }
    let intermediate = token
        .read_slot(0xF9)
        .map_err(|e| format!("slot {slot:02X}: no card attestation certificate ({e})"))?;
    let chains = openssl::x509::X509::from_der(&attestation)
        .and_then(|att| {
            let issuer = openssl::x509::X509::from_der(intermediate.cert_der())?;
            let issuer_key = issuer.public_key()?;
            att.verify(&issuer_key)
        })
        .map_err(|e| format!("slot {slot:02X}: attestation chain unreadable ({e})"))?;
    if !chains {
        return Err(format!(
            "slot {slot:02X}: the attestation is not signed by the card's attestation certificate"
        ));
    }
    Ok(())
}

/// The refusal for an operator act whose PIN prompt yielded no PIN: the
/// operator dismissed it, it timed out, or the askpass program failed. All
/// are `cancelled` (RFC 0012 §2.3); the detail says it was the prompt.
fn operator_act_prompt_refusal(e: &dyn std::fmt::Display) -> (crate::operator_act::Status, String) {
    (
        crate::operator_act::Status::Cancelled,
        format!("no PIN from the askpass: {e}"),
    )
}

/// The refusal for an operator act whose PIN the card did not take. Still
/// `error` (RFC 0012 §2.3 has no status of its own for it); the detail tells
/// a wrong PIN, with the card's count of tries left, from a blocked PIN and
/// from a verify that failed some other way.
fn operator_act_pin_refusal(e: &PivError) -> (crate::operator_act::Status, String) {
    let detail = match e {
        PivError::PinIncorrect { retries } => format!("wrong PIN ({retries} retries left)"),
        PivError::PinBlocked => "PIN blocked".to_string(),
        other => format!("PIN verify failed: {other}"),
    };
    (crate::operator_act::Status::Error, detail)
}

impl PiggyAgent {
    /// Serve one `operator-act@piggy` request (RFC 0012 §2).
    ///
    /// Order matters. The key decides who answers: a key this agent does not
    /// hold goes to the upstream that listed it, untouched and undisplayed.
    /// For a key held here, the namespace, the text and the attested policy
    /// are all judged BEFORE any prompt, so a refusal never costs the
    /// operator a PIN. Only then is the text shown, on the same prompt that
    /// takes the PIN, and the bytes signed are built here from that text.
    async fn handle_operator_act(
        &mut self,
        details: &[u8],
        extension: Extension,
    ) -> OperatorActAnswer {
        use crate::operator_act::{self as act, Response, Status};
        let refuse =
            |status, detail: String| OperatorActAnswer::Local(Response::refusal(status, detail));

        // Routing reads the key and nothing else: whether the rest of the
        // request is one this build understands is for the agent that holds
        // the key to say (RFC 0012 §2.8), and that may be a newer agent.
        let Some(public_key) =
            act::request_key(details).and_then(|key| PublicKey::from_bytes(key).ok())
        else {
            return refuse(Status::BadRequest, "malformed operator-act request".into());
        };
        let key = match self.find_cached_key(public_key.key_data()).await {
            Ok(key) => key,
            Err(_) => {
                let relayed = self
                    .upstreams
                    .forward_extension_for_key(
                        public_key.key_data(),
                        extension,
                        OPERATOR_ACT_UPSTREAM_WAIT,
                    )
                    .await;
                return match relayed {
                    Some(Ok(answer)) => OperatorActAnswer::Relayed(answer),
                    // The upstream never answered. Say so in a response, or
                    // the caller takes this agent for one without the
                    // extension. The prompt may still be up over there.
                    Some(Err(unanswered)) => refuse(Status::Error, unanswered),
                    None => refuse(Status::NoSuchKey, "no agent here serves that key".into()),
                };
            }
        };

        let Some(request) = act::Request::decode(details) else {
            return refuse(Status::BadRequest, "malformed operator-act request".into());
        };
        let Some(hash) = act::HashAlgorithm::parse(&request.hash_algorithm) else {
            return refuse(
                Status::BadRequest,
                format!(
                    "hash algorithm {:?} is not sha256 or sha512",
                    request.hash_algorithm
                ),
            );
        };

        let Some(class) = act::display_class(&request.namespace) else {
            return refuse(
                Status::RefusedNamespace,
                format!(
                    "namespace {:?} is not registered for operator acts",
                    request.namespace
                ),
            );
        };
        let Some(text) = act::displayable_text(&request.text) else {
            return refuse(
                Status::RefusedText,
                format!(
                    "the text must be 1 to {} bytes of UTF-8 with no control characters other than newline and tab",
                    act::MAX_TEXT_BYTES
                ),
            );
        };

        {
            let _card_guard = self.card_lock.lock().await;
            let token = match reconnect_to_token(&key.guid) {
                Ok(token) => token,
                Err(e) => return refuse(Status::CardAbsent, e.to_string()),
            };
            if let Err(detail) =
                check_operator_act_attestation(&token, key.slot_id, public_key.key_data())
            {
                return refuse(Status::RefusedPolicy, detail);
            }
        }

        // The PIN is asked for this act whatever is cached: the slot is
        // PIN-always, and the prompt is where the operator reads the text.
        let card = key.guid.short_id();
        let context = act::prompt_context(class, &card, key.slot_id, &request.namespace, text);
        let prompt = format!("PIN for card {card} to sign this operator act");
        let kind = class.as_str();
        let prompted = {
            let _prompt_guard = self.prompt_lock.lock().await;
            let prompt_start = std::time::Instant::now();
            let prompted = tokio::task::spawn_blocking(move || {
                crate::card_oracle::run_askpass_of_kind(&prompt, Some(&context), Some(kind))
            })
            .await;
            // The same `piggy.agent.pin_prompt.<result>` series `ensure_pin`
            // feeds: an operator-act prompt is a PIN prompt.
            let outcome = if matches!(prompted, Ok(Ok(_))) {
                crate::stats::Outcome::Success
            } else {
                crate::stats::Outcome::Failure
            };
            crate::stats::agent_op("pin_prompt", outcome, prompt_start.elapsed());
            prompted
        };
        let pin = match prompted {
            Ok(Ok(pin)) => pin,
            Ok(Err(e)) => {
                let (status, detail) = operator_act_prompt_refusal(&e);
                return refuse(status, detail);
            }
            Err(e) => return refuse(Status::Error, format!("askpass task: {e}")),
        };

        let signed_data = act::signed_data(&request.namespace, hash, &request.text);
        let digest = match prepare_sign_data(key.algorithm, &signed_data, 0) {
            Ok(digest) => digest,
            Err(e) => return refuse(Status::Error, e.to_string()),
        };
        let card_signature = {
            let _card_guard = self.card_lock.lock().await;
            let mut token = match reconnect_to_token(&key.guid) {
                Ok(token) => token,
                Err(e) => return refuse(Status::CardAbsent, e.to_string()),
            };
            // The prompt may have been up for minutes. Whatever was attested
            // before it is not trusted across that gap (RFC 0012 §2.4): the
            // card in the reader now attests again, under the lock the sign
            // is made under.
            if let Err(detail) =
                check_operator_act_attestation(&token, key.slot_id, public_key.key_data())
            {
                return refuse(Status::RefusedPolicy, detail);
            }
            let mut session = match token.begin_pin_session() {
                Ok(session) => session,
                Err(e) => return refuse(Status::CardAbsent, e.to_string()),
            };
            if let Err(e) = session.verify_pin(&pin) {
                let (status, detail) = operator_act_pin_refusal(&e);
                return refuse(status, detail);
            }
            // The card now waits for the touch, and the PIN dialog that had
            // the operator's attention has just closed: tell them.
            let notified = crate::card_oracle::notify_operator(
                "piggy-agent: touch your card",
                &format!(
                    "card {card}, slot {:02X}: touch it now to sign the {kind} operator act",
                    key.slot_id
                ),
            );
            if !notified {
                tracing::warn!(
                    card = %card,
                    "operator act: waiting for a touch, with no notifier to say so \
                     (set SSH_NOTIFY_SEND or PIGGY_ASKPASS_NOTIFIER)"
                );
            }
            // The algorithm is already known from the key list, so sign with
            // it directly: `sign_prehash` would read the slot's certificate
            // first, and on a PIN-always slot a real YubiKey drops the
            // verified PIN across that extra GET DATA, answering 6982 to the
            // sign even after a good PIN and a touch (piggy#325).
            match session.sign_prehash_with_alg(key.slot_id, key.algorithm.to_byte(), &digest) {
                Ok(signature) => signature,
                // 6982 (the card's "security status not satisfied") right
                // after a good PIN in the same transaction is the card
                // giving up on the touch.
                Err(PivError::PinRequired) => {
                    return refuse(Status::Cancelled, "the card was not touched in time".into());
                }
                Err(e) => return refuse(Status::Error, e.to_string()),
            }
        };

        let signature = match to_ssh_signature(key.algorithm, &card_signature, 0) {
            Ok(signature) => signature,
            Err(e) => return refuse(Status::Error, e.to_string()),
        };
        let encoded = act::ssh_signature(signature.algorithm().as_str(), signature.as_bytes());
        OperatorActAnswer::Local(Response::signed(act::sshsig_blob(
            &request.key,
            &request.namespace,
            hash,
            &encoded,
        )))
    }

    async fn find_cached_key(&self, pubkey: &KeyData) -> Result<CachedKey, AgentError> {
        let keys = self.keys.lock().await;
        Self::find_key(&keys, pubkey).ok_or_else(|| AgentError::Other("key not found".into()))
    }

    async fn handle_ecdh(&mut self, details: &[u8]) -> Result<Option<Extension>, NativeExtError> {
        let inner = read_ssh_string(details, 0)
            .map_err(|e| AgentError::Other(e.into()))?
            .0;

        let (card_key_blob, pos) =
            read_ssh_string(inner, 0).map_err(|e| AgentError::Other(e.into()))?;
        let (partner_blob, pos) =
            read_ssh_string(inner, pos).map_err(|e| AgentError::Other(e.into()))?;
        let _flags = read_u32_be(inner, pos, "ecdh")?;

        let card_pubkey = PublicKey::from_bytes(card_key_blob)
            .map_err(|e| AgentError::Other(format!("ecdh: bad card key: {e}").into()))?;

        let key = self
            .find_cached_key(card_pubkey.key_data())
            .await
            .map_err(|_| NativeExtError::KeyNotNative("ecdh: key not found"))?;

        let ec_point = extract_ec_point_from_ssh_blob(partner_blob)
            .map_err(|e| AgentError::Other(e.into()))?;

        match key.algorithm {
            PivAlgorithm::EcP256 | PivAlgorithm::EcP384 => {}
            _ => {
                return Err(AgentError::Other("ecdh: key is not an EC key".into()).into());
            }
        }

        // Acquire-verify-ECDH with a bounded re-prompt on a wrong PIN (#142).
        // PIN acquired OUTSIDE the txn (piggy#105); verify+ECDH bracketed in
        // one transaction (piggy#56). Slot 9E needs no PIN.
        let mut secret = {
            let mut attempt = 0u32;
            loop {
                let acquired = if key.slot_id != 0x9E {
                    Some(self.ensure_pin("ecdh", &key.guid).await?)
                } else {
                    None
                };

                // One request on the card at a time (piggy#213).
                let _card_guard = self.card_lock.lock().await;
                let mut token = reconnect_to_token(&key.guid)?;
                let mut session = token
                    .begin_pin_session()
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;

                if let Some(acq) = &acquired {
                    // piggy#245: never spend a low-retry card's last tries on
                    // a speculative ssh-add -X offer. Drop the offer for this
                    // card (forget_pin records the rejection) and re-prompt;
                    // a prompted PIN is unguarded and stays usable at 1 retry.
                    if acq.offered && !offered_retries_ok(session.pin_retries_remaining()) {
                        self.forget_pin(&key.guid).await;
                        continue;
                    }
                    match session.verify_pin(&acq.pin) {
                        Ok(()) => self.cache_pin(&key.guid, acq).await,
                        Err(PivError::PinIncorrect { .. }) if attempt < PIN_RETRY_LIMIT => {
                            attempt += 1;
                            self.forget_pin(&key.guid).await;
                            continue;
                        }
                        Err(e) => return Err(AgentError::Other(e.to_string().into()).into()),
                    }
                }

                break session
                    .ecdh_derive(key.slot_id, &ec_point)
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;
            }
        };

        let mut resp = Vec::new();
        resp.extend_from_slice(&(secret.len() as u32).to_be_bytes());
        resp.extend_from_slice(&secret);
        secret.zeroize();

        Ok(Some(Extension {
            name: "ecdh@joyent.com".into(),
            details: resp.into(),
        }))
    }

    async fn handle_attest(&mut self, details: &[u8]) -> Result<Option<Extension>, NativeExtError> {
        let inner = read_ssh_string(details, 0)
            .map_err(|e| AgentError::Other(e.into()))?
            .0;

        let (card_key_blob, pos) =
            read_ssh_string(inner, 0).map_err(|e| AgentError::Other(e.into()))?;
        let _flags = read_u32_be(inner, pos, "attest")?;

        let card_pubkey = PublicKey::from_bytes(card_key_blob)
            .map_err(|e| AgentError::Other(format!("attest: bad card key: {e}").into()))?;

        let key = self
            .find_cached_key(card_pubkey.key_data())
            .await
            .map_err(|_| NativeExtError::KeyNotNative("attest: key not found"))?;

        // One request on the card at a time (piggy#213).
        let _card_guard = self.card_lock.lock().await;
        let token = reconnect_to_token(&key.guid)?;

        let attest_cert = token
            .yk_attest(key.slot_id)
            .map_err(|e| AgentError::Other(e.to_string().into()))?;

        let mut certs: Vec<Vec<u8>> = vec![attest_cert];

        if let Ok(f9_slot) = token.read_slot(0xF9) {
            certs.push(f9_slot.cert_der().to_vec());
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&(certs.len() as u32).to_be_bytes());
        for cert in &certs {
            resp.extend_from_slice(&(cert.len() as u32).to_be_bytes());
            resp.extend_from_slice(cert);
        }

        Ok(Some(Extension {
            name: "ykpiv-attest@joyent.com".into(),
            details: resp.into(),
        }))
    }

    async fn handle_ecdh_rebox(
        &mut self,
        details: &[u8],
    ) -> Result<Option<Extension>, NativeExtError> {
        let inner = read_ssh_string(details, 0)
            .map_err(|e| AgentError::Other(e.into()))?
            .0;

        let (boxbuf, pos) = read_ssh_string(inner, 0).map_err(|e| AgentError::Other(e.into()))?;
        let (guid_bytes, pos) =
            read_ssh_string(inner, pos).map_err(|e| AgentError::Other(e.into()))?;
        let slot_id = *inner
            .get(pos)
            .ok_or_else(|| AgentError::Other("ecdh-rebox: truncated slot_id".into()))?;
        let pos = pos + 1;
        let (partner_blob, pos) =
            read_ssh_string(inner, pos).map_err(|e| AgentError::Other(e.into()))?;
        let flags = read_u32_be(inner, pos, "ecdh-rebox")?;

        if flags != 0 {
            return Err(AgentError::Other(
                format!("ecdh-rebox: unsupported flags {flags:#x}").into(),
            )
            .into());
        }

        let mut piv_box = PivBox::from_bytes(boxbuf)
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: bad box: {e}").into()))?;

        // Resolve the agent key + slot for this box. A GUID/slot hint (legacy
        // boxes) matches directly; piggy 2.x boxes are guidless, so match the
        // cached key by the box's recipient pubkey (SEC1-uncompressed
        // equality) — the same pubkey-matching the agentless card_oracle and
        // `handle_ecdh` use. Without this the agent can't decrypt guidless
        // piggy boxes (piggy#58).
        // Either miss is a *native* miss (`KeyNotNative`): the box may well
        // be for a key an upstream serves, so `extension_inner` forwards it.
        let (key, box_slot) =
            match piv_box.guid_slot.as_ref() {
                Some((box_guid, slot)) => {
                    let key = self.find_key_by_guid(box_guid).await.ok_or(
                        NativeExtError::KeyNotNative("ecdh-rebox: no matching key for GUID"),
                    )?;
                    (key, *slot)
                }
                None => self
                    .find_key_by_recipient_pubkey(&piv_box.recipient_pubkey)
                    .await
                    .ok_or(NativeExtError::KeyNotNative(
                        "ecdh-rebox: no agent key matches the box recipient",
                    ))?,
            };

        let ec_point = decompress_ec_point(&piv_box.ephemeral_pubkey, piv_box.curve)?;

        // Acquire-verify-ECDH with a bounded re-prompt on a wrong PIN (#142).
        // PIN acquired OUTSIDE the txn (piggy#105); verify+ECDH bracketed in
        // one transaction (piggy#56). The transaction is released when the loop
        // block ends (ResetCard if a PIN was verified) before the offline
        // reseal below, which is pure CPU and needs no card. Slot 9E needs no PIN.
        let shared_secret = {
            let mut attempt = 0u32;
            loop {
                let acquired = if box_slot != 0x9E {
                    Some(self.ensure_pin("ecdh-rebox", &key.guid).await?)
                } else {
                    None
                };

                // One request on the card at a time (piggy#213).
                let _card_guard = self.card_lock.lock().await;
                let mut token = reconnect_to_token(&key.guid)?;
                let mut session = token
                    .begin_pin_session()
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;

                if let Some(acq) = &acquired {
                    // piggy#245: never spend a low-retry card's last tries on
                    // a speculative ssh-add -X offer. Drop the offer for this
                    // card (forget_pin records the rejection) and re-prompt;
                    // a prompted PIN is unguarded and stays usable at 1 retry.
                    if acq.offered && !offered_retries_ok(session.pin_retries_remaining()) {
                        self.forget_pin(&key.guid).await;
                        continue;
                    }
                    match session.verify_pin(&acq.pin) {
                        Ok(()) => self.cache_pin(&key.guid, acq).await,
                        Err(PivError::PinIncorrect { .. }) if attempt < PIN_RETRY_LIMIT => {
                            attempt += 1;
                            self.forget_pin(&key.guid).await;
                            continue;
                        }
                        Err(e) => return Err(AgentError::Other(e.to_string().into()).into()),
                    }
                }

                break session
                    .ecdh_derive(box_slot, &ec_point)
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;
            }
        };

        piv_box
            .open_with_secret(&shared_secret)
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: decrypt: {e}").into()))?;

        let partner_point = extract_ec_point_from_ssh_blob(partner_blob)
            .map_err(|e| AgentError::Other(e.into()))?;

        let partner_ec_pub = ec_public_key_from_point(&partner_point, piv_box.curve)
            .map_err(|e| AgentError::Other(e.into()))?;

        let mut new_box = PivBox::new(piv_box.curve);
        if !guid_bytes.is_empty() {
            let target_guid = Guid::from_bytes(guid_bytes).map_err(|e| {
                AgentError::Other(format!("ecdh-rebox: bad target GUID: {e}").into())
            })?;
            new_box.guid_slot = Some((target_guid, slot_id));
        }
        let plaintext = piv_box
            .take_data()
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: take_data: {e}").into()))?;
        new_box.set_data(&plaintext);

        new_box
            .seal_offline(&partner_ec_pub)
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: seal: {e}").into()))?;

        let new_box_bytes = new_box
            .to_bytes()
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: serialize: {e}").into()))?;

        let mut resp = Vec::new();
        resp.extend_from_slice(&(new_box_bytes.len() as u32).to_be_bytes());
        resp.extend_from_slice(&new_box_bytes);

        Ok(Some(Extension {
            name: "ecdh-rebox@joyent.com".into(),
            details: resp.into(),
        }))
    }

    async fn find_key_by_guid(&self, guid: &Guid) -> Option<CachedKey> {
        let keys = self.keys.lock().await;
        keys.iter().find(|k| &k.guid == guid).cloned()
    }

    /// Match a cached EC key by a box recipient pubkey (raw SEC1 bytes from a
    /// guidless box), returning the key and the slot it lives in. The
    /// recipient bytes (compressed on the wire) and each cached key's pubkey
    /// are both reduced to SEC1-uncompressed form before comparison, so the
    /// encodings agree (mirrors `card_oracle`'s pubkey matching).
    async fn find_key_by_recipient_pubkey(&self, recipient: &[u8]) -> Option<(CachedKey, u8)> {
        let want = crate::card_oracle::canonicalize_uncompressed(recipient).ok()?;
        let keys = self.keys.lock().await;
        keys.iter().find_map(|k| match &k.public_key {
            KeyData::Ecdsa(ec) if ec.as_sec1_bytes() == want.as_slice() => {
                Some((k.clone(), k.slot_id))
            }
            _ => None,
        })
    }
}

/// Hash data and prepare it for the PIV card's GENERAL AUTHENTICATE.
/// For ECDSA: returns the hash digest.
/// For RSA: returns PKCS#1 v1.5 DigestInfo padded to key size.
fn prepare_sign_data(alg: PivAlgorithm, data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    match alg {
        PivAlgorithm::EcP256 => {
            let hash = Sha256::digest(data);
            Ok(hash.to_vec())
        }
        PivAlgorithm::EcP384 => {
            let hash = Sha384::digest(data);
            Ok(hash.to_vec())
        }
        PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => {
            let key_size = match alg {
                PivAlgorithm::Rsa1024 => 128,
                PivAlgorithm::Rsa2048 => 256,
                _ => unreachable!(),
            };

            let (hash_bytes, digest_prefix) = if flags & signature::RSA_SHA2_512 != 0 {
                let hash = Sha512::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA512)
            } else {
                let hash = Sha256::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA256)
            };

            // Build PKCS#1 v1.5 DigestInfo + pad
            pkcs1_v15_pad(&hash_bytes, digest_prefix, key_size)
        }
        PivAlgorithm::Ed25519 => {
            // Ed25519 does its own hashing on card; pass raw data
            Ok(data.to_vec())
        }
    }
}

/// Fields describing a refused/failed signing operation, for the piggy#178
/// WARN log. The agent otherwise returns `SSH_AGENT_FAILURE` with no journal
/// trace, leaving a refusal diagnosable only from ssh's client-side error.
///
/// Split out as a pure function so the field assembly — slot hex formatting,
/// comment fallback, fingerprint derivation — is unit-testable without a
/// tracing subscriber.
struct SignRefusal {
    /// PIV slot in the card's hex convention (e.g. `9A`), or `unknown` when the
    /// requested key isn't in the served set.
    slot: String,
    /// SHA-256 SSH fingerprint of the requested key (`SHA256:…`).
    fingerprint: String,
    /// The cached key's comment, or `<none>` when absent/empty.
    comment: String,
    /// Underlying cause (card APDU / PIN / handle error) as rendered by the
    /// agent error.
    cause: String,
}

fn describe_sign_refusal(
    key: Option<&CachedKey>,
    pubkey: &KeyData,
    err: &AgentError,
) -> SignRefusal {
    SignRefusal {
        slot: key
            .map(|k| format!("{:02X}", k.slot_id))
            .unwrap_or_else(|| "unknown".to_string()),
        fingerprint: pubkey.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        comment: key
            .map(|k| k.comment.clone())
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| "<none>".to_string()),
        cause: err.to_string(),
    }
}

// DER-encoded DigestInfo AlgorithmIdentifier prefixes for PKCS#1 v1.5
// SHA-256: SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING }
const RSA_DIGEST_PREFIX_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

// SHA-512: SEQUENCE { SEQUENCE { OID sha512, NULL }, OCTET STRING }
const RSA_DIGEST_PREFIX_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Build PKCS#1 v1.5 padded signing block:
/// 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
fn pkcs1_v15_pad(
    hash: &[u8],
    digest_prefix: &[u8],
    key_size: usize,
) -> Result<Vec<u8>, AgentError> {
    let digest_info_len = digest_prefix.len() + hash.len();
    if key_size < digest_info_len + 11 {
        return Err(AgentError::Other("key too small for digest".into()));
    }

    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x01;

    let pad_len = key_size - digest_info_len - 3;
    for byte in &mut padded[2..2 + pad_len] {
        *byte = 0xFF;
    }
    padded[2 + pad_len] = 0x00;

    let di_start = 3 + pad_len;
    padded[di_start..di_start + digest_prefix.len()].copy_from_slice(digest_prefix);
    padded[di_start + digest_prefix.len()..].copy_from_slice(hash);

    Ok(padded)
}

/// Convert raw card signature bytes to ssh_key::Signature.
fn to_ssh_signature(
    alg: PivAlgorithm,
    sig_bytes: &[u8],
    flags: u32,
) -> Result<Signature, AgentError> {
    match alg {
        PivAlgorithm::EcP256 | PivAlgorithm::EcP384 => {
            let algo_name = match alg {
                PivAlgorithm::EcP256 => "ecdsa-sha2-nistp256",
                PivAlgorithm::EcP384 => "ecdsa-sha2-nistp384",
                _ => unreachable!(),
            };
            let algo = Algorithm::new(algo_name).map_err(AgentError::other)?;
            let (r, s) = decode_der_ecdsa_signature(sig_bytes)?;
            let ssh_sig = encode_ecdsa_ssh_signature(&r, &s);
            Signature::new(algo, ssh_sig).map_err(AgentError::other)
        }
        PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => {
            let algo_name = if flags & signature::RSA_SHA2_512 != 0 {
                "rsa-sha2-512"
            } else {
                "rsa-sha2-256"
            };
            let algo = Algorithm::new(algo_name).map_err(AgentError::other)?;
            Signature::new(algo, sig_bytes.to_vec()).map_err(AgentError::other)
        }
        PivAlgorithm::Ed25519 => {
            let algo = Algorithm::new("ssh-ed25519").map_err(AgentError::other)?;
            Signature::new(algo, sig_bytes.to_vec()).map_err(AgentError::other)
        }
    }
}

/// Decode a DER-encoded ECDSA signature into (r, s) as big-endian byte arrays.
///
/// Thin agent-side wrapper over the shared, bounds-checked parser in
/// [`crate::ecdsa_sig`], adapting its `String` error into [`AgentError`]. The
/// parsing logic (and its exhaustive malformed-input tests) lives in the
/// shared module so `piggy sign-bytes` reuses the exact same decoder.
fn decode_der_ecdsa_signature(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AgentError> {
    crate::ecdsa_sig::decode_der_ecdsa_signature(der).map_err(|e| AgentError::Other(e.into()))
}

/// Read an SSH string (u32 length prefix + payload) from `data` at `offset`.
/// Returns `(&payload_slice, next_offset)`.
fn read_ssh_string(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    let hdr_end = offset
        .checked_add(4)
        .filter(|&e| e <= data.len())
        .ok_or("SSH string: not enough data for length")?;
    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let end = hdr_end
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| {
            format!(
                "SSH string: length {len} exceeds remaining data {}",
                data.len() - hdr_end
            )
        })?;
    Ok((&data[hdr_end..end], end))
}

/// Read a big-endian u32 from `data` at `offset`, returning the value.
fn read_u32_be(data: &[u8], offset: usize, label: &str) -> Result<u32, AgentError> {
    let end = offset.checked_add(4).filter(|&e| e <= data.len());
    if end.is_none() {
        return Err(AgentError::Other(
            format!("{label}: truncated flags field").into(),
        ));
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Establish a fresh PCSC context and find the token matching `guid`.
pub(super) fn reconnect_to_token(guid: &Guid) -> Result<piggy_piv::PivToken, AgentError> {
    let ctx = PivContext::new().map_err(|e| AgentError::Other(e.to_string().into()))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| AgentError::Other(e.to_string().into()))?;
    tokens
        .into_iter()
        .find(|t| t.guid() == guid)
        .ok_or_else(|| AgentError::Other("PIV token no longer available".into()))
}

/// Extract the raw SEC1 EC point from an SSH ECDSA public key blob.
///
/// SSH ECDSA public key wire format:
///   ssh_string("ecdsa-sha2-nistp256")  (or nistp384)
///   ssh_string("nistp256")             (curve identifier)
///   ssh_string(<SEC1 EC point>)        (04 || x || y)
fn extract_ec_point_from_ssh_blob(blob: &[u8]) -> Result<Vec<u8>, String> {
    let (_algo, pos) = read_ssh_string(blob, 0)?;
    let (_curve, pos) = read_ssh_string(blob, pos)?;
    let (point, _) = read_ssh_string(blob, pos)?;
    Ok(point.to_vec())
}

fn decompress_ec_point(compressed: &[u8], curve: EcCurve) -> Result<Vec<u8>, AgentError> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint, PointConversionForm};

    let group = EcGroup::from_curve_name(curve.nid())
        .map_err(|e| AgentError::Other(format!("ec group: {e}").into()))?;
    let mut ctx =
        BigNumContext::new().map_err(|e| AgentError::Other(format!("bn ctx: {e}").into()))?;
    let point = EcPoint::from_bytes(&group, compressed, &mut ctx)
        .map_err(|e| AgentError::Other(format!("ec decompress: {e}").into()))?;
    point
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| AgentError::Other(format!("ec to_bytes: {e}").into()))
}

fn ec_public_key_from_point(
    point: &[u8],
    curve: EcCurve,
) -> Result<openssl::ec::EcKey<openssl::pkey::Public>, String> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, EcPoint};

    let group = EcGroup::from_curve_name(curve.nid()).map_err(|e| format!("ec group: {e}"))?;
    let mut ctx = BigNumContext::new().map_err(|e| format!("bn ctx: {e}"))?;
    let ec_point =
        EcPoint::from_bytes(&group, point, &mut ctx).map_err(|e| format!("ec point: {e}"))?;
    EcKey::from_public_key(&group, &ec_point).map_err(|e| format!("ec key: {e}"))
}

/// Encode (r, s) as SSH mpint-pair for ECDSA signature blob.
/// SSH ECDSA signature blob = string(r as mpint) || string(s as mpint)
fn encode_ecdsa_ssh_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // r as SSH mpint
    let r_len = r.len() as u32;
    buf.extend_from_slice(&r_len.to_be_bytes());
    buf.extend_from_slice(r);
    // s as SSH mpint
    let s_len = s.len() as u32;
    buf.extend_from_slice(&s_len.to_be_bytes());
    buf.extend_from_slice(s);
    buf
}

#[cfg(test)]
#[allow(
    clippy::vec_init_then_push,
    clippy::manual_repeat_n,
    clippy::needless_range_loop
)]
mod tests {
    //! Unit tests for the pure signing-path helpers plus the
    //! non-PCSC-touching portions of the `Session` impl.
    //!
    //! Tests DO NOT touch PCSC or real hardware. `PiggyAgent::sign`
    //! internally calls `PivContext::new()` once a matching key has
    //! been found; the tests here only exercise the *pre-PCSC*
    //! branch (key not found in cache) and the pure helpers.

    use super::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use ssh_agent_lib::proto::{Extension, SignRequest, signature};
    use ssh_key::public::{Ed25519PublicKey, KeyData};

    /// piggy#245: the offered-PIN retry guard attempts a speculative
    /// `ssh-add -X` offer only when the card confirms at least
    /// `MIN_RETRIES_FOR_OFFERED_PIN` tries left; a low count or a query
    /// error is treated as unsafe (drop the offer, re-prompt).
    #[test]
    fn offered_retries_ok_permits_only_a_confirmed_safe_margin() {
        assert!(offered_retries_ok(Ok(u8::MAX)), "already verified: safe");
        assert!(offered_retries_ok(Ok(3)), "3 retries: safe");
        assert!(
            offered_retries_ok(Ok(MIN_RETRIES_FOR_OFFERED_PIN)),
            "at the floor: safe"
        );
        assert!(!offered_retries_ok(Ok(1)), "one from lockout: unsafe");
        assert!(!offered_retries_ok(Ok(0)), "blocked: unsafe");
        assert!(
            !offered_retries_ok(Err(PivError::Apdu { sw: 0x6a80 })),
            "query error: unsafe (no confirmed count)"
        );
    }

    // -------- Helpers --------

    /// Build an arbitrary Ed25519 KeyData for testing. All zeroes is
    /// not a cryptographically valid public key, but `Session` never
    /// verifies that — it only uses `KeyData` for equality matching.
    fn ed25519_key_data(seed: u8) -> KeyData {
        KeyData::Ed25519(Ed25519PublicKey([seed; 32]))
    }

    fn sample_guid() -> Guid {
        Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap()
    }

    fn cached_ed25519(seed: u8, slot: u8) -> CachedKey {
        CachedKey {
            guid: sample_guid(),
            reader_name: "MockReader".into(),
            slot_id: slot,
            algorithm: PivAlgorithm::Ed25519,
            public_key: ed25519_key_data(seed),
            comment: format!("seed-{seed}"),
        }
    }

    // -------- prepare_sign_data --------

    #[test]
    fn prepare_sign_data_ecp256_returns_sha256_digest() {
        let data = b"hello world";
        let out = prepare_sign_data(PivAlgorithm::EcP256, data, 0).unwrap();
        let expected = Sha256::digest(data).to_vec();
        assert_eq!(out, expected);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn prepare_sign_data_ecp384_returns_sha384_digest() {
        let data = b"hello world";
        let out = prepare_sign_data(PivAlgorithm::EcP384, data, 0).unwrap();
        let expected = Sha384::digest(data).to_vec();
        assert_eq!(out, expected);
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn prepare_sign_data_ed25519_is_passthrough() {
        let data = b"\x00\x01\x02ascii and binary\xff";
        let out = prepare_sign_data(PivAlgorithm::Ed25519, data, 0).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn prepare_sign_data_ed25519_passthrough_empty() {
        let out = prepare_sign_data(PivAlgorithm::Ed25519, b"", 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn prepare_sign_data_rsa2048_default_sha256() {
        // flags=0 should default to SHA-256
        let data = b"test message";
        let out = prepare_sign_data(PivAlgorithm::Rsa2048, data, 0).unwrap();
        assert_eq!(out.len(), 256);

        // PKCS#1 v1.5 header: 00 01 FF ... FF 00 <DigestInfo> <hash>
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x01);

        let hash = Sha256::digest(data);
        let digest_info_len = RSA_DIGEST_PREFIX_SHA256.len() + hash.len();
        // Tail must equal digest prefix + hash
        let tail_start = out.len() - digest_info_len;
        assert_eq!(
            &out[tail_start..tail_start + RSA_DIGEST_PREFIX_SHA256.len()],
            RSA_DIGEST_PREFIX_SHA256
        );
        assert_eq!(
            &out[tail_start + RSA_DIGEST_PREFIX_SHA256.len()..],
            hash.as_slice()
        );

        // Byte just before DigestInfo must be 0x00 separator
        assert_eq!(out[tail_start - 1], 0x00);
        // All bytes between 0x01 and the 0x00 separator are 0xFF padding
        for &b in &out[2..tail_start - 1] {
            assert_eq!(b, 0xFF);
        }
    }

    #[test]
    fn prepare_sign_data_rsa2048_explicit_sha256_flag() {
        let data = b"test message";
        let default_out = prepare_sign_data(PivAlgorithm::Rsa2048, data, 0).unwrap();
        let flagged_out =
            prepare_sign_data(PivAlgorithm::Rsa2048, data, signature::RSA_SHA2_256).unwrap();
        assert_eq!(default_out, flagged_out);
    }

    #[test]
    fn prepare_sign_data_rsa2048_sha512_flag() {
        let data = b"test message";
        let out = prepare_sign_data(PivAlgorithm::Rsa2048, data, signature::RSA_SHA2_512).unwrap();
        assert_eq!(out.len(), 256);

        let hash = Sha512::digest(data);
        let digest_info_len = RSA_DIGEST_PREFIX_SHA512.len() + hash.len();
        let tail_start = out.len() - digest_info_len;
        assert_eq!(
            &out[tail_start..tail_start + RSA_DIGEST_PREFIX_SHA512.len()],
            RSA_DIGEST_PREFIX_SHA512
        );
        assert_eq!(
            &out[tail_start + RSA_DIGEST_PREFIX_SHA512.len()..],
            hash.as_slice()
        );
    }

    /// When both SHA-256 and SHA-512 flags are set, the production code
    /// (match arm order: SHA-512 first) picks SHA-512. Pins this so a
    /// future refactor that flips branch order would fail — the
    /// precedence is not documented anywhere else.
    #[test]
    fn prepare_sign_data_rsa2048_sha512_wins_when_both_flags_set() {
        let data = b"precedence test";
        let out = prepare_sign_data(
            PivAlgorithm::Rsa2048,
            data,
            signature::RSA_SHA2_256 | signature::RSA_SHA2_512,
        )
        .unwrap();
        // If SHA-512 wins, the tail of the padded block is the SHA-512
        // DigestInfo + SHA-512 hash — NOT the SHA-256 version.
        let hash = Sha512::digest(data);
        let digest_info_len = RSA_DIGEST_PREFIX_SHA512.len() + hash.len();
        let tail_start = out.len() - digest_info_len;
        assert_eq!(
            &out[tail_start..tail_start + RSA_DIGEST_PREFIX_SHA512.len()],
            RSA_DIGEST_PREFIX_SHA512,
            "SHA-512 must take precedence over SHA-256 when both flags set"
        );
        assert_eq!(
            &out[tail_start + RSA_DIGEST_PREFIX_SHA512.len()..],
            hash.as_slice()
        );
    }

    /// Unknown flag bits must default to SHA-256 — verify by comparing
    /// to the pure-default (flags=0) output.
    #[test]
    fn prepare_sign_data_rsa2048_unknown_flags_default_to_sha256() {
        let data = b"unknown flags";
        let default_out = prepare_sign_data(PivAlgorithm::Rsa2048, data, 0).unwrap();
        // Pick a flag bit that is NOT RSA_SHA2_256 or RSA_SHA2_512.
        // The SSH agent protocol defines those as bits 1 and 2; bit 31
        // is guaranteed-unused territory.
        let noise_flags: u32 = 1 << 31;
        let noisy_out = prepare_sign_data(PivAlgorithm::Rsa2048, data, noise_flags).unwrap();
        assert_eq!(
            default_out, noisy_out,
            "unknown flag bits must be ignored (default to SHA-256)"
        );
    }

    #[test]
    fn prepare_sign_data_rsa1024_default_sha256() {
        let data = b"rsa1024 message";
        let out = prepare_sign_data(PivAlgorithm::Rsa1024, data, 0).unwrap();
        assert_eq!(out.len(), 128);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x01);
    }

    #[test]
    fn prepare_sign_data_rsa1024_rejects_sha512_digest_too_large() {
        // SHA-512 DigestInfo (19 + 64 = 83 bytes) plus the minimum 11
        // bytes of PKCS#1 overhead equals 94 bytes, which fits in a
        // 128-byte block. The current impl accepts it. Regression
        // guard: ensure no panic and correct tail.
        let data = b"rsa1024 sha512";
        let out = prepare_sign_data(PivAlgorithm::Rsa1024, data, signature::RSA_SHA2_512).unwrap();
        assert_eq!(out.len(), 128);
        let hash = Sha512::digest(data);
        assert!(out.ends_with(hash.as_slice()));
    }

    // -------- pkcs1_v15_pad (direct) --------

    #[test]
    fn pkcs1_v15_pad_exact_structure_sha256() {
        // Pad a SHA-256 hash (32 bytes) into a 256-byte RSA-2048 block.
        let hash = vec![0xAB; 32];
        let padded = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, 256).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(padded[0..2], [0x00, 0x01]);

        // Expect 0xFF padding of length: 256 - 3 - 19 - 32 = 202 bytes
        let pad_len = 256 - 3 - RSA_DIGEST_PREFIX_SHA256.len() - 32;
        assert_eq!(pad_len, 202);
        for i in 2..2 + pad_len {
            assert_eq!(padded[i], 0xFF, "byte {i} should be 0xFF");
        }
        // Separator
        assert_eq!(padded[2 + pad_len], 0x00);
        // DigestInfo + hash at tail
        assert_eq!(
            &padded[3 + pad_len..3 + pad_len + RSA_DIGEST_PREFIX_SHA256.len()],
            RSA_DIGEST_PREFIX_SHA256
        );
        assert_eq!(&padded[padded.len() - 32..], hash.as_slice());
    }

    #[test]
    fn pkcs1_v15_pad_rejects_undersized_key() {
        // Key too small: need at least digest_info_len + 11. A
        // 40-byte key cannot fit 32 byte hash + 19 byte prefix + 11.
        let hash = vec![0; 32];
        let err = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, 40).unwrap_err();
        assert!(
            format!("{err}").contains("key too small for digest"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pkcs1_v15_pad_minimum_viable_size() {
        // Exactly at the minimum: digest_info_len + 11
        let hash = vec![0xCC; 32];
        let key_size = RSA_DIGEST_PREFIX_SHA256.len() + hash.len() + 11; // 62
        let out = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, key_size).unwrap();
        assert_eq!(out.len(), key_size);
        assert_eq!(out[0..2], [0x00, 0x01]);
        // Padding length is exactly 8 bytes (the minimum allowed)
        for i in 2..10 {
            assert_eq!(out[i], 0xFF);
        }
        assert_eq!(out[10], 0x00);
    }

    /// Boundary: one byte below the minimum viable size MUST be rejected.
    /// Pins the exact cutoff at `digest_info_len + 11` — an off-by-one
    /// in the production check at line 227 (`<` vs `<=`) would accept
    /// this input and corrupt the padding layout.
    #[test]
    fn pkcs1_v15_pad_rejects_one_byte_below_minimum() {
        let hash = vec![0xCC; 32];
        let key_size = RSA_DIGEST_PREFIX_SHA256.len() + hash.len() + 10; // 61, one below
        let err = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, key_size).unwrap_err();
        assert!(
            format!("{err}").contains("key too small for digest"),
            "unexpected error: {err}"
        );
    }

    /// Independent structural parser for a PKCS#1 v1.5 signature block.
    /// Walks the bytes end-to-end without using any of the constants or
    /// helpers from the production module, so any circular-reference
    /// concern (the self-referential-structure critique) is eliminated.
    ///
    /// Returns the embedded hash on success, panics on any layout
    /// violation — tests assert both that the layout is valid and the
    /// hash at the tail matches the input.
    fn parse_pkcs1_v15_padded(block: &[u8], expected_digest_info_prefix_len: usize) -> Vec<u8> {
        assert!(block.len() >= 12, "block too short: {}", block.len());
        assert_eq!(block[0], 0x00, "leading byte must be 0x00");
        assert_eq!(block[1], 0x01, "block type must be 0x01 for signature");
        let mut i = 2;
        while i < block.len() && block[i] == 0xFF {
            i += 1;
        }
        assert!(
            i >= 2 + 8,
            "padding must be at least 8 bytes (got {})",
            i - 2
        );
        assert!(i < block.len(), "no separator byte found");
        assert_eq!(block[i], 0x00, "separator byte must be 0x00");
        let digest_info_start = i + 1;
        let hash_start = digest_info_start + expected_digest_info_prefix_len;
        assert!(hash_start <= block.len(), "DigestInfo prefix exceeds block");
        block[hash_start..].to_vec()
    }

    /// Independent round-trip: pad a SHA-256 hash, then parse the block
    /// with a structure walker that does NOT share code with
    /// pkcs1_v15_pad. Confirms the emitted bytes form a well-formed
    /// PKCS#1 v1.5 signature block and that the trailing hash matches
    /// what we put in — circular assertions avoided.
    #[test]
    fn pkcs1_v15_pad_roundtrips_through_independent_parser() {
        let hash = Sha256::digest(b"hello world").to_vec();
        let padded = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, 256).unwrap();
        let extracted_hash = parse_pkcs1_v15_padded(&padded, RSA_DIGEST_PREFIX_SHA256.len());
        assert_eq!(extracted_hash, hash);
    }

    /// Same for SHA-512 so the DigestInfo prefix length variation is
    /// exercised.
    #[test]
    fn pkcs1_v15_pad_roundtrips_through_independent_parser_sha512() {
        let hash = Sha512::digest(b"hello world").to_vec();
        let padded = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA512, 256).unwrap();
        let extracted_hash = parse_pkcs1_v15_padded(&padded, RSA_DIGEST_PREFIX_SHA512.len());
        assert_eq!(extracted_hash, hash);
    }

    // -------- decode_der_ecdsa_signature --------

    /// Build a DER-encoded ECDSA signature from r, s byte slices.
    /// Assumes r.len() + s.len() + 4 < 128 so single-byte lengths work.
    fn make_der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x30); // SEQUENCE
        v.push((r.len() + s.len() + 4) as u8);
        v.push(0x02); // INTEGER
        v.push(r.len() as u8);
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v
    }

    #[test]
    fn decode_der_ecdsa_signature_minimal_valid() {
        let r = vec![0x11; 32];
        let s = vec![0x22; 32];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    #[test]
    fn decode_der_ecdsa_signature_with_integer_leading_zero_padding() {
        // DER INTEGER encoding prepends 0x00 if the high bit of the
        // first byte is set (to distinguish from negative). Those
        // bytes are part of the decoded integer — the decoder should
        // preserve them verbatim so the caller can re-encode as SSH
        // mpint (which also prefers the same convention).
        let r = vec![0x00, 0x80, 0x12, 0x34];
        let s = vec![0x00, 0xFF, 0xCC];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    #[test]
    fn decode_der_ecdsa_signature_short_integers() {
        // Small r/s — well within range of the algorithm but under
        // the curve's expected byte count. The decoder must accept
        // whatever length the INTEGER TLV reports.
        let r = vec![0x01];
        let s = vec![0x02, 0x03];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_non_sequence() {
        // First byte should be 0x30 (SEQUENCE)
        let bad = vec![0x31, 0x04, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("not a SEQUENCE"));
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_too_short() {
        // Each length hits a different bounds check; assert the error
        // message matches the expected one so a change in the control
        // flow stands out.
        let cases: &[(usize, &str)] = &[
            (0, "not a SEQUENCE"),
            (1, "missing length byte"),
            // len 2-5: SEQUENCE claims length >= the byte value of
            // der[1] (48, since vec![0x30; len]) and the buffer
            // undershoots — truncated body.
            (2, "truncated body"),
            (3, "truncated body"),
            (4, "truncated body"),
            (5, "truncated body"),
        ];
        for &(len, expected_fragment) in cases {
            let bad = vec![0x30; len];
            let err = decode_der_ecdsa_signature(&bad).unwrap_err();
            assert!(
                format!("{err}").contains(expected_fragment),
                "len={len}: expected {expected_fragment:?}, got: {err}"
            );
        }
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_missing_r_integer_tag() {
        // 0x30 seq_len  <not 0x02>  ...
        let bad = vec![0x30, 0x06, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("expected INTEGER tag for r"));
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_missing_s_integer_tag() {
        // 0x30 seq  0x02 r_len r 0x03 s_len s
        let bad = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x03, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("expected INTEGER tag for s"));
    }

    /// Regression (specific bounds check): an INTEGER length that claims
    /// more payload than fits inside the advertised SEQUENCE must error,
    /// NOT panic with index-out-of-bounds. Use a short-form length (0x64
    /// = 100) so we exercise the `int_end > end` bounds check directly
    /// rather than the "unsupported form" filter.
    #[test]
    fn decode_der_ecdsa_signature_rejects_r_len_exceeding_sequence() {
        // 0x30 seq=0x06  0x02 r_len=0x64 (100 — lies)  0x00  0x02 0x01 0x00
        let bad = vec![0x30, 0x06, 0x02, 0x64, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("r INTEGER length exceeds SEQUENCE"));
    }

    /// Regression (specific bounds check): same as the r case but for s.
    #[test]
    fn decode_der_ecdsa_signature_rejects_s_len_exceeding_sequence() {
        // 0x30 seq=0x06  0x02 0x01 0x00  0x02 s_len=0x64 (lies)  0x00
        let bad = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x64, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("s INTEGER length exceeds SEQUENCE"));
    }

    /// Regression (fuzz-style panic-safety): a set of adversarial inputs
    /// that pre-fix code would have panicked on (index-out-of-bounds when
    /// the length byte claims more content than the buffer holds). Any
    /// panic here is a DoS — we only assert that the function returns
    /// without panicking.
    #[test]
    fn decode_der_ecdsa_signature_never_panics_on_malformed_input() {
        let fuzz_inputs: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0xFF],
            &[0x30, 0x06, 0x02, 0xFF, 0x00, 0x02, 0x01, 0x00],
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0xFF, 0x00],
            &[0x30, 0x81, 0xFF, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            &[0x30, 0x82, 0xFF, 0xFF, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            &[0x30, 0x80],                         // indefinite form (unsupported)
            &[0x30, 0x04, 0x02, 0x02, 0x00, 0x01], // s missing entirely
        ];
        for (i, input) in fuzz_inputs.iter().enumerate() {
            // If this panics, the test fails with a clear backtrace.
            let result = decode_der_ecdsa_signature(input);
            assert!(
                result.is_err(),
                "fuzz input #{i} unexpectedly succeeded: {input:?}"
            );
        }
    }

    /// Regression: a SEQUENCE that claims a length larger than the buffer
    /// must be caught up front.
    #[test]
    fn decode_der_ecdsa_signature_rejects_truncated_sequence_body() {
        // 0x30 seq=0x20  then only 4 payload bytes
        let bad = vec![0x30, 0x20, 0x02, 0x01, 0x00, 0x02];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("truncated"));
    }

    /// Build a DER signature using long-form SEQUENCE length (0x81 LL).
    /// Real P-384 signatures hit this when SEQUENCE payload ≥ 128 bytes
    /// (two 48-byte integers + overhead easily exceeds 127).
    fn make_der_sig_long_form(r: &[u8], s: &[u8]) -> Vec<u8> {
        let body_len = 4 + r.len() + s.len(); // two INTEGERs with 1-byte length headers each
        assert!(
            body_len >= 128,
            "long-form test requires body >= 128, got {body_len}"
        );
        let mut v = Vec::new();
        v.push(0x30); // SEQUENCE
        v.push(0x81); // long-form length: next byte is the length
        v.push(body_len as u8);
        v.push(0x02); // INTEGER
        v.push(r.len() as u8);
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v
    }

    /// P-384-shaped signature with SEQUENCE length ≥ 128 must decode
    /// correctly. The previous `pos = 2` implementation would silently
    /// mis-parse long-form DER. DER short-form lengths cap at 127; the
    /// smallest long-form encoding is 0x81 0x80. Pick r+s so body length
    /// = 4 + 63 + 63 = 130, comfortably above the threshold.
    #[test]
    fn decode_der_ecdsa_signature_handles_long_form_sequence_length() {
        let r: Vec<u8> = std::iter::repeat(0x11).take(63).collect();
        let s: Vec<u8> = std::iter::repeat(0x22).take(63).collect();
        let der = make_der_sig_long_form(&r, &s);
        // sanity: long-form marker actually in use
        assert_eq!(der[1], 0x81);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    /// Non-canonical DER is rejected: 0x81 with a length < 128 is not a
    /// valid long-form encoding (should have been short form). Reject to
    /// avoid ambiguity.
    #[test]
    fn decode_der_ecdsa_signature_rejects_non_canonical_long_form() {
        // 0x30 0x81 0x06 {valid body} — 0x81 should never be used for len < 128.
        let bad = vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("non-canonical"));
    }

    /// Trailing bytes inside the SEQUENCE (beyond s) must be rejected so
    /// we don't silently accept malformed or extended signatures.
    #[test]
    fn decode_der_ecdsa_signature_rejects_trailing_bytes_in_sequence() {
        // SEQUENCE body = 0x02 0x01 0x00 0x02 0x01 0x00 0xDE  (7 bytes).
        // r and s parse fine, but 0xDE sits inside the SEQUENCE past s.
        let inner: Vec<u8> = vec![0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0xDE];
        let mut der = Vec::with_capacity(2 + inner.len());
        der.push(0x30);
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);
        let err = decode_der_ecdsa_signature(&der).unwrap_err();
        assert!(format!("{err}").contains("trailing bytes"));
    }

    // -------- encode_ecdsa_ssh_signature --------

    #[test]
    fn encode_ecdsa_ssh_signature_format() {
        // SSH ECDSA sig blob = uint32(r_len) || r || uint32(s_len) || s
        let r = vec![0x01, 0x02, 0x03];
        let s = vec![0xAA, 0xBB];
        let blob = encode_ecdsa_ssh_signature(&r, &s);
        // 4 (r_len) + 3 (r) + 4 (s_len) + 2 (s) = 13
        assert_eq!(blob.len(), 13);
        assert_eq!(&blob[0..4], &3u32.to_be_bytes());
        assert_eq!(&blob[4..7], r.as_slice());
        assert_eq!(&blob[7..11], &2u32.to_be_bytes());
        assert_eq!(&blob[11..13], s.as_slice());
    }

    #[test]
    fn encode_ecdsa_ssh_signature_roundtrip_from_der() {
        let r = vec![0x00, 0xAB, 0xCD, 0xEF];
        let s = vec![0x12, 0x34, 0x56];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        let blob = encode_ecdsa_ssh_signature(&dr, &ds);
        assert_eq!(&blob[0..4], &(r.len() as u32).to_be_bytes());
        assert_eq!(&blob[4..4 + r.len()], r.as_slice());
        let s_off = 4 + r.len();
        assert_eq!(&blob[s_off..s_off + 4], &(s.len() as u32).to_be_bytes());
        assert_eq!(&blob[s_off + 4..], s.as_slice());
    }

    // -------- to_ssh_signature --------

    #[test]
    fn to_ssh_signature_ecp256_decodes_der() {
        // DER INTEGERs with their high bit set carry a leading 0x00 byte
        // (to disambiguate from negative two's-complement). SSH mpint
        // encoding uses the same convention, so the raw DER integer
        // bytes are also a valid SSH mpint body. Build r/s with a
        // leading zero so `Signature::new` validation accepts the
        // resulting blob.
        let mut r = vec![0x00];
        r.extend(std::iter::repeat(0xAB).take(32));
        let mut s = vec![0x00];
        s.extend(std::iter::repeat(0xCD).take(32));
        let der = make_der_sig(&r, &s);
        let sig = to_ssh_signature(PivAlgorithm::EcP256, &der, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp256");
        // Signature body is the SSH ECDSA encoding of (r, s)
        let expected = encode_ecdsa_ssh_signature(&r, &s);
        assert_eq!(sig.as_bytes(), expected.as_slice());
    }

    #[test]
    fn to_ssh_signature_ecp256_decodes_der_low_high_bit() {
        // When the high bit is clear, DER omits the leading zero.
        let r = vec![0x11; 32]; // high bit 0
        let s = vec![0x22; 32]; // high bit 0
        let der = make_der_sig(&r, &s);
        let sig = to_ssh_signature(PivAlgorithm::EcP256, &der, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp256");
        let expected = encode_ecdsa_ssh_signature(&r, &s);
        assert_eq!(sig.as_bytes(), expected.as_slice());
    }

    #[test]
    fn to_ssh_signature_ecp384_decodes_der() {
        // Low high bit -> no leading zero in DER.
        let r = vec![0x11; 48];
        let s = vec![0x22; 48];
        let der = make_der_sig(&r, &s);
        let sig = to_ssh_signature(PivAlgorithm::EcP384, &der, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp384");
        let expected = encode_ecdsa_ssh_signature(&r, &s);
        assert_eq!(sig.as_bytes(), expected.as_slice());
    }

    #[test]
    fn to_ssh_signature_ecdsa_rejects_bad_der() {
        // 0xFF...: not a SEQUENCE. Check the exact error so a refactor
        // that returns a different error (e.g. a post-decode panic path)
        // still fails the test.
        let bad_der = vec![0xFF; 8];
        let err = to_ssh_signature(PivAlgorithm::EcP256, &bad_der, 0).unwrap_err();
        assert!(format!("{err}").contains("not a SEQUENCE"));
    }

    /// Extra coverage: DER that passes the SEQUENCE tag check but has a
    /// malformed inner INTEGER. Pre-fix code could panic here; confirms
    /// the error propagates cleanly through to_ssh_signature.
    #[test]
    fn to_ssh_signature_ecdsa_rejects_malformed_inner_der() {
        let bad_der = vec![0x30, 0x06, 0x02, 0x64, 0x00, 0x02, 0x01, 0x00];
        let err = to_ssh_signature(PivAlgorithm::EcP256, &bad_der, 0).unwrap_err();
        assert!(format!("{err}").contains("r INTEGER length exceeds SEQUENCE"));
    }

    #[test]
    fn to_ssh_signature_ed25519_passthrough() {
        let raw = vec![0x33; 64];
        let sig = to_ssh_signature(PivAlgorithm::Ed25519, &raw, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn to_ssh_signature_rsa2048_default_labels_sha256() {
        let raw = vec![0xBB; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn to_ssh_signature_rsa2048_sha512_flag_labels_sha512() {
        let raw = vec![0xAB; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, signature::RSA_SHA2_512).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-512");
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn to_ssh_signature_rsa2048_sha256_flag_labels_sha256() {
        let raw = vec![0x01; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, signature::RSA_SHA2_256).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    #[test]
    fn to_ssh_signature_rsa1024_sha256_default() {
        let raw = vec![0x01; 128];
        let sig = to_ssh_signature(PivAlgorithm::Rsa1024, &raw, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    /// Mirror of `prepare_sign_data_rsa2048_sha512_wins_when_both_flags_set`
    /// for the to_ssh_signature label path: when both flags are set, the
    /// produced SSH algorithm label is rsa-sha2-512.
    #[test]
    fn to_ssh_signature_rsa2048_sha512_wins_when_both_flags_set() {
        let raw = vec![0xAB; 256];
        let sig = to_ssh_signature(
            PivAlgorithm::Rsa2048,
            &raw,
            signature::RSA_SHA2_256 | signature::RSA_SHA2_512,
        )
        .unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-512");
    }

    /// Mirror of `prepare_sign_data_rsa2048_unknown_flags_default_to_sha256`:
    /// unknown flag bits label the signature as rsa-sha2-256.
    #[test]
    fn to_ssh_signature_rsa2048_unknown_flags_default_to_sha256() {
        let raw = vec![0xAB; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, 1 << 31).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    // -------- Session impl: request_identities --------

    #[tokio::test]
    async fn request_identities_empty() {
        let mut agent = PiggyAgent::new(Vec::new());
        let ids = agent.request_identities().await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn request_identities_returns_all_cached_keys() {
        let keys = vec![
            cached_ed25519(0x11, 0x9A),
            cached_ed25519(0x22, 0x9C),
            cached_ed25519(0x33, 0x9D),
        ];
        let comments: Vec<String> = keys.iter().map(|k| k.comment.clone()).collect();
        let pubs: Vec<KeyData> = keys.iter().map(|k| k.public_key.clone()).collect();

        let mut agent = PiggyAgent::new(keys);
        let ids = agent.request_identities().await.unwrap();
        assert_eq!(ids.len(), 3);
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(id.comment, comments[i]);
            assert_eq!(id.pubkey, pubs[i]);
        }
    }

    #[tokio::test]
    async fn request_identities_idempotent() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x42, 0x9E)]);
        let first = agent.request_identities().await.unwrap();
        let second = agent.request_identities().await.unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0].pubkey, second[0].pubkey);
    }

    // -------- Session impl: upstream proxying (piggy#215) --------

    use crate::cmd::agent::upstream::{Upstream, UpstreamPool, test_support as upstream_stub};

    fn pool_for(path: std::path::PathBuf) -> UpstreamPool {
        UpstreamPool::new(
            vec![Upstream {
                name: "stub".into(),
                path,
            }],
            std::time::Duration::from_secs(5),
        )
    }

    #[tokio::test]
    async fn request_identities_offers_upstream_keys_after_native() {
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x77, "soft-key",
        )]);
        let path = upstream_stub::spawn_stub("sess-merge", stub);
        let mut agent =
            PiggyAgent::new(vec![cached_ed25519(0x11, 0x9A)]).with_upstream_pool(pool_for(path));

        let ids = agent.request_identities().await.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].pubkey, ed25519_key_data(0x11), "native key first");
        assert_eq!(ids[1].comment, "soft-key");
    }

    #[tokio::test]
    async fn request_identities_dedupes_key_served_both_natively_and_upstream() {
        // The upstream serves the SAME pubkey piggy serves natively (seed
        // 0x11); it must be offered exactly once, as the native entry.
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x11, "shadowed",
        )]);
        let path = upstream_stub::spawn_stub("sess-dedupe", stub);
        let native = cached_ed25519(0x11, 0x9A);
        let native_comment = native.comment.clone();
        let mut agent = PiggyAgent::new(vec![native]).with_upstream_pool(pool_for(path));

        let ids = agent.request_identities().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, native_comment, "native entry wins");
    }

    #[tokio::test]
    async fn sign_routes_non_native_key_to_upstream() {
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x77, "soft-key",
        )]);
        let path = upstream_stub::spawn_stub("sess-sign", stub);
        let mut agent =
            PiggyAgent::new(vec![cached_ed25519(0x11, 0x9A)]).with_upstream_pool(pool_for(path));

        let sig = agent
            .sign(SignRequest {
                pubkey: ed25519_key_data(0x77),
                data: b"payload".to_vec(),
                flags: 0,
            })
            .await
            .unwrap();
        assert_eq!(
            sig,
            upstream_stub::canned_signature(),
            "signature must come from the stub upstream, not the native path"
        );
    }

    #[tokio::test]
    async fn sign_key_held_nowhere_errors_even_with_upstreams() {
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x77, "soft-key",
        )]);
        let path = upstream_stub::spawn_stub("sess-nowhere", stub);
        let mut agent =
            PiggyAgent::new(vec![cached_ed25519(0x11, 0x9A)]).with_upstream_pool(pool_for(path));

        let err = agent
            .sign(SignRequest {
                pubkey: ed25519_key_data(0xEE),
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

    // -------- Session impl: extension/lock/add proxying (#215 step 2) --------

    fn ext_request(name: &str) -> Extension {
        Extension {
            name: name.into(),
            details: Vec::new().into(),
        }
    }

    /// Decode piggy's flat query response (u32-length-prefixed names).
    fn decode_flat_query_names(details: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut pos = 0usize;
        while pos + 4 <= details.len() {
            let len = u32::from_be_bytes(details[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            names.push(String::from_utf8(details[pos..pos + len].to_vec()).unwrap());
            pos += len;
        }
        names
    }

    #[tokio::test]
    async fn query_unions_upstream_names_after_native() {
        let stub = upstream_stub::StubUpstream::new(vec![])
            .with_extensions(&["special@example", "ecdh@joyent.com"]);
        let path = upstream_stub::spawn_stub("sess-query", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        let resp = agent
            .extension(ext_request("query"))
            .await
            .unwrap()
            .expect("query response");
        let names = decode_flat_query_names(&resp.details.clone().into_bytes());
        assert_eq!(names[0], "query", "native names stay first");
        assert!(names.iter().any(|n| n == "special@example"), "{names:?}");
        // Advertised both natively and upstream: exactly once.
        assert_eq!(
            names.iter().filter(|n| *n == "ecdh@joyent.com").count(),
            1,
            "{names:?}"
        );
    }

    #[tokio::test]
    async fn unknown_extension_forwarded_to_upstream() {
        let stub = upstream_stub::StubUpstream::new(vec![]).with_extensions(&["special@example"]);
        let path = upstream_stub::spawn_stub("sess-fwd", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        let resp = agent
            .extension(ext_request("special@example"))
            .await
            .unwrap()
            .expect("forwarded response");
        assert_eq!(resp.name.as_str(), "special@example");
        assert_eq!(resp.details.clone().into_bytes(), b"stub-echo".to_vec());
    }

    #[tokio::test]
    async fn session_bind_accepts_natively_and_fans_out() {
        let stub = upstream_stub::StubUpstream::new(vec![]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub("sess-bind", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        let resp = agent
            .extension(ext_request("session-bind@openssh.com"))
            .await
            .unwrap();
        assert!(resp.is_none(), "native accept unchanged");
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e == "ext:session-bind@openssh.com"),
            "binding never reached the upstream"
        );
    }

    #[tokio::test]
    async fn lock_unlock_manage_pin_and_fan_out() {
        let stub = upstream_stub::StubUpstream::new(vec![]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub("sess-lock", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        agent.unlock("123456".to_string()).await.unwrap();
        assert!(agent.pin_handle().lock().await.has_any(), "PIN cached");
        agent.lock(String::new()).await.unwrap();
        assert!(!agent.pin_handle().lock().await.has_any(), "PIN dropped");

        let events = events.lock().unwrap();
        assert!(events.iter().any(|e| e == "unlock:123456"), "{events:?}");
        assert!(events.iter().any(|e| e == "lock:"), "{events:?}");
    }

    #[tokio::test]
    async fn add_identity_routes_to_designated_upstream() {
        let stub = upstream_stub::StubUpstream::new(vec![]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub("sess-add", stub);
        let pool = UpstreamPool::new(
            vec![Upstream {
                name: "soft".into(),
                path,
            }],
            std::time::Duration::from_secs(5),
        )
        .with_add_new_keys_to("soft")
        .unwrap();
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool);

        agent
            .add_identity(upstream_stub::test_add_identity())
            .await
            .unwrap();
        assert!(
            events.lock().unwrap().iter().any(|e| e == "add_identity"),
            "designated upstream never received the add"
        );
    }

    #[tokio::test]
    async fn upstream_status_extension_advertised_and_answers() {
        let stub =
            upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(0x21, "k1")]);
        let path = upstream_stub::spawn_stub("sess-status", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        // Advertised in query only because upstreams are configured...
        let resp = agent
            .extension(ext_request("query"))
            .await
            .unwrap()
            .expect("query response");
        let names = decode_flat_query_names(&resp.details.clone().into_bytes());
        assert!(
            names.iter().any(|n| n == "upstream-status@piggy"),
            "{names:?}"
        );

        // ...and answered with a JSON payload naming the upstream.
        let resp = agent
            .extension(ext_request("upstream-status@piggy"))
            .await
            .unwrap()
            .expect("status payload");
        let statuses: Vec<crate::cmd::agent::upstream::UpstreamStatus> =
            serde_json::from_slice(&resp.details.clone().into_bytes()).unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].name, "stub");
        assert!(statuses[0].reachable);
        assert_eq!(statuses[0].keys, 1);
    }

    /// eng#295: every agent advertises and answers `agent-mode@piggy`;
    /// the payload reflects `--proxy-only`, the live native key count,
    /// and the upstream count.
    #[tokio::test]
    async fn agent_mode_extension_reports_role() {
        use crate::cmd::agent::mode::{AGENT_MODE_EXT, AgentMode};

        // Card-backed, event-driven, no upstreams, no --service-name:
        // advertised, proxy_only=false, event_driven=true, service=None.
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9A)]).with_event_driven(true);
        let resp = agent
            .extension(ext_request("query"))
            .await
            .unwrap()
            .expect("query response");
        let names = decode_flat_query_names(&resp.details.clone().into_bytes());
        assert!(names.iter().any(|n| n == AGENT_MODE_EXT), "{names:?}");
        let resp = agent
            .extension(ext_request(AGENT_MODE_EXT))
            .await
            .unwrap()
            .expect("mode payload");
        let mode: AgentMode = serde_json::from_slice(&resp.details.clone().into_bytes()).unwrap();
        assert_eq!(
            mode,
            AgentMode {
                proxy_only: false,
                native_keys: 1,
                upstreams: 0,
                service: None,
                event_driven: true,
            }
        );

        // Proxy-only with one upstream and a --service-name (piggy#162).
        let path = upstream_stub::spawn_stub("sess-mode", upstream_stub::StubUpstream::new(vec![]));
        let mut agent = PiggyAgent::new(Vec::new())
            .with_upstream_pool(pool_for(path))
            .with_proxy_only(true)
            .with_service_name(Some("piggy-agent-proxy.service".into()));
        let resp = agent
            .extension(ext_request(AGENT_MODE_EXT))
            .await
            .unwrap()
            .expect("mode payload");
        let mode: AgentMode = serde_json::from_slice(&resp.details.clone().into_bytes()).unwrap();
        assert_eq!(
            mode,
            AgentMode {
                proxy_only: true,
                native_keys: 0,
                upstreams: 1,
                service: Some("piggy-agent-proxy.service".into()),
                event_driven: false,
            }
        );
    }

    #[tokio::test]
    async fn upstream_status_extension_refused_without_upstreams() {
        // Without upstreams the name is neither advertised nor served —
        // same refusal as any unknown extension.
        let mut agent = PiggyAgent::new(Vec::new());
        agent
            .extension(ext_request("upstream-status@piggy"))
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn add_identity_without_target_refuses() {
        // Upstreams configured but no --add-new-keys-to: refuse.
        let stub = upstream_stub::StubUpstream::new(vec![]);
        let path = upstream_stub::spawn_stub("sess-add-no", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        let err = agent
            .add_identity(upstream_stub::test_add_identity())
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("no --add-new-keys-to"),
            "unexpected error: {err}"
        );
    }

    // -------- Session impl: native card extensions, native-miss fallthrough --------
    //
    // The proxy-only role (eng#295): an agent with NO native keys fronting
    // a card-backed upstream must forward ecdh / ecdh-rebox / attest for
    // keys it doesn't serve, and still refuse them without upstreams.
    // None of these touch PCSC: the native miss short-circuits before any
    // card access, so they run in environments without PCSC.

    fn ssh_string(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// A well-formed `ecdh@joyent.com` request whose card key (seed 0x77,
    /// Ed25519 — parseable, but not a key this agent serves) is a native
    /// miss. The partner blob is never reached on the miss path.
    fn ecdh_request_for_foreign_key() -> Extension {
        let card_key: PublicKey = ed25519_key_data(0x77).into();
        let mut inner = ssh_string(&card_key.to_bytes().unwrap());
        inner.extend(ssh_string(b"partner"));
        inner.extend(0u32.to_be_bytes());
        Extension {
            name: "ecdh@joyent.com".into(),
            details: ssh_string(&inner).into(),
        }
    }

    fn attest_request_for_foreign_key() -> Extension {
        let card_key: PublicKey = ed25519_key_data(0x77).into();
        let mut inner = ssh_string(&card_key.to_bytes().unwrap());
        inner.extend(0u32.to_be_bytes());
        Extension {
            name: "ykpiv-attest@joyent.com".into(),
            details: ssh_string(&inner).into(),
        }
    }

    /// A well-formed guidless `ecdh-rebox@joyent.com` request for a box
    /// sealed to a throwaway P-256 recipient no agent key matches.
    fn rebox_request_for_foreign_recipient() -> Extension {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let recipient = EcKey::generate(&group).unwrap();
        let recipient_pub = EcKey::from_public_key(&group, recipient.public_key()).unwrap();
        let mut piv_box = PivBox::new(EcCurve::NistP256);
        piv_box.set_data(b"secret");
        piv_box.seal_offline(&recipient_pub).unwrap();

        let mut inner = ssh_string(&piv_box.to_bytes().unwrap());
        inner.extend(ssh_string(b"")); // no target GUID
        inner.push(0x9D); // slot_id
        inner.extend(ssh_string(b"partner"));
        inner.extend(0u32.to_be_bytes());
        Extension {
            name: "ecdh-rebox@joyent.com".into(),
            details: ssh_string(&inner).into(),
        }
    }

    async fn assert_forwarded(tag: &str, request: Extension) {
        let name = request.name.clone();
        let stub = upstream_stub::StubUpstream::new(vec![]).with_extensions(&[name.as_str()]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub(tag, stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        let resp = agent
            .extension(request)
            .await
            .unwrap()
            .expect("forwarded response");
        assert_eq!(resp.name, name);
        assert_eq!(resp.details.clone().into_bytes(), b"stub-echo");
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| *e == format!("ext:{name}")),
            "upstream never saw the forwarded {name}"
        );
    }

    #[tokio::test]
    async fn ecdh_native_miss_forwards_to_upstream() {
        assert_forwarded("ecdh-fwd", ecdh_request_for_foreign_key()).await;
    }

    #[tokio::test]
    async fn attest_native_miss_forwards_to_upstream() {
        assert_forwarded("attest-fwd", attest_request_for_foreign_key()).await;
    }

    #[tokio::test]
    async fn ecdh_rebox_native_miss_forwards_to_upstream() {
        assert_forwarded("rebox-fwd", rebox_request_for_foreign_recipient()).await;
    }

    #[tokio::test]
    async fn ecdh_native_miss_without_upstreams_refuses() {
        let mut agent = PiggyAgent::new(Vec::new());
        let err = agent
            .extension(ecdh_request_for_foreign_key())
            .await
            .unwrap_err();
        assert_agent_error_other_eq(&err, "ecdh: key not found");
    }

    #[tokio::test]
    async fn ecdh_rebox_native_miss_without_upstreams_refuses() {
        let mut agent = PiggyAgent::new(Vec::new());
        let err = agent
            .extension(rebox_request_for_foreign_recipient())
            .await
            .unwrap_err();
        assert_agent_error_other_eq(&err, "ecdh-rebox: no agent key matches the box recipient");
    }

    #[tokio::test]
    async fn ecdh_malformed_request_is_not_forwarded() {
        // A genuine error in a request the agent owns (truncated payload)
        // must surface as that error, never be retried against an upstream.
        let stub = upstream_stub::StubUpstream::new(vec![]).with_extensions(&["ecdh@joyent.com"]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub("ecdh-malformed", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));

        agent
            .extension(Extension {
                name: "ecdh@joyent.com".into(),
                details: vec![0x00, 0x00].into(),
            })
            .await
            .unwrap_err();
        assert!(
            !events
                .lock()
                .unwrap()
                .iter()
                .any(|e| e == "ext:ecdh@joyent.com"),
            "malformed ecdh request was forwarded upstream"
        );
    }

    // -------- operator-act@piggy (RFC 0012; pre-PCSC branches) --------
    //
    // Everything here is decided before the card is opened or a prompt is
    // raised, so it runs without PCSC. The card half (attestation, prompt,
    // sign) is the fibby lanes' to cover.

    use crate::operator_act as act;

    fn operator_act_request(key: KeyData, namespace: &str, hash: &str, text: &[u8]) -> Extension {
        let key: PublicKey = key.into();
        Extension {
            name: act::EXTENSION.into(),
            details: act::Request {
                key: key.to_bytes().unwrap(),
                namespace: namespace.into(),
                hash_algorithm: hash.into(),
                text: text.to_vec(),
            }
            .encode()
            .into(),
        }
    }

    async fn operator_act_status(agent: &mut PiggyAgent, request: Extension) -> act::Status {
        let answer = agent
            .extension(request)
            .await
            .expect("a refusal is a SUCCESS response, not an agent failure")
            .expect("an operator-act response");
        assert_eq!(answer.name, act::EXTENSION);
        let response = act::Response::decode(&answer.details.into_bytes()).expect("well-formed");
        assert!(response.sshsig.is_empty(), "a refusal carries no signature");
        response.status
    }

    #[test]
    fn operator_act_wrong_pin_and_askpass_failure_read_differently() {
        let (status, detail) = operator_act_pin_refusal(&PivError::PinIncorrect { retries: 2 });
        assert_eq!(status, act::Status::Error);
        assert_eq!(detail, "wrong PIN (2 retries left)");

        let (status, detail) = operator_act_pin_refusal(&PivError::PinBlocked);
        assert_eq!(status, act::Status::Error);
        assert_eq!(detail, "PIN blocked");

        let (status, detail) = operator_act_pin_refusal(&PivError::Apdu { sw: 0x6A80 });
        assert_eq!(status, act::Status::Error);
        assert!(detail.starts_with("PIN verify failed: "), "{detail}");

        let (status, detail) = operator_act_prompt_refusal(&"askpass exited with exit status: 1");
        assert_eq!(status, act::Status::Cancelled);
        assert_eq!(
            detail,
            "no PIN from the askpass: askpass exited with exit status: 1"
        );
        assert!(!detail.contains("wrong PIN"));
    }

    #[tokio::test]
    async fn operator_act_malformed_request_is_bad_request() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9C)]);
        let truncated = Extension {
            name: act::EXTENSION.into(),
            details: vec![0x00, 0x00].into(),
        };
        assert_eq!(
            operator_act_status(&mut agent, truncated).await,
            act::Status::BadRequest
        );
        let unknown_hash = operator_act_request(
            ed25519_key_data(0x11),
            "piggy-escalation-v1",
            "md5",
            b"grant",
        );
        assert_eq!(
            operator_act_status(&mut agent, unknown_hash).await,
            act::Status::BadRequest
        );
    }

    #[tokio::test]
    async fn operator_act_unserved_key_without_upstreams_is_no_such_key() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9C)]);
        let request = operator_act_request(
            ed25519_key_data(0x77),
            "piggy-escalation-v1",
            "sha512",
            b"grant",
        );
        assert_eq!(
            operator_act_status(&mut agent, request).await,
            act::Status::NoSuchKey
        );
    }

    #[tokio::test]
    async fn operator_act_refuses_unregistered_namespaces_for_a_held_key() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9C)]);
        for namespace in ["git", "file", "email", "piggy-record-v1", "piggy-grant-v9"] {
            let request = operator_act_request(ed25519_key_data(0x11), namespace, "sha512", b"x");
            assert_eq!(
                operator_act_status(&mut agent, request).await,
                act::Status::RefusedNamespace,
                "{namespace}"
            );
        }
    }

    #[tokio::test]
    async fn operator_act_refuses_text_the_prompt_cannot_show() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9C)]);
        let oversize = vec![b'a'; act::MAX_TEXT_BYTES + 1];
        for text in [&b""[..], b"a\x1b[2Jb", b"\xff\xfe", &oversize] {
            let request = operator_act_request(
                ed25519_key_data(0x11),
                "piggy-escalation-v1",
                "sha512",
                text,
            );
            assert_eq!(
                operator_act_status(&mut agent, request).await,
                act::Status::RefusedText
            );
        }
    }

    /// RFC 0012 §2.8: a key this agent does not hold goes to the upstream
    /// that listed it, and the upstream's answer comes back as it was.
    #[tokio::test]
    async fn operator_act_for_an_upstream_key_is_relayed_unjudged() {
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x77, "card-key",
        )])
        .with_extensions(&[act::EXTENSION]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub("operator-act-fwd", stub);
        let mut agent = PiggyAgent::new(Vec::new())
            .with_proxy_only(true)
            .with_upstream_pool(pool_for(path));
        agent.request_identities().await.unwrap();

        // A namespace this agent would refuse for its own key: a proxy does
        // not judge, the agent that holds the card does.
        let request = operator_act_request(ed25519_key_data(0x77), "git", "sha512", b"x");
        let answer = agent.extension(request).await.unwrap().expect("relayed");
        assert_eq!(answer.details.into_bytes(), b"stub-echo");
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| *e == format!("ext:{}", act::EXTENSION)),
            "the upstream never saw the request"
        );
    }

    #[tokio::test]
    async fn operator_act_is_advertised_by_a_card_agent_and_not_by_a_bare_proxy() {
        async fn advertised(agent: &mut PiggyAgent) -> bool {
            let answer = agent
                .extension(Extension {
                    name: "query".into(),
                    details: Vec::new().into(),
                })
                .await
                .unwrap()
                .unwrap();
            let details = answer.details.into_bytes();
            details
                .windows(act::EXTENSION.len())
                .any(|w| w == act::EXTENSION.as_bytes())
        }
        assert!(advertised(&mut PiggyAgent::new(Vec::new())).await);
        assert!(!advertised(&mut PiggyAgent::new(Vec::new()).with_proxy_only(true)).await);
    }

    /// The ordinary sign path must not mint what `operator-act@piggy` exists
    /// to guard: sshsig signed data in an operator-act namespace is refused
    /// before the card or a prompt is reached.
    #[tokio::test]
    async fn sign_refuses_operator_act_signed_data() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9C)]);
        let req = SignRequest {
            pubkey: ed25519_key_data(0x11),
            data: act::signed_data(
                "piggy-escalation-v1",
                act::HashAlgorithm::Sha512,
                b"grant: anything",
            ),
            flags: 0,
        };
        let err = agent.sign(req).await.unwrap_err();
        assert_agent_error_other_eq(&err, "signed only through operator-act@piggy");
    }

    /// The refusal comes before routing: an upstream that predates the rule
    /// never sees the bytes, so it cannot sign them.
    #[tokio::test]
    async fn sign_refuses_operator_act_signed_data_for_an_upstream_key_too() {
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x77, "card-key",
        )]);
        let events = stub.events.clone();
        let path = upstream_stub::spawn_stub("operator-act-sign-guard", stub);
        let mut agent = PiggyAgent::new(Vec::new()).with_upstream_pool(pool_for(path));
        agent.request_identities().await.unwrap();
        let seen_before = events.lock().unwrap().len();

        let req = SignRequest {
            pubkey: ed25519_key_data(0x77),
            data: act::signed_data("piggy-quote-v1", act::HashAlgorithm::Sha256, b"words"),
            flags: 0,
        };
        let err = agent.sign(req).await.unwrap_err();
        assert_agent_error_other_eq(&err, "signed only through operator-act@piggy");
        assert_eq!(
            events.lock().unwrap().len(),
            seen_before,
            "the upstream was asked to sign operator-act data"
        );
    }

    /// A proxy does not judge what it forwards: a request this build would
    /// call `bad-request` still reaches the upstream that holds the key.
    #[tokio::test]
    async fn operator_act_from_a_later_version_is_still_relayed() {
        let stub = upstream_stub::StubUpstream::new(vec![upstream_stub::upstream_identity(
            0x77, "card-key",
        )])
        .with_extensions(&[act::EXTENSION]);
        let path = upstream_stub::spawn_stub("operator-act-fwd-v2", stub);
        let mut agent = PiggyAgent::new(Vec::new())
            .with_proxy_only(true)
            .with_upstream_pool(pool_for(path));
        agent.request_identities().await.unwrap();

        let key: PublicKey = ed25519_key_data(0x77).into();
        let mut contents = 2u32.to_be_bytes().to_vec();
        contents.extend(ssh_string(&key.to_bytes().unwrap()));
        contents.extend_from_slice(b"what version 2 adds");
        let request = Extension {
            name: act::EXTENSION.into(),
            details: ssh_string(&contents).into(),
        };
        let answer = agent.extension(request).await.unwrap().expect("relayed");
        assert_eq!(answer.details.into_bytes(), b"stub-echo");
    }

    // -------- Session impl: sign (pre-PCSC branch) --------

    /// Assert that an `AgentError` is the `::Other` variant AND that its
    /// rendered message equals `expected`. The variant check uses the
    /// `{:?}` Debug representation (which starts with the variant name),
    /// the message check uses `{}` Display. Tighter than a raw
    /// `.contains()` on Display alone — a refactor that moves the error
    /// to a different variant but keeps a similar message would fail
    /// this assertion.
    fn assert_agent_error_other_eq(err: &AgentError, expected: &str) {
        let debug = format!("{err:?}");
        let display = format!("{err}");
        assert!(
            debug.trim_start().starts_with("Other"),
            "expected AgentError::Other variant, got debug={debug}"
        );
        assert!(
            display.contains(expected),
            "error message mismatch: expected to contain {expected:?}, got {display}"
        );
    }

    #[tokio::test]
    async fn sign_unknown_key_errors_before_touching_pcsc() {
        // An empty cache plus any pubkey must short-circuit at
        // find_key returning "key not found" -- importantly, this
        // branch never calls PivContext::new(), so the test runs
        // in environments without PCSC.
        let mut agent = PiggyAgent::new(Vec::new());
        let req = SignRequest {
            pubkey: ed25519_key_data(0x01),
            data: b"whatever".to_vec(),
            flags: 0,
        };
        let err = agent.sign(req).await.unwrap_err();
        assert_agent_error_other_eq(&err, "key not found");
    }

    #[tokio::test]
    async fn sign_mismatched_key_errors_before_touching_pcsc() {
        // Cache has seed 0x11, request asks for seed 0x99 -- must
        // still short-circuit before PCSC.
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9A)]);
        let req = SignRequest {
            pubkey: ed25519_key_data(0x99),
            data: b"whatever".to_vec(),
            flags: 0,
        };
        let err = agent.sign(req).await.unwrap_err();
        assert_agent_error_other_eq(&err, "key not found");
    }

    // -------- describe_sign_refusal (piggy#178) --------

    #[test]
    fn describe_sign_refusal_with_cached_key_reports_slot_and_comment() {
        let key = cached_ed25519(0x11, 0x9A);
        let err = AgentError::Other("card transaction failed".into());
        let refusal = describe_sign_refusal(Some(&key), &key.public_key, &err);
        assert_eq!(refusal.slot, "9A");
        assert_eq!(refusal.comment, "seed-17");
        assert!(
            refusal.cause.contains("card transaction failed"),
            "cause should carry the underlying error, got {:?}",
            refusal.cause
        );
        assert_eq!(
            refusal.fingerprint,
            key.public_key
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        );
    }

    #[test]
    fn describe_sign_refusal_unknown_key_uses_placeholders() {
        // A refusal at find_cached_key (key not served) has no slot/comment.
        let pubkey = ed25519_key_data(0x42);
        let err = AgentError::Other("key not found".into());
        let refusal = describe_sign_refusal(None, &pubkey, &err);
        assert_eq!(refusal.slot, "unknown");
        assert_eq!(refusal.comment, "<none>");
        assert!(refusal.cause.contains("key not found"));
    }

    #[test]
    fn describe_sign_refusal_empty_comment_falls_back() {
        let mut key = cached_ed25519(0x11, 0x9C);
        key.comment = String::new();
        let err = AgentError::Other("x".into());
        let refusal = describe_sign_refusal(Some(&key), &key.public_key, &err);
        assert_eq!(refusal.slot, "9C");
        assert_eq!(refusal.comment, "<none>");
    }

    // -------- Session impl: lock / unlock --------

    // piggy#177: `ssh-add -X` becomes the OFFER — not tied to a card
    // until it verifies on one.
    #[tokio::test]
    async fn unlock_populates_offer() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.unlock("1234".into()).await.unwrap();
        let pins = agent.pin_handle();
        let pins = pins.lock().await;
        assert_eq!(pins.offered().as_deref(), Some("1234"));
        assert!(pins.has_any());
    }

    #[tokio::test]
    async fn lock_clears_everything() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.unlock("abcd".into()).await.unwrap();
        agent
            .pin_handle()
            .lock()
            .await
            .cache_verified(&sample_guid(), "verified");
        agent.lock("ignored-by-impl".into()).await.unwrap();
        assert!(!agent.pin_handle().lock().await.has_any());
    }

    #[tokio::test]
    async fn unlock_overwrites_existing_offer() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.unlock("first".into()).await.unwrap();
        agent.unlock("second".into()).await.unwrap();
        assert_eq!(
            agent.pin_handle().lock().await.offered().as_deref(),
            Some("second")
        );
    }

    #[tokio::test]
    async fn lock_when_empty_is_noop() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.lock("anything".into()).await.unwrap();
        assert!(!agent.pin_handle().lock().await.has_any());
        // Lock again, still empty.
        agent.lock("again".into()).await.unwrap();
        assert!(!agent.pin_handle().lock().await.has_any());
    }

    #[tokio::test]
    async fn lock_unlock_lock_cycle() {
        let mut agent = PiggyAgent::new(Vec::new());
        let handle = agent.pin_handle();

        assert!(!handle.lock().await.has_any());
        agent.unlock("pin1".into()).await.unwrap();
        assert_eq!(handle.lock().await.offered().as_deref(), Some("pin1"));
        agent.lock("x".into()).await.unwrap();
        assert!(!handle.lock().await.has_any());
        agent.unlock("pin2".into()).await.unwrap();
        assert_eq!(handle.lock().await.offered().as_deref(), Some("pin2"));
    }

    #[tokio::test]
    async fn pin_handle_shares_state_with_clone() {
        // `pin_handle()` must hand out an Arc that reflects live
        // state — otherwise the background `probe_loop` could never
        // clear a card's PIN.
        let mut agent = PiggyAgent::new(Vec::new());
        let handle = agent.pin_handle();
        agent.unlock("shared".into()).await.unwrap();
        assert_eq!(handle.lock().await.offered().as_deref(), Some("shared"));

        // Mutate via the handle (as the probe loop does), observe via the
        // agent's own handle.
        handle
            .lock()
            .await
            .cache_verified(&sample_guid(), "via-handle");
        let handle2 = agent.pin_handle();
        assert_eq!(
            handle2.lock().await.verified_for(&sample_guid()).as_deref(),
            Some("via-handle")
        );
    }

    /// piggy#177 at the `ensure_pin` level: the `ssh-add -X` offer is
    /// handed out as FRESH (cache-after-verify), promotes to a per-card
    /// verified PIN on `cache_pin`, and a card that rejects it
    /// (`forget_pin`) stops being offered it — without touching another
    /// card's verified PIN. No askpass fires anywhere in this flow.
    #[tokio::test]
    async fn ensure_pin_offer_promotes_per_card_and_rejection_is_per_card() {
        let agent = PiggyAgent::new(Vec::new());
        let card_a = sample_guid();
        let card_b = Guid::from_hex("00112233445566778899AABBCCDDEEFF").unwrap();

        // ssh-add -X: both cards are offered the PIN, as fresh.
        agent.pin_handle().lock().await.offer("offer-pin");
        let acq_a = agent.ensure_pin("test", &card_a).await.unwrap();
        assert!(acq_a.fresh, "offer must ride the cache-after-verify path");
        assert_eq!(acq_a.pin.as_str(), "offer-pin");

        // Card A verifies it: promoted to A's verified PIN; subsequent
        // lookups are trusted (not fresh).
        agent.cache_pin(&card_a, &acq_a).await;
        let again_a = agent.ensure_pin("test", &card_a).await.unwrap();
        assert!(!again_a.fresh, "verified PIN must not be re-cached");

        // Card B rejects the offer: it is not offered again to B…
        agent.forget_pin(&card_b).await;
        assert!(
            agent.pin_handle().lock().await.lookup(&card_b).is_none(),
            "rejected offer re-offered to the same card"
        );
        // …while A's verified PIN is untouched (the whole point of #177).
        assert_eq!(
            agent
                .pin_handle()
                .lock()
                .await
                .verified_for(&card_a)
                .as_deref(),
            Some("offer-pin")
        );
    }

    // -------- Session impl: extension --------

    #[tokio::test]
    async fn extension_query_lists_supported_names() {
        let mut agent = PiggyAgent::new(Vec::new());
        let resp = agent
            .extension(Extension {
                name: "query".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .expect("query extension must produce a response");
        assert_eq!(resp.name, "query");

        // Body is a sequence of uint32-length-prefixed ASCII names.
        let body: Vec<u8> = resp.details.into_bytes();
        let mut names = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let len = u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
            i += 4;
            names.push(String::from_utf8(body[i..i + len].to_vec()).unwrap());
            i += len;
        }
        assert_eq!(
            i,
            body.len(),
            "body must fully parse with no trailing bytes"
        );
        assert!(names.iter().any(|n| n == "query"));
        assert!(names.iter().any(|n| n == "session-bind@openssh.com"));
        assert!(names.iter().any(|n| n == "pin-status@joyent.com"));
    }

    #[tokio::test]
    async fn extension_session_bind_returns_none() {
        let mut agent = PiggyAgent::new(Vec::new());
        let resp = agent
            .extension(Extension {
                name: "session-bind@openssh.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap();
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn extension_pin_status_empty_agent() {
        let mut agent = PiggyAgent::new(Vec::new());
        let resp = agent
            .extension(Extension {
                name: "pin-status@joyent.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .expect("pin-status must produce a response");
        let body: Vec<u8> = resp.details.into_bytes();
        assert_eq!(body.len(), 2);
        assert_eq!(body[0], 0, "no PIN -> has_pin=0");
        assert_eq!(body[1], 0, "no keys -> has_card=0");
    }

    #[tokio::test]
    async fn extension_pin_status_with_keys_and_pin() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x77, 0x9A)]);
        agent.unlock("cached".into()).await.unwrap();

        let resp = agent
            .extension(Extension {
                name: "pin-status@joyent.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .unwrap();
        let body: Vec<u8> = resp.details.into_bytes();
        assert_eq!(body, vec![1, 1]);
    }

    #[tokio::test]
    async fn extension_pin_status_with_keys_no_pin() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x77, 0x9A)]);
        let resp = agent
            .extension(Extension {
                name: "pin-status@joyent.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .unwrap();
        let body: Vec<u8> = resp.details.into_bytes();
        assert_eq!(body, vec![0, 1]);
    }

    #[tokio::test]
    async fn extension_unknown_returns_error() {
        let mut agent = PiggyAgent::new(Vec::new());
        let err = agent
            .extension(Extension {
                name: "bogus@example.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap_err();
        // Specifically the UnsupportedCommand protocol error, not any
        // random other AgentError variant.
        let debug = format!("{err:?}");
        assert!(
            debug.contains("UnsupportedCommand"),
            "expected UnsupportedCommand, got {debug}"
        );
    }

    /// Matching on extension names is case-sensitive — "Query" must NOT
    /// match the "query" arm. Pins the exact-match semantics so a later
    /// refactor to case-insensitive lookup (which would be a protocol
    /// violation per the SSH agent spec) fails loudly.
    #[tokio::test]
    async fn extension_name_is_case_sensitive() {
        let mut agent = PiggyAgent::new(Vec::new());
        let err = agent
            .extension(Extension {
                name: "Query".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("UnsupportedCommand"));
    }

    // -------- Sanity: RSA DigestInfo prefixes match RFC 8017 --------

    #[test]
    fn rsa_digest_prefix_sha256_matches_rfc_8017() {
        // RFC 8017 § 9.2 (PKCS#1 v2.2) EMSA-PKCS1-v1_5 DigestInfo for SHA-256:
        //   30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        let expected: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        assert_eq!(RSA_DIGEST_PREFIX_SHA256, &expected);
    }

    #[test]
    fn rsa_digest_prefix_sha512_matches_rfc_8017() {
        // RFC 8017 § 9.2 EMSA-PKCS1-v1_5 DigestInfo for SHA-512:
        //   30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
        let expected: [u8; 19] = [
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ];
        assert_eq!(RSA_DIGEST_PREFIX_SHA512, &expected);
    }
}
