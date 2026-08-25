//! Background PIV-card presence lifecycle (piggy#244).
//!
//! A single [`reconcile_loop`] maintains the agent's served key set against
//! the cards physically present: it drops a removed card's keys and forgets
//! its PIN, and adopts a newly-inserted card's keys (sign-path gated). It
//! subsumes the old single-primary PIN-clear probe, the piggy#175 0-key
//! recovery, and the piggy#143 CAK-swap loop.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::time::{Duration, interval};

use pcsc::{Context, ReaderState, Scope, State};

use piggy_piv::Guid;

use super::pins::PinCache;
use super::session::CachedKey;

/// Default cadence for the per-card presence reconcile loop (piggy#244).
/// Shorter than the historical 60s single-card probe so a removed card's keys
/// and PIN clear within a few ticks; tunable via `--probe-interval`.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// Consecutive absent ticks before a served card is dropped — a per-GUID
/// debounce so a single transient enumeration blip does not evict a card.
pub const PROBE_FAIL_LIMIT: u32 = 3;

/// Reader names whose card presence the event source (piggy#248) has observed
/// change since the last reconcile pass. Shared from the sync watch thread to
/// the async reconcile loop; the loop drains it on an event wake and collapses
/// the removal debounce (to a single miss) for ONLY those cards, so an event
/// about one reader never evicts a still-present card that is merely blipping
/// in enumeration. A `std::sync::Mutex` (not tokio's) because the producer is a
/// blocking thread; the reconcile holds it only for a non-`await` drain.
pub type ChangedReaders = Arc<std::sync::Mutex<HashSet<String>>>;

/// The per-card presence reconcile loop (piggy#244) — the agent side of
/// runtime card hot-swap.
///
/// Each `interval` tick, under the piggy#214 request-serializing card lock
/// (`try_lock`ed, so a wedged request can never starve the loop and a probe
/// never races an in-flight card op), it re-enumerates the DESIRED served set
/// via `load` (production: `super::load_cached_keys_from_cards`, which applies
/// the guid filter, all-cards/first-card selection, and the piggy#143 CAK
/// anti-swap) and reconciles the live `keys` vec by GUID:
///
/// - A served card absent for `fail_limit` consecutive ticks has its keys
///   dropped and its PIN forgotten ([`PinCache::forget_card`]); a per-GUID
///   miss counter debounces a transient blip, and a sibling card is untouched
///   (piggy#177).
/// - A newly-present card is adopted only once it round-trips the sign-path
///   reconnect probe (`verify`, piggy#179), so a card that enumerates but
///   cannot sign is never served.
///
/// `verify` (card IO) runs outside the `keys`/`pin` locks; the `keys` vec is
/// mutated once per tick (removals + adoptions together) so a concurrent
/// `request_identities` never sees a half-updated set.
///
/// Generic over `load`/`verify` for unit testing; the production caller passes
/// closures over `super::load_cached_keys_from_cards` and
/// `super::session::reconnect_to_token`.
pub async fn reconcile_loop<L, V>(
    keys: Arc<Mutex<Vec<CachedKey>>>,
    pin: Arc<Mutex<PinCache>>,
    card_lock: Arc<Mutex<()>>,
    mut load: L,
    mut verify: V,
    interval_duration: Duration,
    fail_limit: u32,
) where
    L: FnMut() -> Vec<CachedKey> + Send,
    V: FnMut(&Guid) -> Result<(), String> + Send,
{
    let mut misses: HashMap<Guid, u32> = HashMap::new();
    let mut interval = interval(interval_duration);
    // Poll-only: every card always uses the full blip debounce.
    let no_immediate = HashSet::new();

    loop {
        interval.tick().await;
        reconcile_once(
            &keys,
            &pin,
            &card_lock,
            &mut load,
            &mut verify,
            &mut misses,
            fail_limit,
            &no_immediate,
        )
        .await;
    }
}

/// The event-driven variant of [`reconcile_loop`] (piggy#248, opt-in via
/// `--event-driven`). The reconciler is identical — the SAME
/// [`reconcile_once`] tick — but a [`Notify`] fired by the
/// `SCardGetStatusChange` event source ([`run_event_source`]) triggers an
/// IMMEDIATE reconcile in addition to the poll interval, collapsing the
/// removed-card latency from ~`fail_limit × interval` to near-instant.
///
/// The debounce is source-aware, per card: a **timer** tick keeps the piggy#244
/// enumeration-blip debounce (`fail_limit`, so a one-tick spurious absence
/// never evicts a card) for every card. An **event** wake drains the
/// `changed` reader set (readers the watch saw actually transition) and
/// collapses the debounce to a single miss for ONLY those cards — the
/// authoritative "this reader changed" signal drops a now-absent card at once,
/// while a card whose reader did NOT change keeps its full blip debounce. This
/// is what stops an event about one reader from evicting a *different*
/// still-present card that happens to be blipping in enumeration (the poll
/// path's whole reason for debouncing). The poll interval stays the safety net
/// for anything the event source misses (a whole reader unplugged, a cold
/// pcscd, a coalesced burst). The shared `misses` map is coherent across both
/// sources because a present card always resets its counter.
#[allow(clippy::too_many_arguments)]
pub async fn reconcile_loop_with_events<L, V>(
    keys: Arc<Mutex<Vec<CachedKey>>>,
    pin: Arc<Mutex<PinCache>>,
    card_lock: Arc<Mutex<()>>,
    mut load: L,
    mut verify: V,
    interval_duration: Duration,
    fail_limit: u32,
    notify: Arc<Notify>,
    changed: ChangedReaders,
) where
    L: FnMut() -> Vec<CachedKey> + Send,
    V: FnMut(&Guid) -> Result<(), String> + Send,
{
    let mut misses: HashMap<Guid, u32> = HashMap::new();
    let mut interval = interval(interval_duration);

    loop {
        // A reader-state change (event) OR the poll deadline, whichever comes
        // first. `interval.tick()` fires immediately on the first poll, so the
        // opening pass is always a timer reconcile (matching `reconcile_loop`).
        let event = tokio::select! {
            _ = interval.tick() => false,
            _ = notify.notified() => true,
        };
        // On an event, drain the readers the watch reported changed; those
        // cards drop on the first absent pass, others keep the blip debounce.
        // A timer tick uses the empty set — full debounce for every card.
        let immediate = if event {
            std::mem::take(&mut *changed.lock().unwrap())
        } else {
            HashSet::new()
        };
        reconcile_once(
            &keys,
            &pin,
            &card_lock,
            &mut load,
            &mut verify,
            &mut misses,
            fail_limit,
            &immediate,
        )
        .await;
    }
}

/// One reconcile pass — the shared body of [`reconcile_loop`] and
/// [`reconcile_loop_with_events`]. Under the piggy#214 card lock
/// (`try_lock`ed, skipped if a request holds it) it re-enumerates the desired
/// served set via `load`, drops a card absent for `fail_limit` consecutive
/// passes (debounced through the caller-owned `misses` map) while forgetting
/// its PIN, and adopts a newly-present card once it clears the piggy#179
/// sign-path `verify` gate. `verify` (card IO) runs outside the keys/pin
/// locks; the `keys` vec is mutated once (removals + adoptions together) so a
/// concurrent `request_identities` never sees a half-updated set.
#[allow(clippy::too_many_arguments)]
async fn reconcile_once<L, V>(
    keys: &Arc<Mutex<Vec<CachedKey>>>,
    pin: &Arc<Mutex<PinCache>>,
    card_lock: &Arc<Mutex<()>>,
    load: &mut L,
    verify: &mut V,
    misses: &mut HashMap<Guid, u32>,
    fail_limit: u32,
    immediate_readers: &HashSet<String>,
) where
    L: FnMut() -> Vec<CachedKey> + Send,
    V: FnMut(&Guid) -> Result<(), String> + Send,
{
    let Ok(_card_guard) = card_lock.try_lock() else {
        tracing::debug!("card busy with a request; skipping this reconcile pass (piggy#214)");
        return;
    };

    let desired = load();
    let present: HashSet<Guid> = desired.iter().map(|k| k.guid.clone()).collect();
    // Served cards as (GUID, reader_name): the reader name lets a piggy#248
    // event that named a specific reader collapse the debounce for ONLY that
    // card, not the whole served set.
    let served: Vec<(Guid, String)> = keys
        .lock()
        .await
        .iter()
        .map(|k| (k.guid.clone(), k.reader_name.clone()))
        .collect();
    let served_guids: HashSet<Guid> = served.iter().map(|(g, _)| g.clone()).collect();

    // Debounce removals per GUID: a served card counts a miss while absent and
    // is dropped once it has missed `fail_limit` in a row; a card seen present
    // again resets its counter. A piggy#248 event that named THIS card's reader
    // (`immediate_readers`) collapses its debounce to a single miss — the
    // authoritative "this reader changed" signal, so drop at once. A timer pass
    // (empty set) or an event about a DIFFERENT reader keeps the full blip
    // debounce, so a transient enumeration blip on an unrelated present card is
    // never evicted by another card's event.
    let mut to_drop: Vec<Guid> = Vec::new();
    for (g, reader) in &served {
        if present.contains(g) {
            misses.remove(g);
        } else {
            let n = misses.entry(g.clone()).or_insert(0);
            *n += 1;
            let limit = if immediate_readers.contains(reader) {
                1
            } else {
                fail_limit
            };
            if *n >= limit {
                to_drop.push(g.clone());
            }
        }
    }

    // Decide adoptions with the sign-path gate BEFORE touching any lock —
    // `verify` does card IO and must not be held across the keys/pin locks.
    let mut to_adopt: Vec<CachedKey> = Vec::new();
    for g in present.difference(&served_guids) {
        match verify(g) {
            Ok(()) => {
                to_adopt.extend(desired.iter().filter(|k| k.guid == *g).cloned());
                tracing::info!(guid = %g.short_id(), "card inserted; adopting its keys (piggy#244)");
            }
            Err(cause) => {
                tracing::warn!(
                    guid = %g.short_id(),
                    cause = %cause,
                    "inserted card enumerated but did not reconnect via the sign-path helper; retrying (piggy#179)"
                );
            }
        }
    }

    // One atomic keys mutation: drop removed cards, add adopted ones.
    if !to_drop.is_empty() || !to_adopt.is_empty() {
        let mut served = keys.lock().await;
        served.retain(|k| !to_drop.contains(&k.guid));
        served.extend(to_adopt);
    }

    // Forget the dropped cards' PINs (a separate lock; never held with keys).
    if !to_drop.is_empty() {
        let mut pin_cache = pin.lock().await;
        for g in &to_drop {
            misses.remove(g);
            let forgot = pin_cache.forget_card(g);
            tracing::warn!(
                guid = %g.short_id(),
                forgot_pin = forgot,
                "card removed; dropped its keys (piggy#244)"
            );
            if forgot {
                // stats-me: `piggy.agent.pin_cleared` counter — a removed
                // card's cached PIN was dropped.
                crate::stats::agent_op(
                    "pin_cleared",
                    crate::stats::Outcome::Success,
                    Duration::ZERO,
                );
            }
        }
    }
}

/// A short floor on the event source's back-off sleeps so a cold pcscd or a
/// transient PCSC error can never turn the watch into a busy-spin.
const EVENT_SOURCE_BACKOFF: Duration = Duration::from_millis(300);

/// The opt-in event source (piggy#248, `--event-driven`). A blocking loop that
/// owns its own PCSC context and watches every reader's card-presence state
/// via `SCardGetStatusChange`; on any change it fires `notify`, waking
/// [`reconcile_loop_with_events`] for an immediate (`fail_limit = 1`) pass.
///
/// This is layered ON TOP of the poll reconcile, never a replacement: the poll
/// interval keeps running and stays the authoritative safety net for anything
/// this watch cannot see (a whole reader plugged/unplugged mid-wait, a cold
/// pcscd, a coalesced burst). `bounded` caps each blocking wait so the loop
/// periodically re-lists readers and re-checks `shutdown` even when nothing
/// changes.
///
/// Runs forever on a dedicated blocking thread because `get_status_change`
/// blocks the OS thread — like the sibling [`reconcile_loop`], it has no
/// in-process shutdown and is reaped when the agent process exits. Resilient
/// by construction: a failed establish, an empty reader set (nothing plugged
/// yet), or a lost pcscd all back off `EVENT_SOURCE_BACKOFF` and retry rather
/// than spin or crash — matching how the enumeration path degrades a PCSC
/// failure to empty.
pub fn run_event_source(notify: Arc<Notify>, changed: ChangedReaders, bounded: Duration) {
    tracing::info!(
        bounded_secs = bounded.as_secs(),
        "event-driven card presence: watching PC/SC reader states (piggy#248)"
    );
    loop {
        match Context::establish(Scope::System) {
            Ok(ctx) => watch_reader_states(&ctx, &notify, &changed, bounded),
            Err(e) => {
                tracing::debug!(cause = %e, "event source: PCSC establish failed; backing off (piggy#248)");
                std::thread::sleep(EVENT_SOURCE_BACKOFF);
            }
        }
    }
}

/// Watch one PCSC context's readers until the reader SET changes or a PCSC
/// error occurs (return, so the caller re-establishes and rebuilds). On each
/// change it records WHICH reader names transitioned into `changed` and fires
/// `notify`; the reconcile loop re-enumerates authoritatively and uses the
/// named readers only to decide whose debounce to collapse.
fn watch_reader_states(
    ctx: &Context,
    notify: &Arc<Notify>,
    changed: &ChangedReaders,
    bounded: Duration,
) {
    // The reader names this watch is built around. Empty => nothing plugged
    // yet: back off and let the caller re-establish/re-list (never call
    // get_status_change on an empty slice — it returns instantly and spins).
    let names = ctx.list_readers_owned().unwrap_or_default();
    if names.is_empty() {
        std::thread::sleep(EVENT_SOURCE_BACKOFF);
        return;
    }
    let mut states: Vec<ReaderState> = names
        .iter()
        .cloned()
        .map(|n| ReaderState::new(n, State::UNAWARE))
        .collect();

    loop {
        match ctx.get_status_change(bounded, &mut states) {
            Ok(()) => {
                // Record exactly which readers transitioned (State::CHANGED) so
                // the reconcile collapses the debounce for only those cards —
                // NOT the whole served set. (The first UNAWARE pass marks every
                // reader changed and fires one harmless startup reconcile; all
                // cards are present then, so nothing is dropped.)
                {
                    let mut set = changed.lock().unwrap();
                    for (rs, name) in states.iter().zip(names.iter()) {
                        if rs.event_state().contains(State::CHANGED) {
                            set.insert(name.to_string_lossy().into_owned());
                        }
                    }
                }
                notify.notify_one();
                for rs in &mut states {
                    rs.sync_current_state();
                }
            }
            Err(pcsc::Error::Timeout) => {
                // Nothing changed within `bounded`. Re-list to catch a whole
                // reader added/removed while we were blocked; a changed set
                // means rebuild the array (return to the caller). No notify —
                // the poll safety net already covers a quiet interval.
                match ctx.list_readers_owned() {
                    Ok(fresh) if fresh != names => return,
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
            Err(e) => {
                // A reader vanished, a card reset, pcscd went away: back off
                // and rebuild against a fresh context/list.
                tracing::debug!(cause = %e, "event source: get_status_change error; rebuilding (piggy#248)");
                std::thread::sleep(EVENT_SOURCE_BACKOFF);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Deterministic unit tests for `reconcile_loop`.
    //!
    //! All time-dependent tests run under `#[tokio::test(start_paused =
    //! true)]` and drive the clock manually via `tokio::time::advance`, so
    //! there is no wall-clock flake risk. `tokio::time::interval` fires its
    //! first tick immediately; each subsequent tick needs one `advance`.
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use tokio::task::yield_now;

    fn guid_a() -> Guid {
        Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap()
    }

    fn guid_b() -> Guid {
        Guid::from_hex("00112233445566778899AABBCCDDEEFF").unwrap()
    }

    /// An arbitrary `CachedKey` for `guid` on the default mock reader.
    fn cached_key(guid: &Guid) -> CachedKey {
        cached_key_on(guid, "MockReader")
    }

    /// A `CachedKey` for `guid` on a named reader — the reader name is what the
    /// piggy#248 event path keys its per-card debounce collapse on.
    fn cached_key_on(guid: &Guid, reader: &str) -> CachedKey {
        use ssh_key::public::{Ed25519PublicKey, KeyData};
        CachedKey {
            guid: guid.clone(),
            reader_name: reader.into(),
            slot_id: 0x9d,
            algorithm: piggy_piv::PivAlgorithm::Ed25519,
            public_key: KeyData::Ed25519(Ed25519PublicKey([7u8; 32])),
            comment: "reconcile-test".into(),
        }
    }

    fn pin_cache_with(entries: &[(&Guid, &str)]) -> Arc<Mutex<PinCache>> {
        let mut cache = PinCache::new();
        for (g, p) in entries {
            cache.cache_verified(g, p);
        }
        Arc::new(Mutex::new(cache))
    }

    async fn verified(pin: &Arc<Mutex<PinCache>>, guid: &Guid) -> Option<String> {
        pin.lock().await.verified_for(guid)
    }

    async fn served_guids(keys: &Arc<Mutex<Vec<CachedKey>>>) -> Vec<String> {
        keys.lock().await.iter().map(|k| k.guid.to_hex()).collect()
    }

    /// Advance the paused clock one interval and let the spawned loop run.
    async fn tick(interval_dur: Duration) {
        tokio::time::advance(interval_dur).await;
        for _ in 0..6 {
            yield_now().await;
        }
    }

    /// Let the immediate first tick fire.
    async fn settle() {
        for _ in 0..6 {
            yield_now().await;
        }
    }

    const IVL: Duration = Duration::from_millis(10);

    /// A removed card's keys are dropped and its PIN forgotten after
    /// `fail_limit` absent ticks — and NOT before (debounce boundary).
    #[tokio::test(start_paused = true)]
    async fn drops_keys_and_forgets_pin_after_fail_limit() {
        let a = guid_a();
        let keys = Arc::new(Mutex::new(vec![cached_key(&a)]));
        let pin = pin_cache_with(&[(&a, "1234")]);
        let card_lock = Arc::new(Mutex::new(()));
        let calls = Arc::new(AtomicU32::new(0));
        let calls_cl = calls.clone();
        // Card A is absent every tick.
        let load = move || {
            calls_cl.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        };
        let handle = tokio::spawn({
            let (keys, pin, card_lock) = (keys.clone(), pin.clone(), card_lock.clone());
            async move { reconcile_loop(keys, pin, card_lock, load, |_| Ok(()), IVL, 3).await }
        });

        settle().await; // tick 1 (miss 1)
        tick(IVL).await; // tick 2 (miss 2) — still below the limit
        assert_eq!(
            served_guids(&keys).await,
            vec![a.to_hex()],
            "kept below limit"
        );
        assert_eq!(verified(&pin, &a).await.as_deref(), Some("1234"));

        tick(IVL).await; // tick 3 (miss 3 == limit) — dropped
        assert!(
            served_guids(&keys).await.is_empty(),
            "dropped after fail_limit"
        );
        assert_eq!(verified(&pin, &a).await, None, "PIN forgotten on removal");
        assert!(calls.load(Ordering::SeqCst) >= 3, "loop actually ran");
        handle.abort();
    }

    /// A one-tick absence blip does NOT drop the card — the miss counter
    /// resets when it reappears.
    #[tokio::test(start_paused = true)]
    async fn debounces_a_transient_blip() {
        let a = guid_a();
        let keys = Arc::new(Mutex::new(vec![cached_key(&a)]));
        let pin = pin_cache_with(&[(&a, "1234")]);
        let n = Arc::new(AtomicU32::new(0));
        let n_cl = n.clone();
        let a_cl = a.clone();
        // Absent on tick 2 only, present otherwise.
        let load = move || {
            let i = n_cl.fetch_add(1, Ordering::SeqCst);
            if i == 1 {
                Vec::new()
            } else {
                vec![cached_key(&a_cl)]
            }
        };
        let handle = tokio::spawn({
            let (keys, pin) = (keys.clone(), pin.clone());
            async move {
                reconcile_loop(
                    keys,
                    pin,
                    Arc::new(Mutex::new(())),
                    load,
                    |_| Ok(()),
                    IVL,
                    3,
                )
                .await
            }
        });

        settle().await;
        for _ in 0..5 {
            tick(IVL).await;
        }
        assert_eq!(
            served_guids(&keys).await,
            vec![a.to_hex()],
            "blip did not evict"
        );
        assert_eq!(verified(&pin, &a).await.as_deref(), Some("1234"));
        handle.abort();
    }

    /// Removing one card leaves a sibling's keys AND PIN intact (piggy#177).
    #[tokio::test(start_paused = true)]
    async fn removing_one_card_keeps_the_sibling() {
        let (a, b) = (guid_a(), guid_b());
        let keys = Arc::new(Mutex::new(vec![cached_key(&a), cached_key(&b)]));
        let pin = pin_cache_with(&[(&a, "1111"), (&b, "2222")]);
        let b_cl = b.clone();
        // Only B remains present.
        let load = move || vec![cached_key(&b_cl)];
        let handle = tokio::spawn({
            let (keys, pin) = (keys.clone(), pin.clone());
            async move {
                reconcile_loop(
                    keys,
                    pin,
                    Arc::new(Mutex::new(())),
                    load,
                    |_| Ok(()),
                    IVL,
                    3,
                )
                .await
            }
        });

        settle().await;
        for _ in 0..3 {
            tick(IVL).await;
        }
        assert_eq!(
            served_guids(&keys).await,
            vec![b.to_hex()],
            "A dropped, B kept"
        );
        assert_eq!(verified(&pin, &a).await, None, "A's PIN forgotten");
        assert_eq!(
            verified(&pin, &b).await.as_deref(),
            Some("2222"),
            "B's PIN survives"
        );
        handle.abort();
    }

    /// A newly-present card is adopted once `verify` (the #179 sign-path
    /// gate) passes.
    #[tokio::test(start_paused = true)]
    async fn adopts_a_newly_present_card_after_verify() {
        let a = guid_a();
        let keys: Arc<Mutex<Vec<CachedKey>>> = Arc::new(Mutex::new(Vec::new()));
        let pin = Arc::new(Mutex::new(PinCache::new()));
        let a_cl = a.clone();
        let load = move || vec![cached_key(&a_cl)];
        let handle = tokio::spawn({
            let (keys, pin) = (keys.clone(), pin.clone());
            async move {
                reconcile_loop(
                    keys,
                    pin,
                    Arc::new(Mutex::new(())),
                    load,
                    |_| Ok(()),
                    IVL,
                    3,
                )
                .await
            }
        });

        settle().await; // first tick adopts
        assert_eq!(
            served_guids(&keys).await,
            vec![a.to_hex()],
            "adopted on insert"
        );
        handle.abort();
    }

    /// piggy#179: a card that enumerates but fails the sign-path reconnect
    /// probe is NEVER adopted.
    #[tokio::test(start_paused = true)]
    async fn does_not_adopt_when_verify_fails() {
        let a = guid_a();
        let keys: Arc<Mutex<Vec<CachedKey>>> = Arc::new(Mutex::new(Vec::new()));
        let pin = Arc::new(Mutex::new(PinCache::new()));
        let a_cl = a.clone();
        let load = move || vec![cached_key(&a_cl)];
        let handle = tokio::spawn({
            let (keys, pin) = (keys.clone(), pin.clone());
            async move {
                reconcile_loop(
                    keys,
                    pin,
                    Arc::new(Mutex::new(())),
                    load,
                    |_| Err("PIV token no longer available".to_string()),
                    IVL,
                    3,
                )
                .await
            }
        });

        settle().await;
        for _ in 0..3 {
            tick(IVL).await;
        }
        assert!(
            served_guids(&keys).await.is_empty(),
            "sign-incapable card not adopted"
        );
        handle.abort();
    }

    /// piggy#214: while a request holds the card lock, a reconcile tick is
    /// skipped (load is never called) — so a burst spanning several ticks
    /// never evicts a card. Once the lock frees, an absent card still drops.
    #[tokio::test(start_paused = true)]
    async fn skips_ticks_while_request_holds_card_lock() {
        let a = guid_a();
        let keys = Arc::new(Mutex::new(vec![cached_key(&a)]));
        let pin = pin_cache_with(&[(&a, "1234")]);
        let card_lock = Arc::new(Mutex::new(()));
        let calls = Arc::new(AtomicU32::new(0));
        let calls_cl = calls.clone();
        let load = move || {
            calls_cl.fetch_add(1, Ordering::SeqCst);
            Vec::new() // absent whenever actually enumerated
        };
        let held = card_lock.clone().lock_owned().await;
        let handle = tokio::spawn({
            let (keys, pin, card_lock) = (keys.clone(), pin.clone(), card_lock.clone());
            async move { reconcile_loop(keys, pin, card_lock, load, |_| Ok(()), IVL, 3).await }
        });

        settle().await;
        for _ in 0..6 {
            tick(IVL).await;
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "enumerated while a request held the lock"
        );
        assert_eq!(
            served_guids(&keys).await,
            vec![a.to_hex()],
            "card kept while busy"
        );

        drop(held);
        for _ in 0..3 {
            tick(IVL).await;
        }
        assert!(
            calls.load(Ordering::SeqCst) >= 3,
            "reconcile did not resume"
        );
        assert!(
            served_guids(&keys).await.is_empty(),
            "absent card drops once lock frees"
        );
        handle.abort();
    }

    // -------- Event-driven loop (piggy#248) --------

    /// Spawn `reconcile_loop_with_events` and hand back the shared `Notify` and
    /// `changed` reader set, so a test can simulate the event source: seed
    /// `changed` with the readers that "changed", then fire `notify`. Mirrors
    /// the plain-loop spawns above.
    fn spawn_events<L, V>(
        keys: &Arc<Mutex<Vec<CachedKey>>>,
        pin: &Arc<Mutex<PinCache>>,
        card_lock: &Arc<Mutex<()>>,
        load: L,
        verify: V,
        fail_limit: u32,
    ) -> (tokio::task::JoinHandle<()>, Arc<Notify>, ChangedReaders)
    where
        L: FnMut() -> Vec<CachedKey> + Send + 'static,
        V: FnMut(&Guid) -> Result<(), String> + Send + 'static,
    {
        let notify = Arc::new(Notify::new());
        let changed: ChangedReaders = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let handle = tokio::spawn({
            let (keys, pin, card_lock, notify, changed) = (
                keys.clone(),
                pin.clone(),
                card_lock.clone(),
                notify.clone(),
                changed.clone(),
            );
            async move {
                reconcile_loop_with_events(
                    keys, pin, card_lock, load, verify, IVL, fail_limit, notify, changed,
                )
                .await
            }
        });
        (handle, notify, changed)
    }

    /// Simulate the event source: mark `reader` changed, then wake the loop.
    fn fire_event(changed: &ChangedReaders, notify: &Arc<Notify>, reader: &str) {
        changed.lock().unwrap().insert(reader.to_string());
        notify.notify_one();
    }

    /// The point of piggy#248: an event wake reconciles with `fail_limit = 1`,
    /// so a card that just went absent is dropped in a SINGLE pass — where a
    /// timer tick would debounce it across `fail_limit` passes. No clock is
    /// advanced, so ONLY the event path could have dropped it.
    #[tokio::test(start_paused = true)]
    async fn event_wake_drops_removed_card_in_one_pass() {
        let a = guid_a();
        let keys = Arc::new(Mutex::new(vec![cached_key(&a)]));
        let pin = pin_cache_with(&[(&a, "1234")]);
        let card_lock = Arc::new(Mutex::new(()));
        let removed = Arc::new(AtomicBool::new(false));
        let (removed_cl, a_cl) = (removed.clone(), a.clone());
        let load = move || {
            if removed_cl.load(Ordering::SeqCst) {
                Vec::new()
            } else {
                vec![cached_key(&a_cl)]
            }
        };
        let (handle, notify, changed) = spawn_events(&keys, &pin, &card_lock, load, |_| Ok(()), 3);

        settle().await; // first pass is the immediate timer tick: A present, kept
        assert_eq!(served_guids(&keys).await, vec![a.to_hex()], "A served");

        removed.store(true, Ordering::SeqCst);
        fire_event(&changed, &notify, "MockReader"); // A's reader changed
        settle().await; // ONE event pass, no clock advance
        assert!(
            served_guids(&keys).await.is_empty(),
            "event wake dropped the just-removed card in a single pass"
        );
        assert_eq!(verified(&pin, &a).await, None, "PIN forgotten on removal");
        handle.abort();
    }

    /// A TIMER tick under the event loop keeps the piggy#244 blip debounce:
    /// an absent card survives `fail_limit - 1` timer passes and drops on the
    /// `fail_limit`-th — the event wake never fires here.
    #[tokio::test(start_paused = true)]
    async fn timer_tick_still_debounces_under_event_mode() {
        let a = guid_a();
        let keys = Arc::new(Mutex::new(vec![cached_key(&a)]));
        let pin = pin_cache_with(&[(&a, "1234")]);
        let card_lock = Arc::new(Mutex::new(()));
        let load = move || Vec::new(); // A absent every pass
        let (handle, _notify, _changed) =
            spawn_events(&keys, &pin, &card_lock, load, |_| Ok(()), 3);

        settle().await; // timer pass 1 (miss 1)
        tick(IVL).await; // timer pass 2 (miss 2)
        assert_eq!(
            served_guids(&keys).await,
            vec![a.to_hex()],
            "timer path still debounces below the limit"
        );
        tick(IVL).await; // timer pass 3 (miss 3 == limit)
        assert!(
            served_guids(&keys).await.is_empty(),
            "timer path drops at fail_limit"
        );
        handle.abort();
    }

    /// An event wake with two served cards drops NEITHER while both remain
    /// present — a guard against an event pass mis-firing on a still-present
    /// card (piggy#248 §mis-fire analysis).
    #[tokio::test(start_paused = true)]
    async fn event_wake_keeps_still_present_cards() {
        let (a, b) = (guid_a(), guid_b());
        let keys = Arc::new(Mutex::new(vec![cached_key(&a), cached_key(&b)]));
        let pin = pin_cache_with(&[(&a, "1111"), (&b, "2222")]);
        let card_lock = Arc::new(Mutex::new(()));
        let (a_cl, b_cl) = (a.clone(), b.clone());
        let load = move || vec![cached_key(&a_cl), cached_key(&b_cl)];
        let (handle, notify, changed) = spawn_events(&keys, &pin, &card_lock, load, |_| Ok(()), 3);

        settle().await;
        fire_event(&changed, &notify, "MockReader");
        settle().await; // an event pass with both still present
        let mut served = served_guids(&keys).await;
        served.sort();
        let mut want = vec![a.to_hex(), b.to_hex()];
        want.sort();
        assert_eq!(served, want, "both present cards kept across an event wake");
        handle.abort();
    }

    /// An event wake adopts a newly-present, sign-capable card, exactly as a
    /// timer tick does (the shared adoption path, piggy#179-gated).
    #[tokio::test(start_paused = true)]
    async fn event_wake_adopts_a_newly_present_card() {
        let a = guid_a();
        let keys: Arc<Mutex<Vec<CachedKey>>> = Arc::new(Mutex::new(Vec::new()));
        let pin = Arc::new(Mutex::new(PinCache::new()));
        let card_lock = Arc::new(Mutex::new(()));
        let a_cl = a.clone();
        let load = move || vec![cached_key(&a_cl)];
        let (handle, notify, changed) = spawn_events(&keys, &pin, &card_lock, load, |_| Ok(()), 3);

        settle().await;
        // Adoption does not depend on the changed set (it acts on present,
        // unserved cards); a plain wake suffices.
        fire_event(&changed, &notify, "MockReader");
        settle().await;
        assert_eq!(
            served_guids(&keys).await,
            vec![a.to_hex()],
            "event wake adopted the inserted card"
        );
        handle.abort();
    }

    /// piggy#248 regression (review finding, confidence 80): an event that
    /// names card B's reader must NOT collapse card A's debounce. A is still
    /// present but blips absent in enumeration this pass; because the event is
    /// about B's reader, A keeps the full blip debounce and is NOT evicted.
    /// Before the reader-scoped fix, the event pass used `fail_limit = 1` for
    /// EVERY served card, so A's single blip + B's unrelated event evicted A.
    #[tokio::test(start_paused = true)]
    async fn event_about_one_reader_does_not_evict_a_blipping_other_card() {
        let (a, b) = (guid_a(), guid_b());
        let keys = Arc::new(Mutex::new(vec![
            cached_key_on(&a, "ReaderA"),
            cached_key_on(&b, "ReaderB"),
        ]));
        let pin = pin_cache_with(&[(&a, "1111"), (&b, "2222")]);
        let card_lock = Arc::new(Mutex::new(()));
        // A blips absent while B stays present; the event is about ReaderB.
        let b_cl = b.clone();
        let load = move || vec![cached_key_on(&b_cl, "ReaderB")];
        let (handle, notify, changed) = spawn_events(&keys, &pin, &card_lock, load, |_| Ok(()), 3);

        settle().await; // timer pass: A absent → miss 1 (< 3, survives); B present
        fire_event(&changed, &notify, "ReaderB"); // event names B, NOT A
        settle().await; // event pass: immediate={ReaderB}; A absent → miss 2 (< 3) → survives
        let served = served_guids(&keys).await;
        assert!(
            served.contains(&a.to_hex()),
            "card A wrongly evicted by an event about card B: {served:?}"
        );
        assert_eq!(
            verified(&pin, &a).await.as_deref(),
            Some("1111"),
            "card A's PIN wrongly forgotten"
        );
        handle.abort();
    }

    // -------- Production constants (pinned) --------

    #[test]
    fn probe_fail_limit_is_3() {
        assert_eq!(PROBE_FAIL_LIMIT, 3);
    }

    /// The default reconcile cadence (piggy#244). Shortened from the historic
    /// 60s single-card probe for hot-swap responsiveness; tunable via
    /// `--probe-interval`. Changing it is a deliberate behavioural knob.
    #[test]
    fn default_probe_interval_is_10s() {
        assert_eq!(DEFAULT_PROBE_INTERVAL, Duration::from_secs(10));
    }
}
