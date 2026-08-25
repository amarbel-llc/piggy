//! Background PIV-card presence lifecycle (piggy#244).
//!
//! A single [`reconcile_loop`] maintains the agent's served key set against
//! the cards physically present: it drops a removed card's keys and forgets
//! its PIN, and adopts a newly-inserted card's keys (sign-path gated). It
//! subsumes the old single-primary PIN-clear probe, the piggy#175 0-key
//! recovery, and the piggy#143 CAK-swap loop.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

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

    loop {
        interval.tick().await;

        let Ok(_card_guard) = card_lock.try_lock() else {
            tracing::debug!("card busy with a request; skipping this reconcile tick (piggy#214)");
            continue;
        };

        let desired = load();
        let present: HashSet<Guid> = desired.iter().map(|k| k.guid.clone()).collect();
        let served_guids: HashSet<Guid> =
            keys.lock().await.iter().map(|k| k.guid.clone()).collect();

        // Debounce removals per GUID: a served card counts a miss while
        // absent and is dropped once it has missed `fail_limit` in a row; a
        // card seen present again resets its counter.
        let mut to_drop: Vec<Guid> = Vec::new();
        for g in &served_guids {
            if present.contains(g) {
                misses.remove(g);
            } else {
                let n = misses.entry(g.clone()).or_insert(0);
                *n += 1;
                if *n >= fail_limit {
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
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::task::yield_now;

    fn guid_a() -> Guid {
        Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap()
    }

    fn guid_b() -> Guid {
        Guid::from_hex("00112233445566778899AABBCCDDEEFF").unwrap()
    }

    /// An arbitrary `CachedKey` for `guid`. Only its GUID matters to the loop.
    fn cached_key(guid: &Guid) -> CachedKey {
        use ssh_key::public::{Ed25519PublicKey, KeyData};
        CachedKey {
            guid: guid.clone(),
            reader_name: "MockReader".into(),
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
