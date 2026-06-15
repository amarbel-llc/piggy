//! Background PIV-card presence probe.
//!
//! Ported from `pivy-agent/src/card.rs` with the `pivy_piv` crate
//! dependency relabelled to `piggy_piv`. The original behaviour (PIN-clearing
//! presence probe) is unchanged; the recovery loop (piggy#175) is new.

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

use piggy_piv::{Guid, PivContext};

use super::session::CachedKey;

const PROBE_INTERVAL: Duration = Duration::from_secs(60);
const PROBE_FAIL_LIMIT: u32 = 3;

/// Cadence at which a 0-key agent re-attempts PIV enumeration to recover from
/// a transient startup PCSC failure (piggy#175). Deliberately shorter than
/// [`PROBE_INTERVAL`] so an agent wedged at login (e.g. a polkit-gated,
/// socket-activated pcscd that denied the first call before the logind
/// session was polkit-`active`) self-heals within seconds once the card
/// becomes reachable. Cheap to poll: a card-absent enumeration returns before
/// any slot certs are read, and the heavier `read_all_slots` only runs once a
/// token actually appears.
pub(crate) const RECOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// Background task that periodically probes the PIV card.
/// Forgets the cached PIN if the card disappears.
///
/// This is a thin wrapper around [`probe_loop_with`] that uses a real
/// [`PivContext`] as the presence detector. The production behaviour is
/// identical to the original single-function implementation: every
/// `PROBE_INTERVAL`, the card is enumerated and the PIN is cleared after
/// `PROBE_FAIL_LIMIT` consecutive failures.
pub async fn probe_loop(guid: Guid, pin: Arc<Mutex<Option<String>>>) {
    probe_loop_with(
        guid,
        pin,
        default_card_probe,
        PROBE_INTERVAL,
        PROBE_FAIL_LIMIT,
    )
    .await
}

/// CAK-reauthenticating probe loop (piggy#143): like [`probe_loop`], but the
/// per-tick probe additionally re-runs the slot-9E CAK challenge/response. A
/// card SWAP (or a card whose 9E stops matching the configured CAK) is then
/// treated as card-absent and clears the cached PIN after `PROBE_FAIL_LIMIT`
/// consecutive failures, matching the C pivy-agent's per-probe `auth_cak`.
pub async fn probe_loop_cak(
    guid: Guid,
    pin: Arc<Mutex<Option<String>>>,
    cak: ssh_key::public::KeyData,
) {
    probe_loop_with(
        guid,
        pin,
        move |g| default_card_probe(g) && super::cak::authenticate(g, &cak),
        PROBE_INTERVAL,
        PROBE_FAIL_LIMIT,
    )
    .await
}

/// Default card-presence probe: establishes a new PCSC context and
/// enumerates tokens. Returns `true` iff a token with the given GUID is
/// available.
fn default_card_probe(guid: &Guid) -> bool {
    match PivContext::new() {
        Ok(ctx) => match ctx.enumerate_tokens() {
            Ok(tokens) => tokens.iter().any(|t| *t.guid() == *guid),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// Generic probe loop parameterised on the card-presence detector and
/// timing knobs. Exposed primarily for unit testing; production callers
/// should use [`probe_loop`].
pub async fn probe_loop_with<F>(
    guid: Guid,
    pin: Arc<Mutex<Option<String>>>,
    mut probe: F,
    interval_duration: Duration,
    fail_limit: u32,
) where
    F: FnMut(&Guid) -> bool + Send,
{
    let mut failures: u32 = 0;
    let mut interval = interval(interval_duration);

    loop {
        interval.tick().await;

        let card_present = probe(&guid);

        if card_present {
            failures = 0;
        } else {
            failures += 1;
            if failures >= fail_limit {
                let mut pin_guard = pin.lock().await;
                if pin_guard.is_some() {
                    tracing::warn!("card unavailable after {} probes, forgetting PIN", failures);
                    *pin_guard = None;
                    // stats-me: `piggy.agent.pin_cleared` counter (no duration
                    // dimension) — the probe loop dropped a cached PIN.
                    crate::stats::agent_op(
                        "pin_cleared",
                        crate::stats::Outcome::Success,
                        std::time::Duration::ZERO,
                    );
                }
                failures = 0;
            }
        }
    }
}

/// Recovery loop for a 0-key startup (piggy#175).
///
/// When the agent enumerates no PIV keys at startup — typically a transient
/// PCSC denial at login on a polkit-gated, socket-activated pcscd — there is
/// otherwise no path back to a working agent short of a manual
/// `systemctl --user restart`. This loop keeps re-running `load` every
/// `interval_duration` and, the first time `load` yields a non-empty key set,
/// writes it into the agent's shared `keys` vec (which the identity/sign
/// handlers read live) and returns the recovered card's GUID so the caller can
/// hand off to the normal PIN-clearing [`probe_loop`].
///
/// `load` is the card-enumeration closure (the real one re-enumerates tokens
/// and rebuilds the cached keys; tests inject a fake). It returns the loaded
/// keys plus the primary GUID; an empty load (card still unreachable) is a
/// no-op that simply waits for the next tick.
///
/// Generic over `load` for unit testing; the production caller passes a
/// closure over `super::load_cached_keys_from_cards`.
pub async fn recovery_loop_with<F>(
    keys: Arc<Mutex<Vec<CachedKey>>>,
    mut load: F,
    interval_duration: Duration,
) -> Guid
where
    F: FnMut() -> (Vec<CachedKey>, Option<Guid>) + Send,
{
    let mut interval = interval(interval_duration);

    loop {
        interval.tick().await;

        let (loaded, guid) = load();
        if let Some(guid) = guid {
            if !loaded.is_empty() {
                let n = loaded.len();
                *keys.lock().await = loaded;
                tracing::info!(
                    keys = n,
                    guid = %guid.short_id(),
                    "recovered keys from PIV tokens after a transient startup failure"
                );
                return guid;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Deterministic unit tests for `probe_loop_with` and the production
    //! constants consumed by `probe_loop`.
    //!
    //! All time-dependent tests run under `#[tokio::test(start_paused =
    //! true)]` and drive the clock manually via `tokio::time::advance`
    //! or `sleep`. This eliminates the wall-clock flake risk the
    //! antagonistic review of #1 called out — the previous tests used a
    //! 1 ms interval + 20 ms real-time `timeout`, which could under-tick
    //! on slow CI and pass vacuously.
    //!
    //! `tick_at_least_n_times` spawns the loop with a known counter,
    //! advances the paused clock past the target number of intervals,
    //! and polls the counter. This is the idiomatic pattern for testing
    //! `tokio::time::interval` under paused time.
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::task::yield_now;

    fn sample_guid() -> Guid {
        Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap()
    }

    /// Spawn `probe_loop_with`, drive the paused clock until the probe
    /// has been called at least `target_probes` times, and return the
    /// loop's JoinHandle (caller aborts it).
    ///
    /// Important: `tokio::time::interval` fires its **first** tick
    /// immediately on the first `.tick().await` — no `advance()` is
    /// required to see probe #1. Each subsequent tick needs one
    /// `advance(interval_dur)`. So `target_probes = k` requires
    /// `k - 1` advances past the initial immediate tick.
    ///
    /// Panics if the counter does not rise to `target_probes` after the
    /// clock is advanced — a floor against silent no-op loops.
    async fn run_until_n_probes<F>(
        guid: Guid,
        pin: Arc<Mutex<Option<String>>>,
        probe: F,
        interval_dur: Duration,
        fail_limit: u32,
        counter: Arc<AtomicU32>,
        target_probes: u32,
    ) -> tokio::task::JoinHandle<()>
    where
        F: FnMut(&Guid) -> bool + Send + 'static,
    {
        assert!(target_probes >= 1, "need at least 1 probe");
        let handle = tokio::spawn(async move {
            probe_loop_with(guid, pin, probe, interval_dur, fail_limit).await;
        });

        // Yield so the spawned task reaches its first tick.await and the
        // immediate tick fires (probe #1).
        for _ in 0..4 {
            yield_now().await;
        }

        // Each further probe needs one interval_dur advance.
        for _ in 0..(target_probes - 1) {
            tokio::time::advance(interval_dur).await;
            for _ in 0..4 {
                yield_now().await;
            }
        }

        let observed = counter.load(Ordering::SeqCst);
        assert!(
            observed >= target_probes,
            "probe loop under-ran: expected ≥ {target_probes} probes, got {observed}"
        );
        handle
    }

    #[tokio::test(start_paused = true)]
    async fn probe_loop_clears_pin_after_fail_limit() {
        let pin = Arc::new(Mutex::new(Some("1234".to_string())));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let fail_limit: u32 = 3;
        let counter_cl = counter.clone();
        let probe = move |_g: &Guid| {
            counter_cl.fetch_add(1, Ordering::SeqCst);
            false
        };

        let handle = run_until_n_probes(
            guid,
            pin.clone(),
            probe,
            Duration::from_millis(10),
            fail_limit,
            counter,
            fail_limit, // advance exactly fail_limit ticks
        )
        .await;

        // After fail_limit consecutive failures the PIN must be cleared.
        assert_eq!(*pin.lock().await, None);
        handle.abort();
    }

    /// Positive control for the clear-after-fail-limit test: at one
    /// fewer tick, the PIN must still be present. Pins the boundary.
    #[tokio::test(start_paused = true)]
    async fn probe_loop_keeps_pin_just_below_fail_limit() {
        let pin = Arc::new(Mutex::new(Some("1234".to_string())));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let fail_limit: u32 = 3;
        let counter_cl = counter.clone();
        let probe = move |_g: &Guid| {
            counter_cl.fetch_add(1, Ordering::SeqCst);
            false
        };

        let handle = run_until_n_probes(
            guid,
            pin.clone(),
            probe,
            Duration::from_millis(10),
            fail_limit,
            counter,
            fail_limit - 1, // one tick short of the limit
        )
        .await;

        assert_eq!(*pin.lock().await, Some("1234".to_string()));
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn probe_loop_keeps_pin_while_card_present() {
        let pin = Arc::new(Mutex::new(Some("hunter2".to_string())));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let fail_limit: u32 = 3;
        let counter_cl = counter.clone();
        let probe = move |_g: &Guid| {
            counter_cl.fetch_add(1, Ordering::SeqCst);
            true
        };

        // Run for 2× fail_limit ticks — even if the counter logic were
        // broken, we'd see any spurious clear here.
        let handle = run_until_n_probes(
            guid,
            pin.clone(),
            probe,
            Duration::from_millis(10),
            fail_limit,
            counter,
            fail_limit * 2,
        )
        .await;

        assert_eq!(*pin.lock().await, Some("hunter2".to_string()));
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn probe_loop_resets_failure_counter_on_success() {
        // Pattern: fail, fail, succeed, fail, fail -- should NOT clear
        // the pin because the success resets the counter and we never
        // reach fail_limit=3 consecutive failures.
        let pin = Arc::new(Mutex::new(Some("stable".to_string())));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let fail_limit: u32 = 3;
        let counter_cl = counter.clone();
        let probe = move |_g: &Guid| {
            let n = counter_cl.fetch_add(1, Ordering::SeqCst);
            // Present on every 3rd call (index 2, 5, 8, ...).
            n % 3 == 2
        };

        // 6 ticks: fail, fail, succeed, fail, fail, succeed.
        // Longest consecutive failure run is 2, below fail_limit.
        let handle = run_until_n_probes(
            guid,
            pin.clone(),
            probe,
            Duration::from_millis(10),
            fail_limit,
            counter.clone(),
            6,
        )
        .await;

        // PIN must survive, AND the counter must prove the loop actually
        // ran 6+ times (no vacuous pass).
        assert!(counter.load(Ordering::SeqCst) >= 6);
        assert_eq!(*pin.lock().await, Some("stable".to_string()));
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn probe_loop_no_op_when_pin_already_empty() {
        // If the PIN is None and the card is absent, the loop must
        // still run cleanly and leave the PIN as None.
        let pin: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let fail_limit: u32 = 3;
        let counter_cl = counter.clone();
        let probe = move |_g: &Guid| {
            counter_cl.fetch_add(1, Ordering::SeqCst);
            false
        };

        let handle = run_until_n_probes(
            guid,
            pin.clone(),
            probe,
            Duration::from_millis(10),
            fail_limit,
            counter,
            fail_limit * 2,
        )
        .await;

        assert_eq!(*pin.lock().await, None);
        handle.abort();
    }

    /// The GUID given to `probe_loop` must be the one passed to the
    /// probe closure on every call — including failure calls, since
    /// that is the security-relevant branch (where the PIN gets
    /// cleared). Collect GUIDs from both success and failure probes.
    #[tokio::test(start_paused = true)]
    async fn probe_loop_passes_correct_guid_to_probe_on_every_call() {
        let pin = Arc::new(Mutex::new(None));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let fail_limit: u32 = 3;
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen_cl = seen.clone();
        let counter_cl = counter.clone();
        let probe = move |g: &Guid| {
            let n = counter_cl.fetch_add(1, Ordering::SeqCst);
            seen_cl.lock().unwrap().push(g.to_hex());
            // Alternate success/failure so both branches get exercised.
            n.is_multiple_of(2)
        };

        let handle = run_until_n_probes(
            guid.clone(),
            pin,
            probe,
            Duration::from_millis(10),
            fail_limit,
            counter,
            5,
        )
        .await;

        let seen = seen.lock().unwrap();
        assert!(
            seen.len() >= 5,
            "expected ≥ 5 probe calls, got {}",
            seen.len()
        );
        for h in seen.iter() {
            assert_eq!(h, &guid.to_hex());
        }
        handle.abort();
    }

    // -------- Recovery loop (piggy#175) --------

    /// Build an arbitrary `CachedKey` for the recovery-loop tests. The key
    /// material is never verified by the loop — only its presence (non-empty
    /// vec) and the carried GUID matter.
    fn cached_test_key(guid: &Guid) -> CachedKey {
        use ssh_key::public::{Ed25519PublicKey, KeyData};
        CachedKey {
            guid: guid.clone(),
            reader_name: "MockReader".into(),
            slot_id: 0x9d,
            algorithm: piggy_piv::PivAlgorithm::Ed25519,
            public_key: KeyData::Ed25519(Ed25519PublicKey([7u8; 32])),
            comment: "recovery-test".into(),
        }
    }

    /// Issue #175: an agent that starts with 0 keys (transient PCSC failure)
    /// must keep retrying and adopt keys into its shared vec once the card
    /// becomes reachable, returning the recovered GUID so the caller can hand
    /// off to the PIN-clearing probe loop.
    #[tokio::test(start_paused = true)]
    async fn recovery_loop_adopts_keys_once_card_appears() {
        let keys: Arc<Mutex<Vec<CachedKey>>> = Arc::new(Mutex::new(Vec::new()));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_cl = counter.clone();
        let guid_cl = guid.clone();
        // Fail (card unreachable) for the first two loads, then succeed.
        let load = move || {
            let n = counter_cl.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                (Vec::new(), None)
            } else {
                (vec![cached_test_key(&guid_cl)], Some(guid_cl.clone()))
            }
        };

        let keys_cl = keys.clone();
        let handle = tokio::spawn(async move {
            recovery_loop_with(keys_cl, load, Duration::from_millis(10)).await
        });

        // First tick fires immediately (load #1 = fail). Advancing two more
        // intervals reaches load #3, the first success.
        for _ in 0..4 {
            yield_now().await;
        }
        for _ in 0..2 {
            tokio::time::advance(Duration::from_millis(10)).await;
            for _ in 0..4 {
                yield_now().await;
            }
        }

        let recovered = handle.await.unwrap();
        assert_eq!(recovered.to_hex(), guid.to_hex());
        assert_eq!(keys.lock().await.len(), 1);
        assert!(counter.load(Ordering::SeqCst) >= 3);
    }

    /// While the card stays unreachable the loop must keep the shared key vec
    /// empty and keep running (never returning) — the agent serves 0 keys but
    /// remains poised to self-heal.
    #[tokio::test(start_paused = true)]
    async fn recovery_loop_keeps_waiting_while_card_absent() {
        let keys: Arc<Mutex<Vec<CachedKey>>> = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::new(AtomicU32::new(0));
        let counter_cl = counter.clone();
        let load = move || {
            counter_cl.fetch_add(1, Ordering::SeqCst);
            (Vec::new(), None)
        };

        let keys_cl = keys.clone();
        let handle = tokio::spawn(async move {
            recovery_loop_with(keys_cl, load, Duration::from_millis(10)).await
        });

        for _ in 0..4 {
            yield_now().await;
        }
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(10)).await;
            for _ in 0..4 {
                yield_now().await;
            }
        }

        assert!(
            !handle.is_finished(),
            "loop must not return while card absent"
        );
        assert!(keys.lock().await.is_empty());
        assert!(counter.load(Ordering::SeqCst) >= 5);
        handle.abort();
    }

    // -------- Production constants (pinned) --------

    /// Pin the production `PROBE_FAIL_LIMIT`. Changing the constant is a
    /// behavioural change worth a deliberate update to this test, not a
    /// silent regression.
    #[test]
    fn probe_fail_limit_is_3() {
        assert_eq!(PROBE_FAIL_LIMIT, 3);
    }

    /// Pin the production `PROBE_INTERVAL`. 60 seconds is the window
    /// between card-presence probes and also bounds how quickly a
    /// pulled card de-authenticates (3 × 60 s = 3 min); changing it is
    /// a security-relevant knob.
    #[test]
    fn probe_interval_is_60s() {
        assert_eq!(PROBE_INTERVAL, Duration::from_secs(60));
    }
}
