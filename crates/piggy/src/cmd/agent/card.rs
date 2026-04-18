//! Background PIV-card presence probe.
//!
//! Ported from `pivy-agent/src/card.rs` with the `pivy_piv` crate
//! dependency relabelled to `piggy_piv`. No behavioural changes.

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

use piggy_piv::{Guid, PivContext};

const PROBE_INTERVAL: Duration = Duration::from_secs(60);
const PROBE_FAIL_LIMIT: u32 = 3;

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
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::time::timeout;

    fn sample_guid() -> Guid {
        Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap()
    }

    /// Drive the probe loop for enough real time to fire `n_ticks`
    /// immediate-interval ticks, then cancel it.
    ///
    /// `interval(Duration::from_millis(0))` still fires on every poll,
    /// but each tick yields; `timeout` cancels the loop cleanly.
    async fn run_probe_for_ticks<F>(
        guid: Guid,
        pin: Arc<Mutex<Option<String>>>,
        probe: F,
        fail_limit: u32,
    ) where
        F: FnMut(&Guid) -> bool + Send + 'static,
    {
        // Use a very small interval; `timeout` cancels the loop.
        // 20ms total is plenty for ~100 rapid-fire ticks while keeping
        // tests fast and deterministic on slow CI.
        let _ = timeout(
            Duration::from_millis(20),
            probe_loop_with(guid, pin, probe, Duration::from_millis(1), fail_limit),
        )
        .await;
    }

    #[tokio::test]
    async fn probe_loop_clears_pin_after_fail_limit() {
        let pin = Arc::new(Mutex::new(Some("1234".to_string())));
        let guid = sample_guid();
        let probe = |_g: &Guid| false;

        run_probe_for_ticks(guid, pin.clone(), probe, 3).await;

        // After multiple consecutive failures, the pin must have been
        // cleared.
        assert_eq!(*pin.lock().await, None);
    }

    #[tokio::test]
    async fn probe_loop_keeps_pin_while_card_present() {
        let pin = Arc::new(Mutex::new(Some("hunter2".to_string())));
        let guid = sample_guid();
        let probe = |_g: &Guid| true;

        run_probe_for_ticks(guid, pin.clone(), probe, 3).await;

        // Continuously successful probes must not touch the pin.
        assert_eq!(*pin.lock().await, Some("hunter2".to_string()));
    }

    #[tokio::test]
    async fn probe_loop_resets_failure_counter_on_success() {
        // Pattern: fail, fail, succeed, fail, fail -- should NOT clear
        // the pin because the success resets the counter and we never
        // reach fail_limit=3 consecutive failures.
        let pin = Arc::new(Mutex::new(Some("stable".to_string())));
        let guid = sample_guid();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_cl = counter.clone();
        let probe = move |_g: &Guid| {
            let n = counter_cl.fetch_add(1, Ordering::SeqCst);
            // Present on every 3rd call (index 2, 5, 8, ...).
            n % 3 == 2
        };

        run_probe_for_ticks(guid, pin.clone(), probe, 3).await;

        assert_eq!(*pin.lock().await, Some("stable".to_string()));
    }

    #[tokio::test]
    async fn probe_loop_no_op_when_pin_already_empty() {
        // If the PIN is None and the card is absent, the loop must
        // still exit cleanly and leave the PIN as None (no spurious
        // writes / panics).
        let pin: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let guid = sample_guid();
        let probe = |_g: &Guid| false;

        run_probe_for_ticks(guid, pin.clone(), probe, 3).await;

        assert_eq!(*pin.lock().await, None);
    }

    #[tokio::test]
    async fn probe_loop_passes_correct_guid_to_probe() {
        // The guid given to probe_loop must be the guid the probe
        // function receives -- regression guard against future
        // refactors that might accidentally drop it.
        let pin = Arc::new(Mutex::new(None));
        let guid = sample_guid();
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen_cl = seen.clone();
        let probe = move |g: &Guid| {
            seen_cl.lock().unwrap().push(g.to_hex());
            true
        };

        run_probe_for_ticks(guid.clone(), pin, probe, 3).await;

        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "probe should have been called at least once");
        for h in seen.iter() {
            assert_eq!(h, &guid.to_hex());
        }
    }
}
