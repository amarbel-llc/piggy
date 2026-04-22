use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

use pivy_piv::{Guid, PivContext};

const PROBE_INTERVAL: Duration = Duration::from_secs(60);
const PROBE_FAIL_LIMIT: u32 = 3;

/// Background task that periodically probes the PIV card.
/// Forgets the cached PIN if the card disappears.
pub async fn probe_loop(guid: Guid, pin: Arc<Mutex<Option<String>>>) {
    let mut failures: u32 = 0;
    let mut interval = interval(PROBE_INTERVAL);

    loop {
        interval.tick().await;

        let card_present = match PivContext::new() {
            Ok(ctx) => match ctx.enumerate_tokens() {
                Ok(tokens) => tokens.iter().any(|t| *t.guid() == guid),
                Err(_) => false,
            },
            Err(_) => false,
        };

        if card_present {
            failures = 0;
        } else {
            failures += 1;
            if failures >= PROBE_FAIL_LIMIT {
                let mut pin_guard = pin.lock().await;
                if pin_guard.is_some() {
                    tracing::warn!("card unavailable after {} probes, forgetting PIN", failures);
                    *pin_guard = None;
                }
            }
        }
    }
}
