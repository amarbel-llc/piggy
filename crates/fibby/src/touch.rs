//! Simulated physical touch for touch-policy slots (FDR 0006, the minimal
//! test-surface cut of phase (c)).
//!
//! A YubiKey slot whose touch policy is `always` or `cached` does not
//! complete a private-key operation until its button is pressed. fibby
//! has no button, so a touch is *granted* over the control socket
//! (`fibby ctl touch <reader>`) and held in a [`TouchPad`] until the next
//! touch-requiring operation on that card consumes it.
//!
//! Locking: the pad has its own mutex and condition variable, separate
//! from the card's backend mutex. A connection thread that must wait for
//! a touch releases the backend mutex first and parks on the pad alone
//! (see `server::transmit_waiting_for_touch`), so the control socket can
//! still lock the card to deliver the touch and no other card or client
//! is stalled. The only nesting is backend mutex, then pad mutex, never
//! the reverse.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How long a touch-requiring operation waits for a touch before failing.
/// Overridden per fibby start by `--touch-timeout-ms`.
pub const DEFAULT_TOUCH_TIMEOUT: Duration = Duration::from_secs(15);

/// How long one touch keeps satisfying a `cached` slot, in wall time.
/// The YubicoPIV figure (`YKPIV_TOUCH_CACHED`, "Cached for 15sec",
/// vendor/pivy/src/piv.h).
pub const TOUCH_CACHE_WINDOW: Duration = Duration::from_secs(15);

#[derive(Default)]
struct PadState {
    /// Touches granted and not yet consumed by an operation.
    pending: u32,
    /// Per slot: end of the window in which that `cached` slot needs no
    /// fresh touch. Per key, as on a YubiKey: a touch that opened 9A's
    /// window does not serve 9C.
    cached_until: HashMap<u8, Instant>,
    /// Bumped on every change a blocked operation could be waiting for
    /// (a grant, or a cache window opening). A waiter records the value
    /// it saw when it blocked and sleeps until it moves, so a grant that
    /// lands between "blocked" and "asleep" is never lost.
    generation: u64,
}

/// One card's touch state. Shared (`Arc`) between the card and whichever
/// connection threads are waiting on it.
#[derive(Default)]
pub struct TouchPad {
    state: Mutex<PadState>,
    changed: Condvar,
}

/// How a touch-requiring operation got past the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPass {
    /// It consumed a pending granted touch.
    Granted,
    /// It rode an earlier touch still inside the `cached` window.
    Cached,
}

impl TouchPad {
    /// Grant one touch. Returns how many are now pending.
    pub fn grant(&self) -> u32 {
        let mut state = self.state.lock().unwrap();
        state.pending += 1;
        state.generation += 1;
        self.changed.notify_all();
        state.pending
    }

    /// Try to satisfy one touch-requiring operation on `slot` at time
    /// `now`, without blocking. `cached_policy` is true for a
    /// touch-`cached` slot, false for touch-`always`. On failure returns
    /// the pad generation to wait on with [`Self::wait_for_change`].
    pub fn try_consume(
        &self,
        slot: u8,
        cached_policy: bool,
        now: Instant,
    ) -> Result<TouchPass, u64> {
        let mut state = self.state.lock().unwrap();
        if cached_policy
            && state
                .cached_until
                .get(&slot)
                .is_some_and(|until| now < *until)
        {
            return Ok(TouchPass::Cached);
        }
        if state.pending == 0 {
            return Err(state.generation);
        }
        state.pending -= 1;
        if cached_policy {
            state.cached_until.insert(slot, now + TOUCH_CACHE_WINDOW);
            // A second operation blocked on the same cached slot can now
            // ride this touch: wake it.
            state.generation += 1;
            self.changed.notify_all();
        }
        Ok(TouchPass::Granted)
    }

    /// Block until the pad changes from generation `seen` or `deadline`
    /// passes. Returns true when it changed (the caller retries the
    /// operation), false on timeout.
    pub fn wait_for_change(&self, seen: u64, deadline: Instant) -> bool {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.generation != seen {
                return true;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            if left.is_zero() {
                return false;
            }
            state = self.changed.wait_timeout(state, left).unwrap().0;
        }
    }

    /// Close every slot's `cached` window (card removed, factory reset).
    /// Pending grants are kept: a grant models the operator's finger, not
    /// card state.
    pub fn clear_cache(&self) {
        self.state.lock().unwrap().cached_until.clear();
    }

    /// Touches granted and not yet consumed.
    pub fn pending(&self) -> u32 {
        self.state.lock().unwrap().pending
    }
}

/// What a connection thread needs to wait for a touch after the card
/// reported the operation blocked: the pad to park on, the generation the
/// card saw, and what to answer if no touch arrives.
pub struct TouchWait {
    pub pad: Arc<TouchPad>,
    /// Pad generation observed, under the card's lock, when it blocked.
    pub seen: u64,
    /// How long the whole operation may wait.
    pub timeout: Duration,
    /// Slot label for the log lines (`9A`, `9C`, ...).
    pub slot_label: String,
    /// The response APDU for a touch that never came (status word only).
    pub timeout_response: Vec<u8>,
}

/// The three log lines of a blocked touch, in one place so the card's
/// non-waiting path and the server's waiting path cannot drift apart.
/// Emitted at INFO so they show at every enabled `FIBBY_LOG` level.
pub fn log_touch_needed(slot_label: &str, detail: &str) {
    crate::trace::emit(
        crate::trace::INFO,
        "vcard",
        &format!("TOUCH needed {slot_label} ({detail})"),
    );
}

/// See [`log_touch_needed`]. The client that was waiting went away, so
/// the operation is dropped untried and any touch is left pending for the
/// next live operation.
pub fn log_touch_abandoned(slot_label: &str) {
    crate::trace::emit(
        crate::trace::INFO,
        "vcard",
        &format!("TOUCH abandoned {slot_label} (client gone)"),
    );
}

/// See [`log_touch_needed`]. `response` is the status word answered.
pub fn log_touch_timeout(slot_label: &str, response: &[u8]) {
    let sw: String = response.iter().map(|b| format!("{b:02X}")).collect();
    crate::trace::emit(
        crate::trace::INFO,
        "vcard",
        &format!("TOUCH timeout {slot_label} -> {sw}"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_policy_consumes_one_grant_per_operation() {
        let pad = TouchPad::default();
        let now = Instant::now();
        assert!(pad.try_consume(0x9A, false, now).is_err(), "no touch yet");
        assert_eq!(pad.grant(), 1);
        assert_eq!(pad.try_consume(0x9A, false, now), Ok(TouchPass::Granted));
        assert!(
            pad.try_consume(0x9A, false, now).is_err(),
            "one grant serves one touch-always operation"
        );
    }

    #[test]
    fn cached_policy_rides_one_touch_for_the_window_only() {
        let pad = TouchPad::default();
        let t0 = Instant::now();
        pad.grant();
        assert_eq!(pad.try_consume(0x9A, true, t0), Ok(TouchPass::Granted));
        assert_eq!(
            pad.try_consume(
                0x9A,
                true,
                t0 + TOUCH_CACHE_WINDOW - Duration::from_millis(1)
            ),
            Ok(TouchPass::Cached),
            "inside the window no fresh touch is needed"
        );
        assert!(
            pad.try_consume(0x9A, true, t0 + TOUCH_CACHE_WINDOW)
                .is_err(),
            "the window has closed"
        );
        assert!(
            pad.try_consume(0x9A, false, t0).is_err(),
            "a cached touch never serves a touch-always slot"
        );
    }

    /// YubiKey's `cached` window is per key: a touch on 9A does not let a
    /// 9C operation through, and each slot's window runs on its own clock.
    #[test]
    fn cached_window_is_per_slot() {
        let pad = TouchPad::default();
        let t0 = Instant::now();
        pad.grant();
        assert_eq!(pad.try_consume(0x9A, true, t0), Ok(TouchPass::Granted));
        assert!(
            pad.try_consume(0x9C, true, t0).is_err(),
            "9A's window does not serve 9C"
        );
        let t1 = t0 + Duration::from_secs(10);
        pad.grant();
        assert_eq!(pad.try_consume(0x9C, true, t1), Ok(TouchPass::Granted));
        let t2 = t0 + TOUCH_CACHE_WINDOW;
        assert!(
            pad.try_consume(0x9A, true, t2).is_err(),
            "9A's window closed"
        );
        assert_eq!(
            pad.try_consume(0x9C, true, t2),
            Ok(TouchPass::Cached),
            "9C's window, opened later, is still open"
        );
    }

    #[test]
    fn clear_cache_closes_the_window_and_keeps_grants() {
        let pad = TouchPad::default();
        let t0 = Instant::now();
        pad.grant();
        pad.grant();
        assert_eq!(pad.try_consume(0x9A, true, t0), Ok(TouchPass::Granted));
        pad.clear_cache();
        assert_eq!(pad.pending(), 1, "the unconsumed grant survives");
        assert_eq!(
            pad.try_consume(0x9A, true, t0),
            Ok(TouchPass::Granted),
            "with the window closed the next operation needs a touch again"
        );
    }

    #[test]
    fn wait_returns_at_once_for_a_grant_that_beat_the_waiter() {
        let pad = TouchPad::default();
        let seen = pad.try_consume(0x9A, false, Instant::now()).unwrap_err();
        pad.grant(); // lands before the waiter parks
        assert!(pad.wait_for_change(seen, Instant::now() + Duration::from_secs(5)));
    }

    #[test]
    fn wait_times_out_when_nothing_changes() {
        let pad = TouchPad::default();
        let seen = pad.try_consume(0x9A, false, Instant::now()).unwrap_err();
        let start = Instant::now();
        assert!(!pad.wait_for_change(seen, start + Duration::from_millis(40)));
        assert!(start.elapsed() >= Duration::from_millis(40));
    }
}
