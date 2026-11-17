//! Cancelling a request whose client has gone.
//!
//! The wire adapter makes one [`Cancel`] per request and gives a
//! [`CancelOnDrop`] to whatever the client's connection owns: the in-flight
//! request future while the proxy works, then the response body once it is
//! streaming. When hyper drops either because the client hung up, the guard
//! fires the [`Cancel`], and the upstream call (the dial, the handshake, the
//! wait for the response head, a read of the response body) stops and its
//! connection closes, instead of running to completion or to the head
//! timeout.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

#[derive(Default)]
struct State {
    cancelled: AtomicBool,
    notify: Notify,
}

/// A request's cancellation, shared by whoever may fire it and whoever must
/// stop. The default is one that nothing fires (a request without a
/// connection to lose, as in the unit tests).
#[derive(Clone, Default)]
pub struct Cancel(Arc<State>);

impl std::fmt::Debug for Cancel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cancel({})", self.is_cancelled())
    }
}

impl Cancel {
    /// Fire it. Idempotent.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        // One waiter per request; `notify_one` keeps a permit if the waiter
        // has not started waiting yet, so a cancel that races the wait is
        // not lost.
        self.0.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Resolves once [`Cancel::cancel`] has been called.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.0.notify.notified().await;
    }
}

/// Fires its [`Cancel`] when dropped.
pub struct CancelOnDrop(Cancel);

impl CancelOnDrop {
    pub fn new(cancel: Cancel) -> Self {
        Self(cancel)
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn a_fresh_cancel_is_not_cancelled_and_cancel_is_idempotent() {
        let c = Cancel::default();
        assert!(!c.is_cancelled());
        c.cancel();
        c.cancel();
        assert!(c.is_cancelled());
    }

    #[test]
    fn cancelled_resolves_at_once_when_already_fired() {
        let c = Cancel::default();
        c.cancel();
        runtime().block_on(async {
            tokio::time::timeout(Duration::from_secs(5), c.cancelled())
                .await
                .expect("an already-fired cancel resolves");
        });
    }

    #[test]
    fn cancelled_wakes_when_fired_from_another_thread() {
        let c = Cancel::default();
        let firer = c.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            firer.cancel();
        });
        runtime().block_on(async {
            tokio::time::timeout(Duration::from_secs(5), c.cancelled())
                .await
                .expect("a later cancel wakes the waiter");
        });
        t.join().unwrap();
    }

    #[test]
    fn dropping_the_guard_fires_the_cancel() {
        let c = Cancel::default();
        let guard = CancelOnDrop::new(c.clone());
        assert!(!c.is_cancelled());
        drop(guard);
        assert!(c.is_cancelled());
    }
}
