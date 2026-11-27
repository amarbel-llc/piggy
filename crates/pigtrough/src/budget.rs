//! The cap on request bodies held in memory, over every request and every
//! listener at once. A route's body limit bounds one request; this bounds
//! their sum, which the number of connections would otherwise multiply.
//!
//! A body is charged as its bytes arrive, never from the length a client
//! declares, so a client holds only as much as it has sent. The charge lives
//! with the buffer ([`Reservation::into_body`]) and ends when the last
//! handle on it is dropped. A body that does not fit is refused at once, not
//! queued. It counts body bytes only: buffer slack, the HTTP and TLS
//! libraries' own buffers and response bodies are outside it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;

/// The bytes of request bodies the binary holds at once.
pub const TOTAL_BUFFERED_BODIES: usize = 64 << 20;

/// How long a client may take to send one request body, so that a stalled
/// upload cannot keep its share of the budget.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);

pub struct BodyBudget {
    cap: usize,
    used: AtomicUsize,
    read_timeout: Option<Duration>,
}

impl Default for BodyBudget {
    fn default() -> Self {
        Self::new(TOTAL_BUFFERED_BODIES)
    }
}

impl BodyBudget {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            used: AtomicUsize::new(0),
            read_timeout: Some(BODY_READ_TIMEOUT),
        }
    }

    /// The budget `serve` is told to keep. Each value is the default when
    /// not given, and 0 turns that limit off, which is how things were
    /// before there was one.
    pub fn configured(cap_bytes: Option<usize>, read_timeout_seconds: Option<u64>) -> Self {
        let cap = match cap_bytes {
            None => TOTAL_BUFFERED_BODIES,
            Some(0) => usize::MAX,
            Some(bytes) => bytes,
        };
        let read_timeout = match read_timeout_seconds {
            None => Some(BODY_READ_TIMEOUT),
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
        };
        Self::new(cap).with_read_timeout(read_timeout)
    }

    /// Replace the time a body may take to arrive; `None` is no limit.
    pub fn with_read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_timeout = timeout;
        self
    }

    pub fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    /// The bytes charged now.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }

    /// An empty charge against this budget.
    pub fn reservation(self: &Arc<Self>) -> Reservation {
        Reservation {
            budget: self.clone(),
            held: 0,
        }
    }
}

/// One body's charge, given back when it is dropped.
pub struct Reservation {
    budget: Arc<BodyBudget>,
    held: usize,
}

impl Reservation {
    /// Charge `more` bytes, or charge nothing and answer `false` if they do
    /// not fit.
    #[must_use]
    pub fn grow(&mut self, more: usize) -> bool {
        let cap = self.budget.cap;
        let fits = self
            .budget
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(more).filter(|total| *total <= cap)
            })
            .is_ok();
        if fits {
            self.held += more;
        }
        fits
    }

    /// `data` as a shared buffer that keeps this charge until its last clone
    /// is dropped, wherever that is: an upstream client may still be writing
    /// the body after the request path has returned.
    pub fn into_body(self, data: Vec<u8>) -> Bytes {
        Bytes::from_owner(Charged {
            data,
            _charge: self,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.held, Ordering::SeqCst);
    }
}

struct Charged {
    data: Vec<u8>,
    _charge: Reservation,
}

impl AsRef<[u8]> for Charged {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges_up_to_the_cap_and_gives_back_on_drop() {
        let budget = Arc::new(BodyBudget::new(10));
        let mut a = budget.reservation();
        assert!(a.grow(6));
        let mut b = budget.reservation();
        assert!(!b.grow(5), "does not fit");
        assert_eq!(budget.used(), 6, "a refused charge takes nothing");
        assert!(b.grow(4));
        assert!(!b.grow(usize::MAX), "no overflow");
        drop(a);
        assert_eq!(budget.used(), 4);
        drop(b);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn configured_tells_unset_from_off() {
        let unset = Arc::new(BodyBudget::configured(None, None));
        assert!(!unset.reservation().grow(TOTAL_BUFFERED_BODIES + 1));
        assert_eq!(unset.read_timeout(), Some(BODY_READ_TIMEOUT));

        let off = Arc::new(BodyBudget::configured(Some(0), Some(0)));
        assert!(off.reservation().grow(TOTAL_BUFFERED_BODIES + 1));
        assert_eq!(off.read_timeout(), None);

        let set = Arc::new(BodyBudget::configured(Some(7), Some(9)));
        assert!(!set.reservation().grow(8));
        assert!(set.reservation().grow(7));
        assert_eq!(set.read_timeout(), Some(Duration::from_secs(9)));
    }

    #[test]
    fn the_charge_lives_as_long_as_the_last_handle_on_the_body() {
        let budget = Arc::new(BodyBudget::new(10));
        let mut charge = budget.reservation();
        assert!(charge.grow(3));
        let body = charge.into_body(b"abc".to_vec());
        let held_elsewhere = body.clone();
        drop(body);
        assert_eq!(budget.used(), 3);
        assert_eq!(&held_elsewhere[..], b"abc");
        drop(held_elsewhere);
        assert_eq!(budget.used(), 0);
    }
}
