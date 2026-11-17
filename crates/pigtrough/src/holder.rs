//! The secret holder: one route's credential in guarded memory.
//!
//! A `load` replaces the held secret whole. A request takes an
//! [`Arc`] to the secret it started with, so a request in flight during a
//! reload finishes on the old secret and the next request uses the new one
//! (behaviour 8). The old secret's pages are wiped when its last request
//! drops it.

use std::fmt;
use std::sync::{Arc, RwLock};

use piggy_guard::{GuardError, GuardedBytes};

pub struct SecretHolder {
    current: RwLock<Option<Arc<GuardedBytes>>>,
}

/// A route with its own secret holder: the unit `serve` mounts, the proxy
/// decorates with and `load` fills.
#[derive(Clone)]
pub struct Mount {
    pub route: &'static crate::route::Route,
    pub holder: Arc<SecretHolder>,
}

impl Mount {
    /// A mount whose holder starts empty.
    pub fn empty(route: &'static crate::route::Route) -> Self {
        Self {
            route,
            holder: Arc::new(SecretHolder::empty()),
        }
    }
}

#[derive(Debug)]
pub enum LoadError {
    /// Nothing to load.
    Empty,
    /// A byte that cannot go into a header value as is (a space, a control
    /// byte, a non-ASCII byte). Refused rather than escaped, so a stray
    /// newline cannot split the outbound header.
    NotAToken,
    Guard(GuardError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Empty => f.write_str("the secret is empty"),
            LoadError::NotAToken => {
                f.write_str("the secret holds a byte that is not a visible ASCII character")
            }
            LoadError::Guard(e) => write!(f, "guarded memory: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl SecretHolder {
    /// A holder with nothing loaded: every request answers
    /// `secret-unavailable` until the first `load`.
    pub fn empty() -> Self {
        Self {
            current: RwLock::new(None),
        }
    }

    /// Replace the held secret. `piggy pass show` ends its line with a
    /// newline; one trailing `\n` or `\r\n` is dropped, nothing else is.
    pub fn load(&self, input: &[u8]) -> Result<(), LoadError> {
        let token = strip_one_line_ending(input);
        if token.is_empty() {
            return Err(LoadError::Empty);
        }
        if !token.iter().all(|b| (0x21..=0x7e).contains(b)) {
            return Err(LoadError::NotAToken);
        }
        let guarded = GuardedBytes::from_slice(token).map_err(LoadError::Guard)?;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(guarded));
        Ok(())
    }

    /// The secret a request should use, if one is loaded.
    pub fn current(&self) -> Option<Arc<GuardedBytes>> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

fn strip_one_line_ending(input: &[u8]) -> &[u8] {
    input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(holder: &SecretHolder) -> Option<Vec<u8>> {
        holder.current().map(|s| s.with(|b| b.to_vec()).unwrap())
    }

    #[test]
    fn starts_empty() {
        assert!(SecretHolder::empty().current().is_none());
    }

    #[test]
    fn load_strips_one_line_ending() {
        let h = SecretHolder::empty();
        h.load(b"piggy-test-token\n").unwrap();
        assert_eq!(held(&h).unwrap(), b"piggy-test-token");
        h.load(b"piggy-test-token\r\n").unwrap();
        assert_eq!(held(&h).unwrap(), b"piggy-test-token");
    }

    #[test]
    fn load_refuses_what_could_split_a_header() {
        let h = SecretHolder::empty();
        assert!(matches!(h.load(b""), Err(LoadError::Empty)));
        assert!(matches!(h.load(b"\n"), Err(LoadError::Empty)));
        assert!(matches!(h.load(b"a\n\n"), Err(LoadError::NotAToken)));
        assert!(matches!(
            h.load(b"a\r\nX-Evil: 1"),
            Err(LoadError::NotAToken)
        ));
        assert!(matches!(h.load(b"a b"), Err(LoadError::NotAToken)));
        assert!(
            h.current().is_none(),
            "a refused load leaves the holder as it was"
        );
    }

    #[test]
    fn reload_keeps_the_old_secret_alive_for_its_holders() {
        let h = SecretHolder::empty();
        h.load(b"piggy-test-old").unwrap();
        let in_flight = h.current().unwrap();
        h.load(b"piggy-test-new").unwrap();
        assert_eq!(in_flight.with(|b| b.to_vec()).unwrap(), b"piggy-test-old");
        assert_eq!(held(&h).unwrap(), b"piggy-test-new");
    }
}
