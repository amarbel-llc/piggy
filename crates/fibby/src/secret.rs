//! A card secret held in guarded memory (FDR 0006 phase (c), piggy#382
//! item 3): slot keys, the PIN, the PUK, the management key and the
//! attestation key.
//!
//! Each [`Secret`] is one `piggy-guard` allocation: its own pages between
//! guard pages, locked against swap where the kernel allows it, left out
//! of core dumps and wiped in a forked child on Linux, and inaccessible
//! except while one operation reads it. An operation that needs the bytes
//! as an owned value (the crypto crates take arrays) gets a
//! [`zeroize::Zeroizing`] copy that lives for that operation only.
//!
//! An allocation or protection change that fails is a broken host, not a
//! card condition: fibby panics with the system call that failed rather
//! than serve a card whose secrets are not where it says they are.

use piggy_guard::{GuardedBytes, Protections};
use zeroize::Zeroizing;

pub struct Secret(GuardedBytes);

impl Secret {
    /// A sealed copy of `bytes`; the caller zeroizes its own copy.
    pub fn new(bytes: &[u8]) -> Self {
        Secret(
            GuardedBytes::from_slice(bytes)
                .unwrap_or_else(|e| panic!("fibby: cannot hold a secret in guarded memory: {e}")),
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What the kernel granted this secret's pages.
    pub fn protections(&self) -> Protections {
        self.0.protections()
    }

    /// Run `f` over the secret's bytes, its pages readable only meanwhile.
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        self.0
            .with(f)
            .unwrap_or_else(|e| panic!("fibby: cannot read a guarded secret: {e}"))
    }

    /// A zeroizing copy of the secret as an `N`-byte array, for one
    /// operation. Panics if the secret is not `N` bytes long (a
    /// programming error: every caller knows its secret's width).
    pub fn array<const N: usize>(&self) -> Zeroizing<[u8; N]> {
        let mut out = Zeroizing::new([0u8; N]);
        self.with(|bytes| out.copy_from_slice(bytes));
        out
    }

    /// Whether `candidate` equals the secret, comparing every byte
    /// whatever the first mismatch (no early exit on content).
    pub fn equals(&self, candidate: &[u8]) -> bool {
        self.with(|bytes| {
            bytes.len() == candidate.len()
                && bytes
                    .iter()
                    .zip(candidate)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
        })
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes, guarded)", self.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_reads_back_and_compares() {
        let s = Secret::new(b"12345678");
        assert_eq!(s.len(), 8);
        assert!(s.equals(b"12345678"));
        assert!(!s.equals(b"12345679"));
        assert!(!s.equals(b"1234567"), "a different length never matches");
        assert_eq!(*s.array::<8>(), *b"12345678");
    }

    #[test]
    fn debug_never_prints_the_bytes() {
        let s = Secret::new(b"piggy-test-secret");
        let shown = format!("{s:?}");
        assert!(!shown.contains("piggy-test"), "{shown}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_secret_is_left_out_of_core_dumps_on_linux() {
        assert!(Secret::new(&[1; 32]).protections().excluded_from_core_dumps);
    }
}
