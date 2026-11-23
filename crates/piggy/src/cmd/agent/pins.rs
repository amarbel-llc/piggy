//! Per-card, per-slot PIN cache for `piggy agent` (piggy#177, piggy#404).
//!
//! The cache used to be one global `Option<String>`: whichever PIN was
//! verified last was tried on every card. Under `-A` (or any agent
//! serving two cards) with cards holding *different* PINs, every
//! alternation between cards first VERIFYed the other card's PIN — one
//! wrong attempt on the card (retry counter 3→2, reset by the following
//! success, so no lockout), a forced re-prompt, and the same dance on the
//! way back. This keys verified PINs by the card they verified on, and
//! models the one source of a PIN that arrives without a card —
//! `ssh-add -X` (`SSH_AGENTC_UNLOCK`) — as an *offer*: tried at most once
//! per card, promoted to that card's verified PIN on success, and never
//! re-offered to a card that rejected it.
//!
//! Since piggy#404 a PIN is also keyed by the SLOT it was typed for, and each
//! slot has its own rule ([`super::pin_policy`]: never, or so long idle and so
//! long in all). The PIV PIN is the card's, but a PIN typed to log in over ssh
//! (9A) must not quietly decrypt the store (9D) or sign (9C): a request on
//! another slot asks again. The rule is read when a PIN is cached, and the
//! entry keeps its own limits.
//!
//! Pure data structure, no IO: the session decides when to verify, and
//! the probe loop decides when a card is gone. Time is an argument (`*_at`),
//! so the tests drive it without sleeping.
//!
//! Each PIN is held in a [`GuardedBytes`] (FDR 0006 phase (b), piggy#378):
//! its own locked pages, out of core dumps, inaccessible between lookups.
//! A lookup hands out a short-lived `Zeroizing` copy for one VERIFY. If a
//! PIN cannot be put on guarded pages it is not cached at all, and the next
//! op prompts again; that is logged as a warning.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use piggy_guard::GuardedBytes;
use piggy_piv::Guid;
use zeroize::Zeroizing;

use super::pin_policy::{CacheRule, PinCachePolicy};

fn guard(pin: &str) -> Option<GuardedBytes> {
    GuardedBytes::from_slice(pin.as_bytes())
        .inspect_err(
            |e| tracing::warn!(error = %e, "could not hold a PIN on guarded pages; not caching it"),
        )
        .ok()
}

fn copy_out(pin: &GuardedBytes) -> Option<Zeroizing<String>> {
    pin.with(|bytes| {
        Zeroizing::new(String::from(
            std::str::from_utf8(bytes).expect("a cached PIN is stored from a &str"),
        ))
    })
    .inspect_err(|e| tracing::warn!(error = %e, "could not read a cached PIN"))
    .ok()
}

/// Where an [`PinCache::lookup`] hit came from; the caller caches a PIN
/// into the per-card map only after an on-card verify succeeds, so a
/// wrong offered PIN is never promoted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinSource {
    /// Already verified on this very card — trust it.
    Verified,
    /// From `ssh-add -X`, not yet tried on this card — verify before caching.
    Offered,
}

/// One PIN typed for one slot of one card, with the limits it was cached under.
struct Entry {
    pin: GuardedBytes,
    cached_at: Instant,
    last_used: Instant,
    idle: Option<Duration>,
    cap: Option<Duration>,
}

impl Entry {
    fn expired(&self, now: Instant) -> bool {
        self.idle
            .is_some_and(|idle| now.saturating_duration_since(self.last_used) >= idle)
            || self
                .cap
                .is_some_and(|cap| now.saturating_duration_since(self.cached_at) >= cap)
    }
}

pub struct PinCache {
    policy: PinCachePolicy,
    /// PINs that verified on-card, keyed by the card and the slot they were
    /// typed for.
    verified: HashMap<(Guid, u8), Entry>,
    /// The `ssh-add -X` PIN, not tied to a card until it verifies on one.
    offered: Option<GuardedBytes>,
    /// Cards that rejected the current `offered` PIN — don't burn another
    /// retry re-offering it there.
    offered_rejected_by: HashSet<Guid>,
}

impl Default for PinCache {
    fn default() -> Self {
        Self::with_policy_inner(PinCachePolicy::compiled_in())
    }
}

impl PinCache {
    /// A cache under the table compiled into this binary.
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache under a table of the tests' own (no such constructor ships).
    #[cfg(test)]
    pub fn with_policy(policy: PinCachePolicy) -> Self {
        Self::with_policy_inner(policy)
    }

    fn with_policy_inner(policy: PinCachePolicy) -> Self {
        Self {
            policy,
            verified: HashMap::new(),
            offered: None,
            offered_rejected_by: HashSet::new(),
        }
    }

    /// The PIN to try for `slot` of `guid`, if any: the one typed for this
    /// very slot first (and not past its limits), else the offered one (unless
    /// this card already rejected it, or the slot is never cached). A hit
    /// counts as a use for the idle limit.
    pub fn lookup(&mut self, guid: &Guid, slot: u8) -> Option<(Zeroizing<String>, PinSource)> {
        self.lookup_at(guid, slot, Instant::now())
    }

    pub fn lookup_at(
        &mut self,
        guid: &Guid,
        slot: u8,
        now: Instant,
    ) -> Option<(Zeroizing<String>, PinSource)> {
        if self.policy.rule(slot) == CacheRule::Never {
            return None;
        }
        let key = (guid.clone(), slot);
        if let Some(entry) = self.verified.get_mut(&key) {
            if entry.expired(now) {
                self.verified.remove(&key);
            } else {
                entry.last_used = now;
                return copy_out(&entry.pin).map(|pin| (pin, PinSource::Verified));
            }
        }
        match &self.offered {
            Some(p) if !self.offered_rejected_by.contains(guid) => {
                copy_out(p).map(|pin| (pin, PinSource::Offered))
            }
            _ => None,
        }
    }

    /// Record that `pin` verified on `guid` for `slot` (a prompted PIN, or a
    /// promoted offer), under the slot's rule. A slot that is never cached
    /// records nothing.
    pub fn cache_verified(&mut self, guid: &Guid, slot: u8, pin: &str) {
        self.cache_verified_at(guid, slot, pin, Instant::now());
    }

    pub fn cache_verified_at(&mut self, guid: &Guid, slot: u8, pin: &str, now: Instant) {
        let (idle, cap) = match self.policy.rule(slot) {
            CacheRule::Never => return,
            CacheRule::For { idle, cap } => (idle, cap),
        };
        self.store(guid, slot, pin, now, idle, cap);
    }

    /// The holder's own PIN for the card it minted: nobody types it and it
    /// is never prompted for, so it is kept until the card leaves whatever the
    /// table says.
    pub fn cache_verified_unlimited(&mut self, guid: &Guid, slot: u8, pin: &str) {
        self.store(guid, slot, pin, Instant::now(), None, None);
    }

    fn store(
        &mut self,
        guid: &Guid,
        slot: u8,
        pin: &str,
        now: Instant,
        idle: Option<Duration>,
        cap: Option<Duration>,
    ) {
        let key = (guid.clone(), slot);
        match guard(pin) {
            Some(guarded) => {
                self.verified.insert(
                    key,
                    Entry {
                        pin: guarded,
                        cached_at: now,
                        last_used: now,
                        idle,
                        cap,
                    },
                );
            }
            None => {
                self.verified.remove(&key);
            }
        }
    }

    /// `guid` rejected the PIN it was just given (piggy#142 re-prompt
    /// path): drop its verified PINs, for every slot (the PIN is the card's,
    /// so none can still be right), and stop offering the `ssh-add -X` PIN to
    /// it. Other cards' verified PINs are untouched — that is the whole point
    /// of keying by card.
    pub fn forget_for(&mut self, guid: &Guid) {
        self.verified.retain(|(g, _), _| g != guid);
        self.offered_rejected_by.insert(guid.clone());
    }

    /// `guid` disappeared (probe loop): drop its verified PINs. The offered
    /// PIN is dropped too — it is an unverified blob and may well have been
    /// meant for the card that just left; re-offering it elsewhere later is
    /// the surprising direction.
    pub fn forget_card(&mut self, guid: &Guid) -> bool {
        let before = self.verified.len();
        self.verified.retain(|(g, _), _| g != guid);
        let had = self.verified.len() != before || self.offered.is_some();
        self.offered = None;
        self.offered_rejected_by.clear();
        had
    }

    /// `ssh-add -X <pin>`: offer `pin` to every card that has no verified
    /// PIN. Replaces a previous offer and forgets who rejected that one.
    pub fn offer(&mut self, pin: &str) {
        self.offered = guard(pin);
        self.offered_rejected_by.clear();
    }

    /// `ssh-add -x`: forget everything.
    pub fn clear(&mut self) {
        self.verified.clear();
        self.offered = None;
        self.offered_rejected_by.clear();
    }

    /// Anything cached at all (the `pin-status@joyent.com` `has_pin` bit).
    pub fn has_any(&self) -> bool {
        !self.verified.is_empty() || self.offered.is_some()
    }

    /// The table this cache runs under, one line per named slot.
    pub fn describe_policy(&self) -> Vec<String> {
        self.policy.describe()
    }

    /// Test accessor: the verified PIN for `slot` of `guid`.
    #[cfg(test)]
    pub fn verified_for(&self, guid: &Guid, slot: u8) -> Option<String> {
        self.verified
            .get(&(guid.clone(), slot))
            .and_then(|e| copy_out(&e.pin))
            .map(|p| p.to_string())
    }

    /// Test accessor: the current `ssh-add -X` offer.
    #[cfg(test)]
    pub fn offered(&self) -> Option<String> {
        self.offered
            .as_ref()
            .and_then(copy_out)
            .map(|p| p.to_string())
    }

    /// Test accessor: what the kernel granted each held PIN.
    #[cfg(test)]
    fn protections(&self) -> Vec<piggy_guard::Protections> {
        self.verified
            .values()
            .map(|e| &e.pin)
            .chain(&self.offered)
            .map(GuardedBytes::protections)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(seed: u8) -> Guid {
        Guid::from_bytes(&[seed; 16]).unwrap()
    }

    const A: u8 = 0x9A;
    const C: u8 = 0x9C;
    const D: u8 = 0x9D;

    /// A test-only table with short values: nothing here is the shipped one.
    fn short_table() -> PinCache {
        PinCache::with_policy(PinCachePolicy::for_test_table(&[
            (A, CacheRule::idle_secs(100)),
            (C, CacheRule::Never),
            (D, CacheRule::idle_secs_cap_secs(10, 30)),
            (0x83, CacheRule::idle_secs(100)),
        ]))
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn empty_cache_has_nothing() {
        let mut c = PinCache::new();
        assert!(!c.has_any());
        assert!(c.lookup(&g(1), A).is_none());
    }

    /// The #177 scenario: two cards, two PINs. Card A's verified PIN is
    /// never handed out for card B, and vice versa.
    #[test]
    fn verified_pins_are_per_card() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), A, "1111");
        c.cache_verified(&g(2), A, "2222");
        assert_eq!(
            c.lookup(&g(1), A),
            Some((Zeroizing::new("1111".into()), PinSource::Verified))
        );
        assert_eq!(
            c.lookup(&g(2), A),
            Some((Zeroizing::new("2222".into()), PinSource::Verified))
        );
        assert!(c.lookup(&g(3), A).is_none(), "a third card gets nothing");
    }

    /// piggy#404: the defect. A PIN typed for 9A never satisfies a 9D or 9C
    /// request on the same card; each slot is asked for its own.
    #[test]
    fn a_pin_typed_for_one_slot_does_not_satisfy_another() {
        let mut c = short_table();
        let now = Instant::now();
        c.cache_verified_at(&g(1), A, "1111", now);
        assert!(c.lookup_at(&g(1), A, now).is_some());
        assert!(c.lookup_at(&g(1), D, now).is_none(), "9A PIN for 9D");
        assert!(c.lookup_at(&g(1), C, now).is_none(), "9A PIN for 9C");
        // And the other way: 9D's does not serve 9A once 9A's is gone.
        c.cache_verified_at(&g(2), D, "2222", now);
        assert!(c.lookup_at(&g(2), A, now).is_none(), "9D PIN for 9A");
    }

    #[test]
    fn a_never_cached_slot_keeps_nothing() {
        let mut c = short_table();
        c.cache_verified(&g(1), C, "1111");
        assert!(!c.has_any());
        assert!(c.lookup(&g(1), C).is_none());
        // Not a slot the table names: also never.
        c.cache_verified(&g(1), 0x84, "1111");
        assert!(!c.has_any());
    }

    #[test]
    fn the_authority_slots_keep_nothing_even_if_a_table_says_so() {
        let mut c = short_table();
        c.cache_verified(&g(1), 0x83, "1111");
        c.cache_verified(&g(1), 0x82, "1111");
        assert!(!c.has_any());
        assert!(c.lookup(&g(1), 0x83).is_none());
    }

    #[test]
    fn idle_expiry_counts_from_the_last_use() {
        let mut c = short_table();
        let t0 = Instant::now();
        c.cache_verified_at(&g(1), D, "1111", t0);
        // Used at 8 s: still there, and the idle clock restarts.
        assert!(c.lookup_at(&g(1), D, t0 + secs(8)).is_some());
        assert!(
            c.lookup_at(&g(1), D, t0 + secs(16)).is_some(),
            "8 s after the last use is inside the 10 s idle window"
        );
        // 10 s with no use: gone, and gone for good.
        assert!(c.lookup_at(&g(1), D, t0 + secs(26)).is_none());
        assert!(c.verified_for(&g(1), D).is_none());
    }

    #[test]
    fn the_cap_ends_it_however_busy() {
        let mut c = short_table();
        let t0 = Instant::now();
        c.cache_verified_at(&g(1), D, "1111", t0);
        for step in [8, 16, 24] {
            assert!(
                c.lookup_at(&g(1), D, t0 + secs(step)).is_some(),
                "inside the cap at {step} s"
            );
        }
        // 32 s after it was typed: past the 30 s cap although used 8 s ago.
        assert!(c.lookup_at(&g(1), D, t0 + secs(32)).is_none());
    }

    #[test]
    fn a_slot_without_a_cap_is_only_idle_limited() {
        let mut c = short_table();
        let t0 = Instant::now();
        c.cache_verified_at(&g(1), A, "1111", t0);
        for step in (50..=500).step_by(50) {
            assert!(c.lookup_at(&g(1), A, t0 + secs(step)).is_some(), "{step}");
        }
    }

    #[test]
    fn the_holders_own_pin_is_kept_whatever_the_table_says() {
        let mut c = short_table();
        c.cache_verified_unlimited(&g(1), 0x9A, "1111");
        assert!(c
            .lookup_at(&g(1), 0x9A, Instant::now() + secs(1_000_000))
            .is_some());
    }

    #[test]
    fn offer_is_handed_to_any_unverified_card_as_offered() {
        let mut c = PinCache::new();
        c.offer("9999");
        assert_eq!(
            c.lookup(&g(1), A),
            Some((Zeroizing::new("9999".into()), PinSource::Offered))
        );
        assert_eq!(
            c.lookup(&g(2), A),
            Some((Zeroizing::new("9999".into()), PinSource::Offered))
        );
        // A card with its own verified PIN keeps it over the offer.
        c.cache_verified(&g(2), A, "2222");
        assert_eq!(
            c.lookup(&g(2), A),
            Some((Zeroizing::new("2222".into()), PinSource::Verified))
        );
    }

    /// The offer is a cache entry too: a slot that is never cached does not
    /// get it.
    #[test]
    fn the_offer_is_not_handed_to_a_never_cached_slot() {
        let mut c = short_table();
        c.offer("9999");
        assert!(c.lookup(&g(1), C).is_none());
        assert!(c.lookup(&g(1), 0x83).is_none());
        assert!(c.lookup(&g(1), A).is_some());
    }

    /// A card that rejected the offer is never offered it again (no
    /// second burned retry), but OTHER cards still get it.
    #[test]
    fn rejected_offer_is_not_reoffered_to_that_card_only() {
        let mut c = PinCache::new();
        c.offer("9999");
        c.forget_for(&g(1));
        assert!(c.lookup(&g(1), A).is_none());
        assert_eq!(
            c.lookup(&g(2), A),
            Some((Zeroizing::new("9999".into()), PinSource::Offered))
        );
        // A fresh offer resets the rejection list.
        c.offer("8888");
        assert_eq!(
            c.lookup(&g(1), A),
            Some((Zeroizing::new("8888".into()), PinSource::Offered))
        );
    }

    #[test]
    fn forget_for_drops_every_slots_pin_of_that_card_only() {
        let mut c = short_table();
        c.cache_verified(&g(1), A, "1111");
        c.cache_verified(&g(1), D, "1111");
        c.cache_verified(&g(2), A, "2222");
        c.forget_for(&g(1));
        assert!(c.lookup(&g(1), A).is_none());
        assert!(c.lookup(&g(1), D).is_none());
        assert_eq!(c.verified_for(&g(2), A).as_deref(), Some("2222"));
    }

    #[test]
    fn forget_card_drops_its_pins_and_the_unverified_offer() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), A, "1111");
        c.cache_verified(&g(2), A, "2222");
        c.offer("9999");
        assert!(c.forget_card(&g(1)));
        assert!(c.lookup(&g(1), A).is_none());
        assert!(c.offered().is_none());
        assert_eq!(
            c.verified_for(&g(2), A).as_deref(),
            Some("2222"),
            "other card untouched"
        );
        // Nothing left for g(1): reports false (no-op) — the probe loop
        // uses this to decide whether to log "forgetting PIN".
        assert!(!c.forget_card(&g(1)));
    }

    /// Each held PIN is on its own guarded allocation: locked (where
    /// RLIMIT_MEMLOCK allows), and out of core dumps on Linux. That a lock
    /// grows VmLck by a page is piggy-guard's tests/locked_memory.rs.
    #[test]
    fn each_cached_pin_is_held_on_guarded_pages() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), A, "1111");
        c.cache_verified(&g(2), A, "2222");
        c.offer("9999");
        let held = c.protections();
        assert_eq!(held.len(), 3);
        for p in &held {
            assert_eq!(
                p.excluded_from_core_dumps,
                cfg!(target_os = "linux"),
                "{p:?}"
            );
        }
        if !held.iter().all(|p| p.locked) {
            eprintln!("skipped the lock check: mlock was refused here (RLIMIT_MEMLOCK): {held:?}");
        }
    }

    #[test]
    fn clear_forgets_everything() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), A, "1111");
        c.offer("9999");
        c.clear();
        assert!(!c.has_any());
        assert!(c.lookup(&g(1), A).is_none());
    }
}
