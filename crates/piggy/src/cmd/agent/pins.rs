//! Per-card PIN cache for `piggy agent` (piggy#177).
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
//! Pure data structure, no IO: the session decides when to verify, and
//! the probe loop decides when a card is gone.

use std::collections::{HashMap, HashSet};

use piggy_piv::Guid;
use zeroize::Zeroizing;

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

#[derive(Default)]
pub struct PinCache {
    /// PINs that verified on-card, keyed by the card they verified on.
    verified: HashMap<Guid, Zeroizing<String>>,
    /// The `ssh-add -X` PIN, not tied to a card until it verifies on one.
    offered: Option<Zeroizing<String>>,
    /// Cards that rejected the current `offered` PIN — don't burn another
    /// retry re-offering it there.
    offered_rejected_by: HashSet<Guid>,
}

impl PinCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The PIN to try for `guid`, if any: its own verified PIN first,
    /// else the offered one (unless this card already rejected it).
    pub fn lookup(&self, guid: &Guid) -> Option<(Zeroizing<String>, PinSource)> {
        if let Some(p) = self.verified.get(guid) {
            return Some((p.clone(), PinSource::Verified));
        }
        match &self.offered {
            Some(p) if !self.offered_rejected_by.contains(guid) => {
                Some((p.clone(), PinSource::Offered))
            }
            _ => None,
        }
    }

    /// Record that `pin` verified on `guid` (a prompted PIN, or a
    /// promoted offer).
    pub fn cache_verified(&mut self, guid: &Guid, pin: &str) {
        self.verified
            .insert(guid.clone(), Zeroizing::new(pin.to_string()));
    }

    /// `guid` rejected the PIN it was just given (piggy#142 re-prompt
    /// path): drop its verified PIN and stop offering the `ssh-add -X`
    /// PIN to it. Other cards' verified PINs are untouched — that is the
    /// whole point of keying by card.
    pub fn forget_for(&mut self, guid: &Guid) {
        self.verified.remove(guid);
        self.offered_rejected_by.insert(guid.clone());
    }

    /// `guid` disappeared (probe loop): drop its verified PIN. The offered
    /// PIN is dropped too — it is an unverified blob and may well have been
    /// meant for the card that just left; re-offering it elsewhere later is
    /// the surprising direction.
    pub fn forget_card(&mut self, guid: &Guid) -> bool {
        let had = self.verified.remove(guid).is_some() || self.offered.is_some();
        self.offered = None;
        self.offered_rejected_by.clear();
        had
    }

    /// `ssh-add -X <pin>`: offer `pin` to every card that has no verified
    /// PIN. Replaces a previous offer and forgets who rejected that one.
    pub fn offer(&mut self, pin: &str) {
        self.offered = Some(Zeroizing::new(pin.to_string()));
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

    /// Test accessor: the verified PIN for `guid`.
    #[cfg(test)]
    pub fn verified_for(&self, guid: &Guid) -> Option<String> {
        self.verified.get(guid).map(|p| p.as_str().to_string())
    }

    /// Test accessor: the current `ssh-add -X` offer.
    #[cfg(test)]
    pub fn offered(&self) -> Option<String> {
        self.offered.as_ref().map(|p| p.as_str().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(seed: u8) -> Guid {
        Guid::from_bytes(&[seed; 16]).unwrap()
    }

    #[test]
    fn empty_cache_has_nothing() {
        let c = PinCache::new();
        assert!(!c.has_any());
        assert!(c.lookup(&g(1)).is_none());
    }

    /// The #177 scenario: two cards, two PINs. Card A's verified PIN is
    /// never handed out for card B, and vice versa.
    #[test]
    fn verified_pins_are_per_card() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), "1111");
        c.cache_verified(&g(2), "2222");
        assert_eq!(
            c.lookup(&g(1)),
            Some((Zeroizing::new("1111".into()), PinSource::Verified))
        );
        assert_eq!(
            c.lookup(&g(2)),
            Some((Zeroizing::new("2222".into()), PinSource::Verified))
        );
        assert!(c.lookup(&g(3)).is_none(), "a third card gets nothing");
    }

    #[test]
    fn offer_is_handed_to_any_unverified_card_as_offered() {
        let mut c = PinCache::new();
        c.offer("9999");
        assert_eq!(
            c.lookup(&g(1)),
            Some((Zeroizing::new("9999".into()), PinSource::Offered))
        );
        assert_eq!(
            c.lookup(&g(2)),
            Some((Zeroizing::new("9999".into()), PinSource::Offered))
        );
        // A card with its own verified PIN keeps it over the offer.
        c.cache_verified(&g(2), "2222");
        assert_eq!(
            c.lookup(&g(2)),
            Some((Zeroizing::new("2222".into()), PinSource::Verified))
        );
    }

    /// A card that rejected the offer is never offered it again (no
    /// second burned retry), but OTHER cards still get it.
    #[test]
    fn rejected_offer_is_not_reoffered_to_that_card_only() {
        let mut c = PinCache::new();
        c.offer("9999");
        c.forget_for(&g(1));
        assert!(c.lookup(&g(1)).is_none());
        assert_eq!(
            c.lookup(&g(2)),
            Some((Zeroizing::new("9999".into()), PinSource::Offered))
        );
        // A fresh offer resets the rejection list.
        c.offer("8888");
        assert_eq!(
            c.lookup(&g(1)),
            Some((Zeroizing::new("8888".into()), PinSource::Offered))
        );
    }

    #[test]
    fn forget_for_drops_only_that_cards_verified_pin() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), "1111");
        c.cache_verified(&g(2), "2222");
        c.forget_for(&g(1));
        assert!(c.lookup(&g(1)).is_none());
        assert_eq!(c.verified_for(&g(2)).as_deref(), Some("2222"));
    }

    #[test]
    fn forget_card_drops_its_pin_and_the_unverified_offer() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), "1111");
        c.cache_verified(&g(2), "2222");
        c.offer("9999");
        assert!(c.forget_card(&g(1)));
        assert!(c.lookup(&g(1)).is_none());
        assert!(c.offered().is_none());
        assert_eq!(
            c.verified_for(&g(2)).as_deref(),
            Some("2222"),
            "other card untouched"
        );
        // Nothing left for g(1): reports false (no-op) — the probe loop
        // uses this to decide whether to log "forgetting PIN".
        assert!(!c.forget_card(&g(1)));
    }

    #[test]
    fn clear_forgets_everything() {
        let mut c = PinCache::new();
        c.cache_verified(&g(1), "1111");
        c.offer("9999");
        c.clear();
        assert!(!c.has_any());
        assert!(c.lookup(&g(1)).is_none());
    }
}
