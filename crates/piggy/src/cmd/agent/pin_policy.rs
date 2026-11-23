//! Which slots the agent may remember a PIN for, and for how long (piggy#404).
//!
//! The PIV PIN is the card's, one for every slot, but what it unlocks differs:
//! 9A signs SSH logins, 9C signs, 9D decrypts the store. A PIN typed for one
//! slot must not quietly serve another, so the agent keeps a PIN per (card,
//! slot) and each slot has its own rule: never, or for at most so long idle
//! and so long in all.
//!
//! The table is a BUILD-TIME input, not configuration: it is the one small
//! file `pin_cache_table.rs` beside this one, compiled into the binary, so no
//! flag, option or environment of a running host can loosen it. To change it,
//! edit that file (or build with the Nix package argument `pinCachePolicy`),
//! rebuild and bump. A table that makes slot 82 or 83 cacheable fails the
//! build (the `const` check below), and a test says the same.

use std::collections::BTreeMap;
use std::time::Duration;

#[path = "pin_cache_table.rs"]
mod table;

/// What the agent may do with a PIN typed for one slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheRule {
    /// Asked every time, kept nowhere.
    Never,
    /// Kept until `idle` has passed since it was last used, or `cap` since it
    /// was typed, whichever comes first; `None` for a limit means no such
    /// limit.
    For {
        idle: Option<Duration>,
        cap: Option<Duration>,
    },
}

impl CacheRule {
    /// No limit at all (the tests': the shipped table never says this).
    #[cfg(test)]
    pub const UNLIMITED: Self = Self::For {
        idle: None,
        cap: None,
    };

    /// `idle` seconds since last use, no other limit.
    pub const fn idle_secs(idle: u64) -> Self {
        Self::For {
            idle: Some(Duration::from_secs(idle)),
            cap: None,
        }
    }

    /// `idle` seconds since last use and `cap` seconds in all.
    pub const fn idle_secs_cap_secs(idle: u64, cap: u64) -> Self {
        Self::For {
            idle: Some(Duration::from_secs(idle)),
            cap: Some(Duration::from_secs(cap)),
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Never => "never".into(),
            Self::For { idle, cap } => {
                let mut parts = Vec::new();
                if let Some(idle) = idle {
                    parts.push(format!("idle {}", human(idle)));
                }
                if let Some(cap) = cap {
                    parts.push(format!("cap {}", human(cap)));
                }
                if parts.is_empty() {
                    "until the card leaves".into()
                } else {
                    parts.join(", ")
                }
            }
        }
    }
}

fn human(d: Duration) -> String {
    let s = d.as_secs();
    if s != 0 && s.is_multiple_of(3600) {
        format!("{} h", s / 3600)
    } else if s != 0 && s.is_multiple_of(60) {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}

/// The certificate authority slots: never cached, whatever a table says.
const fn is_authority_slot(slot: u8) -> bool {
    slot == 0x82 || slot == 0x83
}

/// The build fails here, naming the slot, if a table makes an authority slot
/// cacheable.
const fn check_table(table: &[(u8, CacheRule)]) {
    let mut i = 0;
    while i < table.len() {
        let (slot, rule) = table[i];
        if is_authority_slot(slot) && !matches!(rule, CacheRule::Never) {
            panic!(
                "pin_cache_table.rs makes slot 82 or 83 cacheable: a certificate authority's \
                 PIN is asked every time and the table may only say `Never` for it"
            );
        }
        i += 1;
    }
}

const _: () = check_table(table::PIN_CACHE_TABLE);

/// The per-slot table. A slot it does not name is never cached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinCachePolicy {
    rules: BTreeMap<u8, CacheRule>,
}

impl Default for PinCachePolicy {
    fn default() -> Self {
        Self::compiled_in()
    }
}

impl PinCachePolicy {
    /// The table compiled into this binary.
    pub fn compiled_in() -> Self {
        Self::from_table(table::PIN_CACHE_TABLE)
    }

    fn from_table(table: &[(u8, CacheRule)]) -> Self {
        Self {
            rules: table.iter().copied().collect(),
        }
    }

    /// A table of the tests' own, with short values: there is no such
    /// constructor in a shipped binary, so no caller can supply a table at
    /// run time. The authority slots stay never cached whatever it says.
    #[cfg(test)]
    pub fn for_test_table(table: &[(u8, CacheRule)]) -> Self {
        Self::from_table(table)
    }

    /// The rule for `slot`: the certificate authority slots are never cached
    /// whatever the table says, and a slot the table does not name is never
    /// cached.
    pub fn rule(&self, slot: u8) -> CacheRule {
        if is_authority_slot(slot) || piggy_piv::slot::is_ca_slot(slot) {
            return CacheRule::Never;
        }
        self.rules.get(&slot).copied().unwrap_or(CacheRule::Never)
    }

    /// One line per slot the table names, for the agent's startup log and
    /// `piggy health -v`.
    pub fn describe(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|(slot, rule)| format!("{slot:02X}: {}", rule.describe()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_table_is_9a_12h_idle_9d_10min_idle_1h_cap_and_9c_60s_idle() {
        let p = PinCachePolicy::compiled_in();
        assert_eq!(p.rule(0x9A), CacheRule::idle_secs(12 * 3600));
        assert_eq!(p.rule(0x9D), CacheRule::idle_secs_cap_secs(600, 3600));
        assert_eq!(p.rule(0x9C), CacheRule::idle_secs(60));
        assert_eq!(p.rule(0x9E), CacheRule::Never, "a slot not named");
        assert_eq!(p.rule(0x84), CacheRule::Never, "a retired slot not named");
    }

    #[test]
    fn the_authority_slots_are_never_cached_whatever_a_table_says() {
        let p = PinCachePolicy::for_test_table(&[
            (0x82, CacheRule::UNLIMITED),
            (0x83, CacheRule::idle_secs(60)),
        ]);
        assert_eq!(p.rule(0x82), CacheRule::Never);
        assert_eq!(p.rule(0x83), CacheRule::Never);
    }

    #[test]
    fn the_shipped_table_names_no_cacheable_authority_slot() {
        // The build already refuses this (the const check); the test says it
        // too, and that the check's idea of an authority slot is the slot
        // module's.
        for (slot, rule) in table::PIN_CACHE_TABLE {
            if piggy_piv::slot::is_ca_slot(*slot) {
                assert_eq!(*rule, CacheRule::Never, "slot {slot:02X}");
            }
        }
        for slot in 0..=u8::MAX {
            assert_eq!(is_authority_slot(slot), piggy_piv::slot::is_ca_slot(slot));
        }
    }

    #[test]
    fn describe_lists_every_named_slot() {
        assert_eq!(
            PinCachePolicy::compiled_in().describe(),
            [
                "82: never",
                "83: never",
                "9A: idle 12 h",
                "9C: idle 1 min",
                "9D: idle 10 min, cap 1 h"
            ]
        );
    }
}
