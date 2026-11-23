//! THE PIN CACHE TABLE: which slots the agent may remember a PIN for, and for
//! how long (piggy#404). Edit this file to change it, rebuild and bump; or
//! build with the Nix package argument `pinCachePolicy` pointing at a file of
//! this shape. Nothing on a running host changes it.
//!
//! A slot is cached while it is used: `idle_secs(N)` forgets the PIN after N
//! seconds without use; `idle_secs_cap_secs(N, M)` also forgets it M seconds
//! after it was typed, however busy. `Never` asks every time. A slot not named
//! here is never cached. Slots 82 and 83 (certificate authorities) may only be
//! `Never`: anything else fails the build.
//!
//! One typed PIN serves only the slot it was typed for.

use super::CacheRule::{self, Never};

#[allow(dead_code)]
const HOURS: u64 = 3600;

pub const PIN_CACHE_TABLE: &[(u8, CacheRule)] = &[
    // 9A: SSH logins, also through a forwarded agent. Touch is the card's.
    (0x9A, CacheRule::idle_secs(12 * HOURS)),
    // 9C: signatures (git signing). Touch every time stays the card's; a PIN
    // is asked again after a minute without a signature.
    (0x9C, CacheRule::idle_secs(60)),
    // 9D: decrypts the secrets store; no touch by default, so the shortest
    // window that still makes one tofu run or one reconcile a single PIN.
    (0x9D, CacheRule::idle_secs_cap_secs(10 * 60, HOURS)),
    // 82 and 83: certificate authorities. Never, here or anywhere.
    (0x82, Never),
    (0x83, Never),
];
