//! A FLEET'S OWN PIN CACHE TABLE (piggy#404): `None` as checked in, so the
//! shipped table (`pin_cache_table.rs`) is the one in effect.
//!
//! The Nix package argument `pinCachePolicy` (`piggy-rs.withPinCachePolicy
//! ./my-table.rs`) replaces THIS file with one of the shape below; the shipped
//! table and its tests stay as they are. Nothing on a running host changes
//! it. The same rules apply to it as to the shipped table: a slot named
//! twice, or slot 82 or 83 as anything but `Never`, fails the build.
//!
//! ```ignore
//! use super::CacheRule;
//! pub const PIN_CACHE_OVERRIDE: Option<&[(u8, CacheRule)]> = Some(&[
//!     (0x9A, CacheRule::idle_secs(3600)),
//!     (0x9D, CacheRule::idle_secs_cap_secs(300, 1800)),
//! ]);
//! ```
//!
//! A slot the table does not name is never cached.

use super::CacheRule;

pub const PIN_CACHE_OVERRIDE: Option<&[(u8, CacheRule)]> = None;
