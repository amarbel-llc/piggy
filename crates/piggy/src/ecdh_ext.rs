//! Names of the agent's card ECDH extension (piggy#335).
//!
//! The names themselves (`CANONICAL`, `LEGACY`, `NAMES`, `is_ecdh`) are
//! defined once in [`piggy_pigpen::ecdh_ext`], which the pure-Rust pigpen
//! agent oracle also uses, and re-exported here; this module adds only
//! the agent's telemetry label.

pub use piggy_pigpen::ecdh_ext::{CANONICAL, LEGACY, NAMES, is_ecdh};

/// The telemetry label for an extension request. The `piggy.agent.*`
/// category is pinned byte-identical to the C agent's mirror
/// (`stats.rs::payload_agent_category_is_byte_identical_to_the_c_mirror`),
/// so both ECDH names record under the legacy label; every other
/// extension records under its own name.
pub fn metric_label(name: &str) -> &str {
    if is_ecdh(name) { LEGACY } else { name }
}
