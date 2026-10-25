//! Names of the agent's card ECDH extension (piggy#335).
//!
//! The extension was inherited from C pivy-agent as `ecdh@joyent.com`.
//! piggy now owns the protocol, so the canonical name is
//! `ecdh@code.linenisgreat.com`; the legacy name stays an alias for as
//! long as anything might speak it (indefinitely, per piggy#335). The wire
//! encoding is identical under both names. Literals are assembled by
//! concatenation so editing tools cannot mangle the email-like strings.

/// The name piggy clients send first and the agent prefers.
pub const CANONICAL: &str = concat!("ecdh@", "code.linenisgreat.com");

/// The name C pivy-agent and every piggy before #335 speak.
pub const LEGACY: &str = concat!("ecdh@", "joyent.com");

/// Both names, canonical first: the order a client tries them in.
pub const NAMES: [&str; 2] = [CANONICAL, LEGACY];

pub fn is_ecdh(name: &str) -> bool {
    NAMES.contains(&name)
}

/// The telemetry label for an extension request. The `piggy.agent.*`
/// category is pinned byte-identical to the C agent's mirror
/// (`stats.rs::payload_agent_category_is_byte_identical_to_the_c_mirror`),
/// so both ECDH names record under the legacy label; every other
/// extension records under its own name.
pub fn metric_label(name: &str) -> &str {
    if is_ecdh(name) { LEGACY } else { name }
}
