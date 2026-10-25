//! Names of the agent's card ECDH extension (piggy#335).
//!
//! The extension was inherited from C pivy-agent as `ecdh@joyent.com`.
//! piggy now owns the protocol, so the canonical name is
//! `ecdh@code.linenisgreat.com`; the legacy name stays an alias for as
//! long as anything might speak it (indefinitely, per piggy#335). The wire
//! encoding is identical under both names. Literals are assembled by
//! concatenation so editing tools cannot mangle the email-like strings.
//!
//! These live here, in the dependency-free pigpen crate, so the pure-Rust
//! agent oracle ([`crate::agent`], feature `agent`) and the piggy agent
//! share one definition; `piggy::ecdh_ext` re-exports them.

/// The name piggy clients send first and the agent prefers.
pub const CANONICAL: &str = concat!("ecdh@", "code.linenisgreat.com");

/// The name C pivy-agent and every piggy before #335 speak.
pub const LEGACY: &str = concat!("ecdh@", "joyent.com");

/// Both names, canonical first: the order a client tries them in.
pub const NAMES: [&str; 2] = [CANONICAL, LEGACY];

pub fn is_ecdh(name: &str) -> bool {
    NAMES.contains(&name)
}
