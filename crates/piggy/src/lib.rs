//! Piggy library surface.
//!
//! The main `piggy` binary lives in [`main.rs`] and has its own module
//! tree (`cmd::agent`, `cmd::pivy_box`, `fallback`). This `lib.rs` exists
//! purely to expose pieces that integration tests in `tests/` need to
//! reach — chiefly the SSH-agent ECDH client used to validate the
//! `ecdh@joyent.com` round-trip against a live `piggy-agent`.

pub mod agent_client;
pub mod card_oracle;
