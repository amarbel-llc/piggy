//! Piggy library surface.
//!
//! The `piggy` binary's user-facing dispatch is in `main.rs`. The
//! library exposes:
//!
//! - `agent_client` and `card_oracle` — the SSH-agent ECDH client
//!   and direct-PCSC oracle used by integration tests in `tests/`
//!   to validate the `ecdh@joyent.com` round-trip.
//! - `cmd` — the Rust re-implementations of `piggy agent` and
//!   `piggy box`, both now ON the dispatch path. `cmd::pivy_box`
//!   backs `piggy box` (falling back to C `pivy-box` for subcommands
//!   it doesn't handle — piggy#57), restoring agentless direct-PCSC
//!   decrypt. `cmd::agent` backs `piggy agent` (piggy#58/#59): a
//!   PIV-backed SSH agent with on-demand SSH_ASKPASS PIN entry and a
//!   card-presence probe loop, atop the #56 PC/SC transactions. See
//!   the head of `main.rs` for the dispatch rationale.

//! - `ecdsa_sig` — shared DER ECDSA signature reframing (DER → raw
//!   `r‖s` or `(r, s)`), used by both the agent's SSH-signature path
//!   and `piggy sign-bytes`.

pub mod agent_client;
pub mod card;
pub mod card_oracle;
pub mod cmd;
pub mod ecdsa_sig;
pub mod manage;
pub mod stats;
