//! Piggy library surface.
//!
//! The `piggy` binary's user-facing dispatch is in `main.rs`. The
//! library exposes:
//!
//! - `agent_client` and `card_oracle` — the SSH-agent ECDH client
//!   and direct-PCSC oracle used by integration tests in `tests/`
//!   to validate the `ecdh@joyent.com` round-trip.
//! - `cmd` — the Rust re-implementations of `piggy agent` and
//!   `piggy box`. `cmd::pivy_box` IS on the dispatch path now
//!   (`piggy box` runs it, falling back to C `pivy-box` for
//!   subcommands it doesn't handle — piggy#57), restoring the
//!   agentless direct-PCSC decrypt. `cmd::agent` is still OFF the
//!   path (`piggy agent` execs C `pivy-agent`) until #58/#59. See
//!   the head of `main.rs` for the full rationale and the #56–#59
//!   maturation roadmap (#56 + #57 done; #58 askpass `[piggy-test]`
//!   context tagging + #59 probe-loop PIN-clearing remain).

pub mod agent_client;
pub mod card_oracle;
pub mod cmd;
