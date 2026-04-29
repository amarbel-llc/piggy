//! Piggy library surface.
//!
//! The `piggy` binary's user-facing dispatch is in `main.rs`. The
//! library exposes:
//!
//! - `agent_client` and `card_oracle` — the SSH-agent ECDH client
//!   and direct-PCSC oracle used by integration tests in `tests/`
//!   to validate the `ecdh@joyent.com` round-trip.
//! - `cmd` — the Rust re-implementations of `piggy agent` and
//!   `piggy box`. These are NOT on the binary's dispatch path
//!   today (the binary wraps C `pivy-agent` and `pivy-box` via
//!   `fallback::exec_pivy`); the modules stay here so the unit
//!   tests under each one keep running and so the code is in
//!   place to swap back in once it reaches feature parity with
//!   the C implementations. See the head of `main.rs` for the
//!   full rationale, and #56 (PC/SC transactions in `piggy-piv`),
//!   #57 (direct-PCSC ECDH oracle for `piggy box stream decrypt`),
//!   #58 (askpass `[piggy-test]` context tagging), and #59
//!   (probe-loop PIN-clearing in `piggy agent`) for the maturation
//!   roadmap.

pub mod agent_client;
pub mod card_oracle;
pub mod cmd;
