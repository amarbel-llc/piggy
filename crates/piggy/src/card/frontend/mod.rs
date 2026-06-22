//! [`crate::card::protocol::Frontend`] bindings (RFC 0006 §4–§5).
//!
//! - [`jsonrpc`] — the JSON-RPC binding an external program (e.g. a
//!   charmbracelet TUI) drives over a byte stream / `AF_UNIX` socket; piggy is
//!   the client.
//!
//! The default in-process tty binding ([`crate::card_oracle::run_askpass`]) and
//! the provisioning engine arrive in Phase 3b.

pub mod jsonrpc;
