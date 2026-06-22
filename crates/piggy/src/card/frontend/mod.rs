//! [`crate::card::protocol::Frontend`] bindings (RFC 0006 §4–§5).
//!
//! - [`tty`] — the default in-process terminal/askpass binding.
//! - [`jsonrpc`] — the JSON-RPC binding an external program (e.g. a
//!   charmbracelet TUI) drives over a byte stream / `AF_UNIX` socket; piggy is
//!   the client.
//!
//! The provisioning engine that consumes these arrives in
//! [`crate::card::engine`] (Phase 3b).

pub mod jsonrpc;
pub mod select;
pub mod tty;
