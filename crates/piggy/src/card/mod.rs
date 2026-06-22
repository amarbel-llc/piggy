//! Card management: the interaction protocol (RFC 0006) and the provisioning
//! engine (piggy#194).
//!
//! [`protocol`] defines the transport-agnostic [`protocol::Frontend`] trait and
//! its serde payload types — the single contract both bindings speak.
//! [`frontend`] holds the bindings: the default in-process tty frontend and the
//! JSON-RPC frontend an external TUI drives over a socket. [`engine`]
//! orchestrates `piggy card init`'s full setup against a `&mut dyn Frontend`,
//! staying agnostic to which binding is in use.

pub mod engine;
pub mod frontend;
pub mod init_cmd;
pub mod protocol;
