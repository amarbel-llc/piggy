//! fibby — a pure-Rust virtual PIV smart card that implements the
//! pcsc-lite daemon protocol directly, so PC/SC clients connect to it
//! with no real `pcscd` or `vsmartcard-vpcd` in the loop.
//!
//! Layering (each module is small and independently testable):
//!
//! - [`proto`] — pcsc-lite wire codec (structs ↔ bytes), protocol 4.6.
//! - [`frame`] — message framing over the socket (header + body / bare
//!   replies / streamed payloads).
//! - [`error`] — `SCARD_*` return codes.
//! - [`trace`] — `FIBBY_LOG`-controlled leveled logging + hex dumps.
//! - [`backend`] — the `Backend` trait (the card seam).
//! - [`virtual_card`] — the in-Rust PIV card (stub today; real applet is
//!   phase-5 work).
//! - [`hardware_proxy`] — forwards to a real pcscd/YubiKey (feature
//!   `hardware-proxy`); the validation oracle.
//! - [`server`] — the listen loop + command dispatch.
//!
//! See docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md.

pub mod apdu;
pub mod backend;
pub mod error;
pub mod frame;
pub mod proto;
pub mod server;
pub mod trace;
pub mod virtual_card;

#[cfg(feature = "hardware-proxy")]
pub mod hardware_proxy;
