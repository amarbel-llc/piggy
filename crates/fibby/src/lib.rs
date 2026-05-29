//! fibby — a pure-Rust virtual PIV smart card that implements the
//! pcsc-lite daemon protocol directly, so PC/SC clients connect to it
//! with no real `pcscd` or `vsmartcard-vpcd` in the loop.
//!
//! Status: scaffolding. The `proto` module (pcsc-lite wire codec) is the
//! first landed brick. The server event loop, the `Backend` trait
//! (virtual PIV card + hardware-proxy), and the PIV applet itself follow.
//! See docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md for the
//! overall design and the proxy-validation methodology.

pub mod proto;
