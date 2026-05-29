//! fibby CLI entry point.
//!
//! Scaffolding only: the listen loop / backend dispatch is not wired yet.
//! Today this validates the host-endianness assumption the pcsc-lite
//! codec relies on and prints the protocol version fibby will advertise.

fn main() {
    fibby::proto::assert_le_host();
    eprintln!(
        "fibby: pcsc-lite protocol {}.{} (server loop not yet wired — see \
         docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md)",
        fibby::proto::PROTOCOL_VERSION_MAJOR,
        fibby::proto::PROTOCOL_VERSION_MINOR,
    );
}
