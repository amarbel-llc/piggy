//! The `Backend` trait: the seam between fibby's pcsc-lite protocol
//! server and *what's behind the reader*.
//!
//! Two implementors:
//!
//! - [`crate::virtual_card::VirtualCard`] — the in-Rust PIV applet (the
//!   goal). Always available.
//! - [`crate::hardware_proxy::HardwareProxy`] — forwards to a real
//!   `pcscd` → real YubiKey via the `pcsc` crate. Behind the
//!   `hardware-proxy` Cargo feature. This is the validation oracle:
//!   run the *same* protocol server in front of real silicon, confirm
//!   `pivy-tool`/`piggy` behave, then trust the virtual path.
//!
//! Keeping the backend this small (connect / transmit / disconnect +
//! reader metadata) is deliberate: transactions, reconnect, and
//! status detail are handled protocol-side in `server.rs` so a backend
//! author only has to model a card, not the daemon.

/// Outcome of a backend operation: either an active protocol /
/// response, or an `SCARD_*` code to put on the wire verbatim.
pub type ScardResult<T> = Result<T, u32>;

pub trait Backend: Send {
    /// Reader name advertised to clients (the string `SCardListReaders`
    /// returns). pcsc-lite reader names conventionally end with a
    /// ` NN NN` slot suffix, e.g. `Yubico YubiKey OTP+FIDO+CCID 00 00`.
    fn reader_name(&self) -> String;

    /// Whether a card is currently present in the reader.
    fn card_present(&self) -> bool;

    /// Toggle runtime presence (piggy#130): a virtual backend models the
    /// card being removed from / re-inserted into the reader, driven by the
    /// control socket. Default no-op — backends whose presence is not
    /// runtime-controllable (e.g. the hardware proxy, which re-probes real
    /// silicon) ignore it.
    fn set_present(&mut self, _present: bool) {}

    /// ATR of the present card (empty if absent).
    fn atr(&self) -> Vec<u8>;

    /// Power up and select the card. Returns the active protocol
    /// (`proto::protocol::T0`/`T1`) negotiated, or an `SCARD_*` error.
    fn connect(&mut self, share_mode: u32, preferred_protocols: u32) -> ScardResult<u32>;

    /// Tear down a connection with the given disposition
    /// (`proto::disposition::*`). LEAVE/RESET/UNPOWER/EJECT.
    fn disconnect(&mut self, disposition: u32) -> ScardResult<()>;

    /// Transmit a command APDU, returning the full response (data ‖ SW1
    /// SW2). The protocol layer streams this straight back to the
    /// client; the backend does no framing of its own.
    fn transmit(&mut self, command_apdu: &[u8]) -> ScardResult<Vec<u8>>;
}
