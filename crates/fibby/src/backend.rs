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

/// Outcome of [`Backend::transmit_or_await_touch`].
pub enum TransmitOutcome {
    /// The full response (data ‖ SW1 SW2), exactly as `transmit` returns.
    Done(Vec<u8>),
    /// The operation needs a touch that has not been granted. Nothing on
    /// the card changed; the caller releases the backend lock, waits on
    /// the pad, and transmits the same APDU again.
    AwaitTouch(crate::touch::TouchWait),
}

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

    /// Monotonic reader-event counter (piggy#248): bumped on each real
    /// presence toggle, reported in `READER_STATE.eventCounter`. libpcsclite
    /// diffs this counter (alongside the PRESENT/ABSENT flags) to decide a
    /// reader-state change occurred, so it must actually move for an
    /// event-driven client's `SCardGetStatusChange` to unblock on a
    /// remove-then-reinsert (same end flags, different counter). Default 0 —
    /// backends with no runtime presence changes (the hardware proxy) never
    /// bump it.
    fn event_counter(&self) -> u32 {
        0
    }

    /// Queue an injected fault (piggy#284): the next `fault.remaining`
    /// command APDUs matching `fault.ins` answer `fault.sw` instead of
    /// being processed. Driven by the control socket (`fibby ctl fault`).
    /// Default: refused — a backend fronting real silicon cannot fake a
    /// status word.
    fn inject_fault(&mut self, _fault: crate::virtual_card::Fault) -> Result<(), String> {
        Err("this backend does not support fault injection".into())
    }

    /// Drop every queued fault (piggy#284). Default no-op.
    fn clear_faults(&mut self) {}

    /// ATR of the present card (empty if absent).
    fn atr(&self) -> Vec<u8>;

    /// Power up and select the card. Returns the active protocol
    /// (`proto::protocol::T0`/`T1`) negotiated, or an `SCARD_*` error.
    fn connect(&mut self, share_mode: u32, preferred_protocols: u32) -> ScardResult<u32>;

    /// Tear down a connection with the given disposition
    /// (`proto::disposition::*`). LEAVE/RESET/UNPOWER/EJECT.
    fn disconnect(&mut self, disposition: u32) -> ScardResult<()>;

    /// End a transaction with the given disposition. A client ending one
    /// with RESET (piggy-piv does, after a session that verified a PIN)
    /// resets the card for every client: no applet stays selected and no
    /// PIN stays verified. Default no-op: a backend fronting real silicon
    /// leaves that to the silicon.
    fn end_transaction(&mut self, _disposition: u32) {}

    /// Transmit a command APDU, returning the full response (data ‖ SW1
    /// SW2). The protocol layer streams this straight back to the
    /// client; the backend does no framing of its own.
    fn transmit(&mut self, command_apdu: &[u8]) -> ScardResult<Vec<u8>>;

    /// Like [`Self::transmit`], but an operation blocked on a touch-policy
    /// slot reports [`TransmitOutcome::AwaitTouch`] instead of failing, so
    /// the server can wait for the touch WITHOUT holding this backend's
    /// lock (see `server::transmit_waiting_for_touch`). Default: no
    /// backend-side touch gate, so always `Done` — the hardware proxy's
    /// touch is the real card's button and blocks inside `transmit`.
    fn transmit_or_await_touch(&mut self, command_apdu: &[u8]) -> ScardResult<TransmitOutcome> {
        self.transmit(command_apdu).map(TransmitOutcome::Done)
    }

    /// Grant one simulated touch, driven by the control socket (`fibby ctl
    /// touch`); the next touch-requiring operation on this card consumes
    /// it. Returns how many touches are now pending. Default: refused — a
    /// backend fronting real silicon has a real button.
    fn grant_touch(&mut self) -> Result<u32, String> {
        Err("this backend does not support simulated touch".into())
    }
}
