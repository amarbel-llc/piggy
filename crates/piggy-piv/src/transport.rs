//! The APDU transport seam: PIV logic above, bytes below (pigsty design,
//! docs/plans/2026-10-25-pigsty-design.md §1).
//!
//! [`PivToken`](crate::token::PivToken) and
//! [`PinSession`](crate::token::PinSession) talk to a card only through
//! these traits. `PcscTransport` (the default-on `pcsc-transport` feature) is the
//! PC/SC implementation every existing caller gets through
//! `PivToken::connect`; a test, or a host without PC/SC (Android
//! NFC/USB), supplies its own and hands it to `PivToken::from_transport`.

use crate::error::PivError;

#[cfg(feature = "pcsc-transport")]
pub use crate::pcsc_transport::PcscTransport;

/// Bound on retries when `SCardBeginTransaction` returns
/// `SCARD_W_RESET_CARD`. C pivy (vendor/pivy/src/piv.c::piv_txn_begin)
/// retries unboundedly; piggy caps it so a card stuck in a reset loop
/// fails fast instead of hanging the agent (piggy#56 decision 5).
pub const PIN_SESSION_RESET_RETRY_CAP: u32 = 3;

/// What happens to the card when a transaction ends. `ResetCard` after a
/// session that verified a PIN, so no PIN state outlives the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndDisposition {
    LeaveCard,
    ResetCard,
}

/// One command APDU in, `data ‖ SW1 SW2` out. No GET RESPONSE chaining,
/// no status-word interpretation: that is the token's job, so every
/// transport gets it identically.
pub trait RawApdu {
    fn transmit_raw(&self, command: &[u8]) -> Result<Vec<u8>, PivError>;
}

/// A connection to one card. `Send` because the agent holds a token and
/// its session across `.await` points in futures that must be `Send`.
pub trait ApduTransport: RawApdu + Send {
    /// Begin an exclusive transaction. The session borrows the transport
    /// for its lifetime; ending it (or dropping it) releases the card.
    fn begin_transaction<'a>(&'a mut self) -> Result<Box<dyn ApduSession + 'a>, PivError>;
}

/// An open transaction. A transport whose medium has no transactions (a
/// single-client NFC link) returns a session that forwards to the
/// connection and treats `end` as a no-op.
pub trait ApduSession: RawApdu + Send {
    fn end(self: Box<Self>, disposition: EndDisposition) -> Result<(), PivError>;
}
