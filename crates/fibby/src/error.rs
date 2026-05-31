//! `SCARD_*` return codes (pcsclite.h / PCSC/pcsclite.h).
//!
//! These travel in the `rv` field of every response struct. Only the
//! subset fibby actually returns is listed; extend as commands grow.
//! Values are the canonical PC/SC codes so real clients render the
//! familiar error strings.

pub const SCARD_S_SUCCESS: u32 = 0x0000_0000;
pub const SCARD_F_INTERNAL_ERROR: u32 = 0x8010_0001;
pub const SCARD_E_INVALID_HANDLE: u32 = 0x8010_0003;
pub const SCARD_E_INVALID_VALUE: u32 = 0x8010_0011;
pub const SCARD_E_NO_SMARTCARD: u32 = 0x8010_000C;
pub const SCARD_E_UNKNOWN_READER: u32 = 0x8010_0009;
pub const SCARD_E_NOT_TRANSACTED: u32 = 0x8010_0016;
pub const SCARD_E_READER_UNAVAILABLE: u32 = 0x8010_0017;
pub const SCARD_E_SHARING_VIOLATION: u32 = 0x8010_000B;
pub const SCARD_E_PROTO_MISMATCH: u32 = 0x8010_000F;
pub const SCARD_E_NO_SERVICE: u32 = 0x8010_001D;
pub const SCARD_W_REMOVED_CARD: u32 = 0x8010_0069;
pub const SCARD_W_UNRESPONSIVE_CARD: u32 = 0x8010_0066;
pub const SCARD_W_RESET_CARD: u32 = 0x8010_0068;
