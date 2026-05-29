//! Minimal ISO 7816-4 / PIV constants fibby's card side needs.
//!
//! Intentionally tiny and local for now. The fuller vocabulary lives in
//! `crates/piggy-piv` (the host-side client); when the real PIV applet
//! lands, the shared subset (AIDs, INS codes, algorithm IDs, GA template
//! tags) should move to a common module so client and card cannot drift
//! — same discipline as `store.rs`/`git_ops.rs`. See the design doc.

/// Full PIV application AID (NIST SP 800-73-4): RID ‖ PIX ‖ version.
pub const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// PIV AID prefix (RID + application portion) a client SELECTs by; the
/// trailing version bytes are optional in the SELECT data field.
pub const PIV_AID_PREFIX: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];

/// ISO 7816-4 instruction bytes fibby's stub recognizes.
pub mod ins {
    pub const SELECT: u8 = 0xA4;
}
