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
    /// PIV GET DATA (SP 800-73-4 §3.1.2). Always with `P1 P2 = 3F FF`,
    /// data field is a `5C <len> <tag>` TLV identifying the object.
    pub const GET_DATA: u8 = 0xCB;
    /// PIV PUT DATA (SP 800-73-4 §3.1.3). Same `P1 P2`; data field is
    /// `5C <len> <tag>` followed by `53 <len> <value>`.
    pub const PUT_DATA: u8 = 0xDB;
    /// YubiKey vendor GET VERSION. Returns 3 bytes encoding the
    /// firmware version (major, minor, patch) + SW 9000. `P1 P2 = 00 00`;
    /// no body. Not in SP 800-73-4 — it's a YubicoPIV extension that
    /// pivy-tool issues during its discovery walk.
    pub const GET_VERSION: u8 = 0xFD;
    /// PIV VERIFY (SP 800-73-4 §3.2.1). Used both to attempt a PIN
    /// verification (with an 8-byte PIN body) and to query the current
    /// verification status (no body). `P2 = 80` selects the PIV
    /// application PIN; other P2 values address PUK / mgmt-key (not
    /// implemented yet).
    pub const VERIFY: u8 = 0x20;
}
