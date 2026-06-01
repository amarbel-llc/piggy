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
    /// PIV GENERATE ASYMMETRIC KEY PAIR (SP 800-73-4 §3.3.2). `P1 = 00`,
    /// `P2 = <slot>`; data field is an `AC` control-reference template
    /// carrying `80 01 <alg>` (e.g. `0x11` = ECCP256) plus optional
    /// YubiKey `AA`/`AB` PIN/touch-policy tags. The card generates a new
    /// keypair in the slot and returns the public key in a `7F49`
    /// template (`86 41 04 <X> <Y>` for ECCP256). mgmt-key gated.
    pub const GEN_ASYM: u8 = 0x47;
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
    /// YubiKey vendor "get serial number". Real YK4 firmware <5.x
    /// doesn't implement this — the wire shows the card returning
    /// `6D00`. YK5 firmware emits a 4-byte big-endian serial number +
    /// SW 9000. `P1 P2 = 00 00`; no body. Not in SP 800-73-4 — it's a
    /// YubicoPIV extension pivy-tool issues during discovery.
    pub const YK_SERIAL: u8 = 0xF8;
    /// PIV GENERAL AUTHENTICATE (SP 800-73-4 §3.2.4). Used for
    /// challenge-response (slot ECDSA + mgmt-key auth) and key
    /// agreement (slot ECDH). `P1` is the algorithm reference (e.g.
    /// `0x11` = ECCP256), `P2` is the key reference (e.g. `0x9D` =
    /// key management slot). The data field is a `7C` dynamic-
    /// authentication-template TLV; for slot 9D ECDH it carries a
    /// `82 00` (response template, empty in request) followed by a
    /// `85 41 04 <Xeph> <Yeph>` exponentiation parameter (the
    /// client's ephemeral uncompressed P-256 point). The card
    /// response is `7C 22 82 20 <Xshared>` — the X-coordinate of
    /// `card_priv * eph_pub`, padded to 32 bytes.
    pub const GENERAL_AUTHENTICATE: u8 = 0x87;
    /// YubiKey vendor "attest slot key". `P1` is the slot (e.g.
    /// `0x9D`), `P2 = 00`. The response is a YubicoPIV-signed X.509
    /// attestation certificate over the slot's public key — proof
    /// that the slot key was generated *on-card* (rather than
    /// imported). Wet-env wire on YubiKey 4 firmware 4.3.5
    /// (2026-05-31): generated-key slots return a ~580-byte cert +
    /// SW 9000 in a single extended-length response; **imported-key
    /// slots return `6A 80`**, because attestation has nothing to
    /// sign without the on-card-generation provenance. VirtualCard
    /// only models the imported-key case (it has no factory
    /// attestation key) and returns `6A 80` for any F9 probe.
    pub const YK_ATTEST: u8 = 0xF9;
}
