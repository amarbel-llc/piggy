//! Wire-format encode/decode for the `ecdh@joyent.com` SSH-agent extension.
//!
//! This module is pure bytes-in/bytes-out: no I/O, no sockets, no runtime
//! dependencies. It mirrors the on-the-wire layout documented in
//! `vendor/pivy/docs/rfcs/0001-ssh-agent-extensions.md` and the server-side
//! decoder in `crates/piggy/src/cmd/agent/session.rs::handle_ecdh`.
//!
//! **Request layout.** The `Extension.details` buffer carries a single
//! SSH-wire string whose contents are three concatenated fields:
//!
//! ```text
//! string wrapped_payload
//!   where wrapped_payload = sshkey_blob(self) | sshkey_blob(partner) | u32(flags)
//! ```
//!
//! Each `sshkey_blob` is itself an SSH wire-format string (u32 BE length +
//! raw key bytes); callers pass the already-SSH-encoded key bytes.
//!
//! **Response layout.** The returned `Extension.details` is a single SSH
//! string that wraps the raw shared-secret bytes.
//!
//! Checkpoint 1 of issue #32.
use crate::error::{BoxError, Result};
use crate::oracle::OracleError;
use crate::piv_box::EcCurve;
use crate::wire::{WireReader, WireWriter};

/// Encode an `ecdh@joyent.com` request body.
///
/// The returned `Vec<u8>` is ready to be placed in `Extension.details`; it
/// already contains the outer SSH-string wrap described at the module level.
pub fn encode_ecdh_request(self_key_blob: &[u8], partner_key_blob: &[u8], flags: u32) -> Vec<u8> {
    let mut inner = WireWriter::new();
    inner.put_string(self_key_blob);
    inner.put_string(partner_key_blob);
    inner.put_u32(flags);

    let mut outer = WireWriter::new();
    outer.put_string(inner.as_bytes());
    outer.into_bytes()
}

/// Decode an `ecdh@joyent.com` response body and return the raw shared
/// secret.
///
/// `details` must be exactly one SSH string (u32 BE length + bytes) with no
/// trailing data. Deviations surface as [`BoxError::InvalidAgentReply`].
pub fn decode_ecdh_response(details: &[u8]) -> Result<Vec<u8>> {
    if details.len() < 4 {
        return Err(BoxError::InvalidAgentReply(format!(
            "response shorter than 4-byte length prefix: {} bytes",
            details.len()
        )));
    }

    let mut reader = WireReader::new(details);
    let secret = reader.get_string().map_err(|e| {
        BoxError::InvalidAgentReply(format!("response length prefix exceeds body: {e}"))
    })?;

    if reader.remaining() != 0 {
        return Err(BoxError::InvalidAgentReply(format!(
            "{} trailing bytes after declared ssh-string",
            reader.remaining()
        )));
    }

    Ok(secret)
}

/// Encode a raw NIST EC point as an OpenSSH `ecdsa-sha2-nistpNNN` sshkey
/// blob.
///
/// The input is the SEC1 uncompressed encoding (`0x04 || X || Y`, 65 bytes
/// for P-256, 97 for P-384) — the same format `piv_box` stores in
/// `recipient_pubkey` / `ephemeral_pubkey` *after* decompressing, and the
/// same encoding the card itself emits over ECDH.
///
/// Returns `string("ecdsa-sha2-nistpNNN") | string("nistpNNN") | string(point)`,
/// which matches what [`ssh_key::PublicKey::to_bytes`] produces for an
/// Ecdsa key — verified by checkpoint 2's integration test round-trip.
///
/// This helper does NOT validate `point`: length-checking is left to the
/// caller or to the oracle backend. A mis-sized point will surface as an
/// oracle-side `InvalidPubkey` error rather than a silent success.
pub fn ec_point_to_ssh_pubkey_blob(curve: EcCurve, point: &[u8]) -> Vec<u8> {
    let (key_type, curve_name) = match curve {
        EcCurve::NistP256 => ("ecdsa-sha2-nistp256", "nistp256"),
        EcCurve::NistP384 => ("ecdsa-sha2-nistp384", "nistp384"),
    };
    let mut w = WireWriter::new();
    w.put_string(key_type.as_bytes());
    w.put_string(curve_name.as_bytes());
    w.put_string(point);
    w.into_bytes()
}

/// Encode a raw 32-byte Ed25519 public key as an OpenSSH `ssh-ed25519`
/// sshkey blob: `string("ssh-ed25519") | string(key)`. Sibling of
/// [`ec_point_to_ssh_pubkey_blob`] for the Ed25519 keys `piggy list
/// --format=ssh` renders from 9A/9C/9E slots (#86); matches what
/// [`ssh_key::PublicKey::to_bytes`] produces for an Ed25519 key —
/// verified by the parity test below.
///
/// Like its EC sibling, this helper does NOT validate `key`: a
/// mis-sized key surfaces downstream rather than panicking here.
pub fn ed25519_to_ssh_pubkey_blob(key: &[u8]) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.put_string(b"ssh-ed25519");
    w.put_string(key);
    w.into_bytes()
}

/// Inverse of [`ec_point_to_ssh_pubkey_blob`]: pull the raw EC point bytes
/// out of an OpenSSH `ecdsa-sha2-nistpNNN` sshkey blob.
///
/// The blob is `string(key_type) | string(curve_name) | string(point)`. We
/// step over the first two strings and return the third as `Vec<u8>` —
/// callers get whatever encoding the original blob carried (in practice
/// SEC1 uncompressed `0x04 || X || Y`, since that's what
/// [`ec_point_to_ssh_pubkey_blob`] writes).
///
/// Returns [`OracleError::InvalidPubkey`] when the blob is too short to
/// hold three length-prefixed strings.
pub fn extract_point_from_sshkey_blob(blob: &[u8]) -> std::result::Result<Vec<u8>, OracleError> {
    fn take_string(b: &[u8]) -> std::result::Result<(&[u8], &[u8]), OracleError> {
        if b.len() < 4 {
            return Err(OracleError::InvalidPubkey(
                "blob too short for length".into(),
            ));
        }
        let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if b.len() < 4 + n {
            return Err(OracleError::InvalidPubkey("blob string underflow".into()));
        }
        Ok((&b[4..4 + n], &b[4 + n..]))
    }
    let (_key_type, rest) = take_string(blob)?;
    let (_curve_name, rest) = take_string(rest)?;
    let (point, _tail) = take_string(rest)?;
    Ok(point.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_through_decode() {
        // Encode a request, strip the outer wrap, and verify the three
        // fields read back in order.
        let self_blob = b"self-key-bytes";
        let partner_blob = b"partner-key-bytes";
        let flags: u32 = 0xDEADBEEF;

        let encoded = encode_ecdh_request(self_blob, partner_blob, flags);

        // Strip the outer ssh-string wrap.
        let mut outer = WireReader::new(&encoded);
        let inner = outer.get_string().expect("outer ssh-string decodes");
        assert_eq!(outer.remaining(), 0, "no trailing bytes after outer wrap");

        // Read the three inner fields.
        let mut inner_reader = WireReader::new(&inner);
        let got_self = inner_reader.get_string().expect("self blob");
        let got_partner = inner_reader.get_string().expect("partner blob");
        let got_flags = inner_reader.get_u32().expect("flags u32");

        assert_eq!(got_self, self_blob);
        assert_eq!(got_partner, partner_blob);
        assert_eq!(got_flags, flags);
        assert_eq!(inner_reader.remaining(), 0, "inner payload fully consumed");
    }

    #[test]
    fn encode_golden_bytes() {
        // Toy inputs chosen so every byte is distinguishable:
        //   self_key_blob    = AA BB CC               (3 bytes)
        //   partner_key_blob = 11 22                  (2 bytes)
        //   flags            = 0
        //
        // Inner payload, computed by hand:
        //   00 00 00 03  AA BB CC        // self ssh-string    (4+3 = 7 bytes)
        //   00 00 00 02  11 22           // partner ssh-string (4+2 = 6 bytes)
        //   00 00 00 00                  // flags u32 BE       (4 bytes)
        //   total = 7 + 6 + 4 = 17 bytes (= 0x11)
        //
        // Outer ssh-string wrap:
        //   00 00 00 11                  // length prefix = 17 inner bytes
        //   <inner payload>
        //   total = 4 + 17 = 21 bytes
        //
        // NOTE: the issue #32 checkpoint-1 brief quotes "19 bytes / 0x13 /
        // 23 bytes total". That is an arithmetic slip in the brief —
        // counting hex pairs in the inner payload it lists yields 17 bytes,
        // not 19, so the correct outer length is 0x11 and the total is 21.
        // The exact byte sequence from the brief is pinned below (with the
        // length byte corrected).
        let self_blob = [0xAA, 0xBB, 0xCC];
        let partner_blob = [0x11, 0x22];
        let flags: u32 = 0;

        let expected: &[u8] = &[
            // outer length = 17
            0x00, 0x00, 0x00, 0x11, //
            // self ssh-string
            0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC, //
            // partner ssh-string
            0x00, 0x00, 0x00, 0x02, 0x11, 0x22, //
            // flags u32 BE
            0x00, 0x00, 0x00, 0x00,
        ];

        let got = encode_ecdh_request(&self_blob, &partner_blob, flags);
        assert_eq!(got.len(), 21, "total length");
        assert_eq!(got.as_slice(), expected, "byte-exact encoding");
    }

    #[test]
    fn decode_returns_secret_bytes() {
        // ssh-string wrapping { 01 02 03 04 05 }: u32 BE length 5, then bytes.
        let wire: &[u8] = &[0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let secret = decode_ecdh_response(wire).expect("decodes");
        assert_eq!(secret, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn decode_rejects_truncated_header() {
        // Empty.
        let err = decode_ecdh_response(&[]).expect_err("empty input rejected");
        assert!(matches!(err, BoxError::InvalidAgentReply(_)));

        // One, two, three byte inputs are all shorter than the u32 length
        // prefix.
        for n in 1..=3 {
            let buf = vec![0u8; n];
            let err = decode_ecdh_response(&buf).expect_err("truncated header rejected");
            assert!(
                matches!(err, BoxError::InvalidAgentReply(_)),
                "{n}-byte input should surface InvalidAgentReply"
            );
        }
    }

    #[test]
    fn decode_rejects_short_body() {
        // Claims 10 bytes of payload but only supplies 3.
        let wire: &[u8] = &[0x00, 0x00, 0x00, 0x0A, 0xAA, 0xBB, 0xCC];
        let err = decode_ecdh_response(wire).expect_err("short body rejected");
        assert!(matches!(err, BoxError::InvalidAgentReply(_)));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // ssh-string declares 2 payload bytes, but wire has 3 after the
        // prefix — the extra byte must be rejected.
        let wire: &[u8] = &[0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC];
        let err = decode_ecdh_response(wire).expect_err("trailing bytes rejected");
        match err {
            BoxError::InvalidAgentReply(msg) => {
                assert!(
                    msg.contains("trailing"),
                    "error should mention trailing bytes: {msg}"
                );
            }
            other => panic!("expected InvalidAgentReply, got {other:?}"),
        }
    }

    /// Byte-exact golden: the sshkey blob for a toy 65-byte P-256 point.
    ///
    /// Layout (u32 BE length + bytes, concatenated):
    ///   00 00 00 13  "ecdsa-sha2-nistp256"        // 4 + 19 = 23 bytes
    ///   00 00 00 08  "nistp256"                   // 4 +  8 = 12 bytes
    ///   00 00 00 41  (65 bytes: 04 || 00 01 02 ..) // 4 + 65 = 69 bytes
    /// total = 23 + 12 + 69 = 104 bytes.
    #[test]
    fn blob_has_expected_shape_p256() {
        // Build a deterministic 65-byte point: 0x04 prefix + 64 filler bytes.
        // The helper does not (and should not) validate the point shape;
        // this test pins the *wire framing*, not the cryptographic legality
        // of the point.
        let mut point = vec![0x04u8];
        for i in 0..64 {
            point.push(i as u8);
        }
        assert_eq!(point.len(), 65);

        let blob = ec_point_to_ssh_pubkey_blob(EcCurve::NistP256, &point);
        assert_eq!(blob.len(), 104, "framed blob is 104 bytes");

        // First ssh-string: "ecdsa-sha2-nistp256"
        assert_eq!(&blob[0..4], &[0x00, 0x00, 0x00, 0x13]);
        assert_eq!(&blob[4..23], b"ecdsa-sha2-nistp256");

        // Second ssh-string: "nistp256"
        assert_eq!(&blob[23..27], &[0x00, 0x00, 0x00, 0x08]);
        assert_eq!(&blob[27..35], b"nistp256");

        // Third ssh-string: the 65-byte point.
        assert_eq!(&blob[35..39], &[0x00, 0x00, 0x00, 0x41]);
        assert_eq!(&blob[39..104], &point[..]);
    }

    /// Same shape, different curve labels and point length.
    #[test]
    fn blob_has_expected_shape_p384() {
        // 97-byte P-384 point: 0x04 prefix + 96 filler bytes.
        let mut point = vec![0x04u8];
        for i in 0..96 {
            point.push(i as u8);
        }
        assert_eq!(point.len(), 97);

        let blob = ec_point_to_ssh_pubkey_blob(EcCurve::NistP384, &point);
        // 4 + 19 (ecdsa-sha2-nistp384) + 4 + 8 (nistp384) + 4 + 97 = 136
        assert_eq!(blob.len(), 136, "framed blob is 136 bytes");

        assert_eq!(&blob[0..4], &[0x00, 0x00, 0x00, 0x13]);
        assert_eq!(&blob[4..23], b"ecdsa-sha2-nistp384");

        assert_eq!(&blob[23..27], &[0x00, 0x00, 0x00, 0x08]);
        assert_eq!(&blob[27..35], b"nistp384");

        assert_eq!(&blob[35..39], &[0x00, 0x00, 0x00, 0x61]);
        assert_eq!(&blob[39..136], &point[..]);
    }

    /// Pin compatibility with the `ssh-key` crate: feeding a real P-256
    /// key through `PublicKey::to_bytes()` must produce the same bytes as
    /// our helper. This is the canary that tells us the oracle will
    /// accept what we're sending.
    ///
    /// `ssh-key` is added under `[dev-dependencies]` so the production
    /// build of piggy-box stays ssh-key-free.
    #[test]
    fn blob_matches_ssh_key_crate_for_p256() {
        use ssh_key::PublicKey;
        use ssh_key::public::{EcdsaPublicKey, KeyData};

        // Arbitrary but valid P-256 point generated via openssl so this
        // test doesn't depend on a hard-coded key elsewhere.
        let group = openssl::ec::EcGroup::from_curve_name(EcCurve::NistP256.nid()).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let uncompressed = key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(uncompressed.len(), 65);

        let ours = ec_point_to_ssh_pubkey_blob(EcCurve::NistP256, &uncompressed);

        let ecdsa = EcdsaPublicKey::from_sec1_bytes(&uncompressed).unwrap();
        let ssh_pub = PublicKey::from(KeyData::Ecdsa(ecdsa));
        let theirs = ssh_pub.to_bytes().unwrap();

        assert_eq!(
            ours, theirs,
            "our sshkey blob must match ssh-key::PublicKey::to_bytes"
        );
    }

    /// Mirror of the P-256 interop check for P-384.
    #[test]
    fn blob_matches_ssh_key_crate_for_p384() {
        use ssh_key::PublicKey;
        use ssh_key::public::{EcdsaPublicKey, KeyData};

        let group = openssl::ec::EcGroup::from_curve_name(EcCurve::NistP384.nid()).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let uncompressed = key
            .public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(uncompressed.len(), 97);

        let ours = ec_point_to_ssh_pubkey_blob(EcCurve::NistP384, &uncompressed);

        let ecdsa = EcdsaPublicKey::from_sec1_bytes(&uncompressed).unwrap();
        let ssh_pub = PublicKey::from(KeyData::Ecdsa(ecdsa));
        let theirs = ssh_pub.to_bytes().unwrap();

        assert_eq!(
            ours, theirs,
            "P-384 sshkey blob must match ssh-key::PublicKey::to_bytes"
        );
    }

    /// Frame layout for the Ed25519 sibling:
    ///   string("ssh-ed25519")  = 4 + 11 = 15 bytes
    ///   string(32-byte key)    = 4 + 32 = 36 bytes
    /// total = 51 bytes.
    #[test]
    fn blob_has_expected_shape_ed25519() {
        let key: Vec<u8> = (0..32u8).collect();

        let blob = ed25519_to_ssh_pubkey_blob(&key);
        assert_eq!(blob.len(), 51, "framed blob is 51 bytes");

        assert_eq!(&blob[0..4], &[0x00, 0x00, 0x00, 0x0B]);
        assert_eq!(&blob[4..15], b"ssh-ed25519");

        assert_eq!(&blob[15..19], &[0x00, 0x00, 0x00, 0x20]);
        assert_eq!(&blob[19..51], &key[..]);
    }

    /// Mirror of the EC interop checks for Ed25519.
    #[test]
    fn blob_matches_ssh_key_crate_for_ed25519() {
        use ssh_key::PublicKey;
        use ssh_key::public::{Ed25519PublicKey, KeyData};

        // Any 32 bytes are a structurally valid Ed25519 public key for
        // framing purposes; the helper (like its EC sibling) does not
        // validate the point.
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));

        let ours = ed25519_to_ssh_pubkey_blob(&key);

        let ssh_pub = PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(key)));
        let theirs = ssh_pub.to_bytes().unwrap();

        assert_eq!(
            ours, theirs,
            "Ed25519 sshkey blob must match ssh-key::PublicKey::to_bytes"
        );
    }
}
