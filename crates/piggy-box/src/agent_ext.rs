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
}
