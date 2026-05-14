//! Parse YubicoPIV attestation certificates.
//!
//! The YubiKey attestation cert returned by INS_ATTEST (0xF9) embeds
//! several Yubico-specific X.509 extensions. The one piggy cares about
//! is `1.3.6.1.4.1.41482.3.8` — the per-slot PIN and touch policy. Its
//! `extnValue` is a 2-byte OCTET STRING `[pin_policy, touch_policy]`,
//! the same byte values used by INS_GET_METADATA tag 0x02. See
//! `vendor/pivy/src/piv.c` (`ykpiv_attest_decode`) for the reference
//! implementation.
//!
//! We walk the cert DER by hand rather than pulling in a full X.509
//! parsing crate — the openssl crate doesn't expose unknown-OID
//! extension data, the structure we care about is shallow, and we
//! already have a BER-TLV reader for PIV data objects.

use crate::error::PivError;
use crate::policy::{PinPolicy, TouchPolicy};
use crate::tlv::TlvReader;

/// DER-encoded OID body for `1.3.6.1.4.1.41482.3.8` (YubicoPIV PIN +
/// touch policy attestation extension). Encoded as the contents of an
/// OID OBJECT IDENTIFIER tag, not including the leading `06 LL` tag
/// and length bytes.
const YK_POLICY_OID_BODY: &[u8] = &[
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08,
];

/// Extract `(PinPolicy, TouchPolicy)` from a YubiKey attestation cert.
///
/// Returns `PivError::Tlv` if the cert can't be walked far enough to
/// find the policy extension (malformed DER, missing extensions, or
/// the YubicoPIV policy OID just isn't present — e.g. attestation from
/// a non-YubiKey card).
pub fn parse_policy(cert_der: &[u8]) -> Result<(PinPolicy, TouchPolicy), PivError> {
    let [pin_byte, touch_byte] = find_policy_bytes(cert_der)?;
    let pin = PinPolicy::from_byte(pin_byte)?;
    let touch = TouchPolicy::from_byte(touch_byte)?;
    Ok((pin, touch))
}

fn find_policy_bytes(cert_der: &[u8]) -> Result<[u8; 2], PivError> {
    // Certificate ::= SEQUENCE
    let mut reader = TlvReader::new(cert_der);
    let tag = reader.read_tag()?;
    if tag != 0x30 {
        return Err(PivError::Tlv {
            message: format!("expected outer SEQUENCE, got tag 0x{tag:02X}"),
        });
    }
    let cert_body = reader.read_value()?;

    // TBSCertificate ::= SEQUENCE
    let mut reader = TlvReader::new(cert_body);
    let tag = reader.read_tag()?;
    if tag != 0x30 {
        return Err(PivError::Tlv {
            message: format!("expected TBSCertificate SEQUENCE, got tag 0x{tag:02X}"),
        });
    }
    let tbs = reader.read_value()?;

    // Walk TBSCertificate fields, looking for [3] EXPLICIT extensions
    // (context-specific constructed tag 0xA3).
    let mut reader = TlvReader::new(tbs);
    while reader.has_remaining() {
        let tag = reader.read_tag()?;
        let value = reader.read_value()?;
        if tag == 0xA3 {
            return find_policy_in_extensions(value);
        }
    }
    Err(PivError::Tlv {
        message: "TBSCertificate has no extensions ([3] context tag)".into(),
    })
}

fn find_policy_in_extensions(extensions_wrapper: &[u8]) -> Result<[u8; 2], PivError> {
    // The [3] EXPLICIT wrapper contains a single SEQUENCE OF Extension.
    let mut reader = TlvReader::new(extensions_wrapper);
    let tag = reader.read_tag()?;
    if tag != 0x30 {
        return Err(PivError::Tlv {
            message: format!("expected Extensions SEQUENCE, got tag 0x{tag:02X}"),
        });
    }
    let ext_seq = reader.read_value()?;

    let mut reader = TlvReader::new(ext_seq);
    while reader.has_remaining() {
        let tag = reader.read_tag()?;
        if tag != 0x30 {
            // Skip non-SEQUENCE entries defensively — DER says they
            // can't appear inside SEQUENCE OF Extension, but firmware
            // bugs happen.
            let _ = reader.read_value()?;
            continue;
        }
        let one_ext = reader.read_value()?;
        if let Some(policy) = try_parse_policy_extension(one_ext)? {
            return Ok(policy);
        }
    }
    Err(PivError::Tlv {
        message: "YubicoPIV policy extension (OID 1.3.6.1.4.1.41482.3.8) \
                  not present in attestation cert"
            .into(),
    })
}

/// If `extension_body` is the YubiKey policy extension, return its two
/// policy bytes. Otherwise return `Ok(None)` — the caller is iterating
/// every extension and only this OID matters.
fn try_parse_policy_extension(extension_body: &[u8]) -> Result<Option<[u8; 2]>, PivError> {
    let mut reader = TlvReader::new(extension_body);

    let oid_tag = reader.read_tag()?;
    if oid_tag != 0x06 {
        // Not an extension we recognise (every Extension SEQUENCE must
        // start with an OID — if it doesn't, skip it rather than fail
        // the whole parse).
        return Ok(None);
    }
    let oid = reader.read_value()?;
    if oid != YK_POLICY_OID_BODY {
        return Ok(None);
    }

    // Per RFC 5280:
    //   Extension ::= SEQUENCE {
    //     extnID    OBJECT IDENTIFIER,
    //     critical  BOOLEAN DEFAULT FALSE,
    //     extnValue OCTET STRING
    //   }
    // BOOLEAN is encoded only when non-default. YubiKey's policy
    // extension is non-critical, so the byte is typically absent, but
    // handle both shapes.
    let mut next_tag = reader.read_tag()?;
    if next_tag == 0x01 {
        let _ = reader.read_value()?;
        next_tag = reader.read_tag()?;
    }
    if next_tag != 0x04 {
        return Err(PivError::Tlv {
            message: format!(
                "YubicoPIV policy extension extnValue: expected OCTET STRING (0x04), got 0x{next_tag:02X}"
            ),
        });
    }
    let extn_value = reader.read_value()?;
    if extn_value.len() != 2 {
        return Err(PivError::Tlv {
            message: format!(
                "YubicoPIV policy extension extnValue is {} bytes, expected 2",
                extn_value.len(),
            ),
        });
    }
    Ok(Some([extn_value[0], extn_value[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal byte-valid DER blob that the policy parser
    /// accepts. Real X.509 certs have many more fields between version
    /// and extensions; our parser walks past anything that isn't the
    /// [3] context tag, so we don't bother emitting them.
    fn synthetic_cert(pin_byte: u8, touch_byte: u8) -> Vec<u8> {
        // Extension: SEQUENCE { OID, OCTET STRING { pin, touch } }
        let mut extension = Vec::new();
        // OID tag (0x06), length, body
        extension.push(0x06);
        extension.push(YK_POLICY_OID_BODY.len() as u8);
        extension.extend_from_slice(YK_POLICY_OID_BODY);
        // OCTET STRING tag (0x04), length 2, [pin, touch]
        extension.extend_from_slice(&[0x04, 0x02, pin_byte, touch_byte]);

        let mut extension_wrap = Vec::new();
        extension_wrap.push(0x30); // SEQUENCE
        extension_wrap.push(extension.len() as u8);
        extension_wrap.extend(extension);

        // Extensions SEQUENCE OF
        let mut extensions_seq = Vec::new();
        extensions_seq.push(0x30);
        extensions_seq.push(extension_wrap.len() as u8);
        extensions_seq.extend(extension_wrap);

        // [3] EXPLICIT wrapper
        let mut ctx3 = Vec::new();
        ctx3.push(0xA3);
        ctx3.push(extensions_seq.len() as u8);
        ctx3.extend(extensions_seq);

        // TBSCertificate SEQUENCE
        let mut tbs = Vec::new();
        tbs.push(0x30);
        tbs.push(ctx3.len() as u8);
        tbs.extend(ctx3);

        // Certificate SEQUENCE
        let mut cert = Vec::new();
        cert.push(0x30);
        cert.push(tbs.len() as u8);
        cert.extend(tbs);

        cert
    }

    #[test]
    fn parses_policy_from_synthetic_attestation() {
        let cert = synthetic_cert(0x02, 0x03);
        let (pin, touch) = parse_policy(&cert).unwrap();
        assert_eq!(pin, PinPolicy::Once);
        assert_eq!(touch, TouchPolicy::Cached);
    }

    #[test]
    fn parses_never_never() {
        let cert = synthetic_cert(0x01, 0x01);
        let (pin, touch) = parse_policy(&cert).unwrap();
        assert_eq!(pin, PinPolicy::Never);
        assert_eq!(touch, TouchPolicy::Never);
    }

    #[test]
    fn missing_policy_extension_is_error() {
        // Cert with extensions wrapper but no YubicoPIV policy OID
        // inside — parser walks the cert, finds no matching extension,
        // returns Err.
        let other_oid = [0x55, 0x04, 0x03]; // 2.5.4.3 = commonName
        let mut extension = Vec::new();
        extension.push(0x06);
        extension.push(other_oid.len() as u8);
        extension.extend_from_slice(&other_oid);
        extension.extend_from_slice(&[0x04, 0x03, b'f', b'o', b'o']);
        let mut extension_wrap = vec![0x30, extension.len() as u8];
        extension_wrap.extend(extension);
        let mut extensions_seq = vec![0x30, extension_wrap.len() as u8];
        extensions_seq.extend(extension_wrap);
        let mut ctx3 = vec![0xA3, extensions_seq.len() as u8];
        ctx3.extend(extensions_seq);
        let mut tbs = vec![0x30, ctx3.len() as u8];
        tbs.extend(ctx3);
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend(tbs);

        let err = parse_policy(&cert).unwrap_err();
        assert!(
            err.to_string().contains("not present"),
            "expected missing-extension error, got: {err}"
        );
    }

    #[test]
    fn unknown_policy_byte_propagates() {
        // pin_byte = 0xFF is outside the YubicoPIV PIN policy table; it
        // should propagate as a from_byte error rather than be silently
        // treated as Default.
        let cert = synthetic_cert(0xFF, 0x01);
        let err = parse_policy(&cert).unwrap_err();
        assert!(err.to_string().contains("0xFF"), "got: {err}");
    }
}
