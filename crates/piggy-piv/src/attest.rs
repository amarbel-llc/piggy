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
const YK_POLICY_OID_BODY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];
/// `1.3.6.1.4.1.41482.3.3`: the firmware version, three bytes
/// (major, minor, patch).
const YK_FIRMWARE_OID_BODY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03];
/// `1.3.6.1.4.1.41482.3.7`: the device serial number, a DER INTEGER.
const YK_SERIAL_OID_BODY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07];

/// The firmware version an attestation names, `(major, minor, patch)`, or
/// `Ok(None)` when the extension is absent (a non-YubiKey attestation).
pub fn firmware_version(cert_der: &[u8]) -> Result<Option<(u8, u8, u8)>, PivError> {
    match extension_value(cert_der, YK_FIRMWARE_OID_BODY)? {
        Some(v) if v.len() == 3 => Ok(Some((v[0], v[1], v[2]))),
        Some(v) => Err(PivError::Tlv {
            message: format!(
                "YubicoPIV firmware extension is {} bytes, expected 3",
                v.len()
            ),
        }),
        None => Ok(None),
    }
}

/// The device serial an attestation names (the DER INTEGER inside the
/// extension), or `Ok(None)` when absent.
pub fn serial_number(cert_der: &[u8]) -> Result<Option<u32>, PivError> {
    let Some(v) = extension_value(cert_der, YK_SERIAL_OID_BODY)? else {
        return Ok(None);
    };
    let mut reader = TlvReader::new(&v);
    let tag = reader.read_tag()?;
    if tag != 0x02 {
        return Err(PivError::Tlv {
            message: format!(
                "YubicoPIV serial extension: expected INTEGER (0x02), got 0x{tag:02X}"
            ),
        });
    }
    let bytes = reader.read_value()?;
    if bytes.is_empty() || bytes.len() > 5 || (bytes.len() == 5 && bytes[0] != 0) {
        return Err(PivError::Tlv {
            message: format!(
                "YubicoPIV serial extension: INTEGER of {} bytes",
                bytes.len()
            ),
        });
    }
    Ok(Some(
        bytes.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)),
    ))
}

/// The `extnValue` contents of the extension with the given OID body, or
/// `Ok(None)` when the certificate carries no such extension. The one
/// walker behind [`parse_policy`], [`firmware_version`] and
/// [`serial_number`].
pub fn extension_value(cert_der: &[u8], oid_body: &[u8]) -> Result<Option<Vec<u8>>, PivError> {
    find_extension(cert_der, oid_body)
}

/// The slot an attestation certificate names as the one it attests: the
/// trailing hex pair of its subject `CN` (`YubiKey PIV Attestation 9c` on
/// a YubiKey, `fibby PIV attestation 9c` on fibby). `Ok(None)` when the
/// subject has no `CN`, or the `CN` ends in no slot. RFC 0012 §2.4 item 5
/// reads the slot from here, the card's own statement, never from the
/// slot a caller asked about.
pub fn attested_slot(cert_der: &[u8]) -> Result<Option<u8>, PivError> {
    use der::Decode;
    use der::asn1::{PrintableStringRef, Utf8StringRef};
    use x509_cert::Certificate;

    const OID_COMMON_NAME: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.4.3");

    let cert = Certificate::from_der(cert_der).map_err(|e| PivError::Tlv {
        message: format!("attestation certificate: {e}"),
    })?;
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid != OID_COMMON_NAME {
                continue;
            }
            let text = if let Ok(s) = atv.value.decode_as::<Utf8StringRef<'_>>() {
                s.as_str().to_owned()
            } else if let Ok(s) = atv.value.decode_as::<PrintableStringRef<'_>>() {
                s.as_str().to_owned()
            } else {
                return Ok(None);
            };
            return Ok(slot_named_by(&text));
        }
    }
    Ok(None)
}

/// The slot a `CN` of the shape `<words> <two hex digits>` names.
fn slot_named_by(common_name: &str) -> Option<u8> {
    let last = common_name.split_whitespace().last()?;
    if last.len() != 2 {
        return None;
    }
    u8::from_str_radix(last, 16).ok()
}

/// Whether the slot attestation certificate `attestation_der` is signed by
/// the card's attestation certificate `intermediate_der` (the one read from
/// slot F9). `Ok(false)` is a signature that does not check out; `Err` is a
/// certificate that could not be read. The one check behind the operator-act
/// handler's policy gate and `piggy card export-attestation`'s bundle (RFC
/// 0012 §2.4, §5); whether F9 chains to a Yubico root is the verifier's.
#[cfg(feature = "openssl-api")]
pub fn attestation_signed_by(
    attestation_der: &[u8],
    intermediate_der: &[u8],
) -> Result<bool, String> {
    let attestation = openssl::x509::X509::from_der(attestation_der)
        .map_err(|e| format!("the slot attestation: {e}"))?;
    let intermediate = openssl::x509::X509::from_der(intermediate_der)
        .map_err(|e| format!("the card's attestation certificate: {e}"))?;
    intermediate
        .public_key()
        .and_then(|key| attestation.verify(&key))
        .map_err(|e| e.to_string())
}

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
    match find_extension(cert_der, YK_POLICY_OID_BODY)? {
        Some(v) if v.len() == 2 => Ok([v[0], v[1]]),
        Some(v) => Err(PivError::Tlv {
            message: format!(
                "YubicoPIV policy extension extnValue is {} bytes, expected 2",
                v.len(),
            ),
        }),
        None => Err(PivError::Tlv {
            message: "YubicoPIV policy extension (OID 1.3.6.1.4.1.41482.3.8) \
                      not present in attestation cert"
                .into(),
        }),
    }
}

/// Walk the certificate to its extensions and return the `extnValue` of
/// the one with `oid_body`, or `None` when it is absent.
fn find_extension(cert_der: &[u8], oid_body: &[u8]) -> Result<Option<Vec<u8>>, PivError> {
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
    // (context-specific constructed tag 0xA3). A certificate with no
    // extensions block has no extension of any OID: that is absence, not a
    // malformed certificate.
    let mut reader = TlvReader::new(tbs);
    while reader.has_remaining() {
        let tag = reader.read_tag()?;
        let value = reader.read_value()?;
        if tag == 0xA3 {
            return find_in_extensions(value, oid_body);
        }
    }
    Ok(None)
}

fn find_in_extensions(
    extensions_wrapper: &[u8],
    oid_body: &[u8],
) -> Result<Option<Vec<u8>>, PivError> {
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
        if let Some(value) = try_parse_extension(one_ext, oid_body)? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// If `extension_body` is the extension with `oid_body`, return its
/// `extnValue` contents. Otherwise return `Ok(None)` — the caller is
/// iterating every extension and only this OID matters.
fn try_parse_extension(
    extension_body: &[u8],
    oid_body: &[u8],
) -> Result<Option<Vec<u8>>, PivError> {
    let mut reader = TlvReader::new(extension_body);

    let oid_tag = reader.read_tag()?;
    if oid_tag != 0x06 {
        // Not an extension we recognise (every Extension SEQUENCE must
        // start with an OID — if it doesn't, skip it rather than fail
        // the whole parse).
        return Ok(None);
    }
    let oid = reader.read_value()?;
    if oid != oid_body {
        return Ok(None);
    }

    // Per RFC 5280:
    //   Extension ::= SEQUENCE {
    //     extnID    OBJECT IDENTIFIER,
    //     critical  BOOLEAN DEFAULT FALSE,
    //     extnValue OCTET STRING
    //   }
    // BOOLEAN is encoded only when non-default. YubiKey's extensions are
    // non-critical, so the byte is typically absent, but handle both shapes.
    let mut next_tag = reader.read_tag()?;
    if next_tag == 0x01 {
        let _ = reader.read_value()?;
        next_tag = reader.read_tag()?;
    }
    if next_tag != 0x04 {
        return Err(PivError::Tlv {
            message: format!(
                "YubicoPIV extension extnValue: expected OCTET STRING (0x04), got 0x{next_tag:02X}"
            ),
        });
    }
    Ok(Some(reader.read_value()?.to_vec()))
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

    /// A certificate whose single extension has the given OID body and
    /// contents, in the same shape as [`synthetic_cert`].
    fn synthetic_cert_with(oid_body: &[u8], contents: &[u8]) -> Vec<u8> {
        let mut extension = vec![0x06, oid_body.len() as u8];
        extension.extend_from_slice(oid_body);
        extension.push(0x04);
        extension.push(contents.len() as u8);
        extension.extend_from_slice(contents);
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
        cert
    }

    #[test]
    fn firmware_and_serial_read_from_their_extensions() {
        let cert = synthetic_cert_with(YK_FIRMWARE_OID_BODY, &[5, 2, 7]);
        assert_eq!(firmware_version(&cert).unwrap(), Some((5, 2, 7)));
        assert_eq!(serial_number(&cert).unwrap(), None, "no serial extension");
        assert!(parse_policy(&cert).is_err(), "no policy extension");

        // INTEGER 0x00F2C8D6 = 15911126, a leading zero for the high bit.
        let cert = synthetic_cert_with(YK_SERIAL_OID_BODY, &[0x02, 0x04, 0x00, 0xF2, 0xC8, 0xD6]);
        assert_eq!(serial_number(&cert).unwrap(), Some(0x00F2_C8D6));
        assert_eq!(serial_number(&cert).unwrap(), Some(15_911_126));
        assert_eq!(firmware_version(&cert).unwrap(), None);

        // A small serial without the leading zero.
        let cert = synthetic_cert_with(YK_SERIAL_OID_BODY, &[0x02, 0x02, 0x01, 0x02]);
        assert_eq!(serial_number(&cert).unwrap(), Some(0x0102));

        // Malformed contents are errors naming the extension, not silence.
        let cert = synthetic_cert_with(YK_FIRMWARE_OID_BODY, &[5, 2]);
        assert!(
            firmware_version(&cert)
                .unwrap_err()
                .to_string()
                .contains("firmware")
        );
        let cert = synthetic_cert_with(YK_SERIAL_OID_BODY, &[0x04, 0x01, 0x00]);
        assert!(
            serial_number(&cert)
                .unwrap_err()
                .to_string()
                .contains("INTEGER")
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

    #[test]
    fn the_attested_slot_is_the_cn_suffix() {
        assert_eq!(slot_named_by("YubiKey PIV Attestation 9c"), Some(0x9C));
        assert_eq!(slot_named_by("YubiKey PIV Attestation 82"), Some(0x82));
        assert_eq!(slot_named_by("fibby PIV attestation 9C"), Some(0x9C));
        assert_eq!(
            slot_named_by("Yubico PIV Attestation"),
            None,
            "the F9 subject"
        );
        assert_eq!(slot_named_by("attestation 9c "), Some(0x9C));
        assert_eq!(slot_named_by("attestation 0x9c"), None);
        assert_eq!(slot_named_by("attestation zz"), None);
        assert_eq!(slot_named_by(""), None);
        assert_eq!(
            slot_named_by("9c"),
            Some(0x9C),
            "a bare slot is the degenerate shape"
        );
    }

    /// A self-signed P-256 certificate whose subject is `CN=<cn>`, built
    /// by OpenSSL so the subject is encoded the way a real certificate's
    /// is (a UTF8String).
    fn cert_with_subject(cn: &str) -> Vec<u8> {
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        b.build().to_der().unwrap()
    }

    #[test]
    fn attested_slot_is_read_from_a_real_certificates_subject() {
        assert_eq!(
            attested_slot(&cert_with_subject("YubiKey PIV Attestation 9c")).unwrap(),
            Some(0x9C)
        );
        assert_eq!(
            attested_slot(&cert_with_subject("YubiKey PIV Attestation 82")).unwrap(),
            Some(0x82)
        );
        assert_eq!(
            attested_slot(&cert_with_subject("fibby PIV attestation 9d")).unwrap(),
            Some(0x9D)
        );
        assert_eq!(
            attested_slot(&cert_with_subject("Yubico PIV Attestation")).unwrap(),
            None,
            "an F9 certificate names no slot"
        );
        assert!(
            attested_slot(b"not a certificate").is_err(),
            "unreadable DER is an error, not an absent slot"
        );
        // The synthetic extension-only shape the policy walker accepts is
        // not a whole certificate: the slot reader, which decodes one,
        // reports it unreadable rather than guessing an absent slot.
        assert!(attested_slot(&synthetic_cert(0x03, 0x02)).is_err());
    }
}
