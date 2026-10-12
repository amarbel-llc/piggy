//! `piggy card export-attestation` (FDR 0006) — write a slot's attestation
//! bundle (RFC 0012 §5): the text document published beside an operator-act
//! key so a verifier can check that the key was generated on a YubiKey with
//! the policy its attestation states. Read-only and PIN-free.

use openssl::x509::X509;
use piggy_ids::{Classification, ClassifyInput, classify_ssh_slot};
use piggy_piv::PivToken;

use crate::card::init_cmd::{CardSelector, select_provisioned_card};

/// The first line of every bundle (RFC 0012 §5 item 1).
pub const BUNDLE_HEADER: &str = "# piggy-attestation-bundle v1";

/// The slot holding the card's own attestation certificate.
const SLOT_ATTESTATION: u8 = 0xF9;

/// The slots whose key has a signing purpose and so can be exported: 9C, the
/// operator-act key and the default, and 9A.
pub fn export_slot(slot: &str) -> Result<u8, String> {
    match slot.to_ascii_lowercase().as_str() {
        "9c" => Ok(0x9C),
        "9a" => Ok(0x9A),
        _ => Err(format!(
            "unknown slot {slot:?} (export-attestation takes 9c or 9a)"
        )),
    }
}

fn parse_cert(what: &str, der: &[u8]) -> Result<X509, String> {
    X509::from_der(der).map_err(|e| format!("{what} is not a certificate: {e}"))
}

fn public_key_der(what: &str, cert: &X509) -> Result<Vec<u8>, String> {
    cert.public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|e| format!("{what}: unreadable public key: {e}"))
}

fn pem(cert: &X509) -> Result<String, String> {
    let pem = cert.to_pem().map_err(|e| format!("encode PEM: {e}"))?;
    String::from_utf8(pem).map_err(|e| format!("encode PEM: {e}"))
}

/// Assemble the bundle from its parts, refusing to publish one a verifier
/// would reject: the attestation must be for this slot's key and must be
/// signed by the card's attestation certificate. Whether that certificate
/// chains to a Yubico root is the verifier's check (RFC 0012 §5); the root
/// is not shipped in the bundle.
pub fn assemble_bundle(
    key_id: &str,
    authorized_keys_line: &str,
    slot_cert_der: &[u8],
    attestation_der: &[u8],
    intermediate_der: &[u8],
) -> Result<String, String> {
    let slot_cert = parse_cert("the slot certificate", slot_cert_der)?;
    let attestation = parse_cert("the slot attestation", attestation_der)?;
    let intermediate = parse_cert("the card's attestation certificate", intermediate_der)?;

    if public_key_der("the slot attestation", &attestation)?
        != public_key_der("the slot certificate", &slot_cert)?
    {
        return Err(
            "the card's attestation is for a different key than the slot certificate holds".into(),
        );
    }
    // `verify` is Ok(false) for a signature that does not check out.
    let signed_by_card = intermediate
        .public_key()
        .and_then(|key| attestation.verify(&key))
        .map_err(|e| format!("verify the slot attestation: {e}"))?;
    if !signed_by_card {
        return Err(
            "the slot attestation is not signed by the card's attestation certificate".into(),
        );
    }

    Ok(format!(
        "{BUNDLE_HEADER}\n# key {key_id}\n{authorized_keys_line}\n{}{}",
        pem(&attestation)?,
        pem(&intermediate)?
    ))
}

/// Build the bundle for `slot` on `token`.
pub fn bundle_for(token: &PivToken, slot: u8) -> Result<String, String> {
    let guid = token.guid().to_hex();
    let slot_key = token
        .read_slot(slot)
        .map_err(|e| format!("slot {slot:02X} holds no key to attest: {e}"))?;

    let key_id = match classify_ssh_slot(ClassifyInput {
        slot_id: slot,
        guid: token.guid().clone(),
        reader: token.reader_name().to_string(),
        serial: token.yk_serial(),
        serial_diag: None,
        algo: slot_key.algorithm(),
        cert_der: slot_key.cert_der(),
        pin_policy: None,
        touch_policy: None,
    }) {
        Classification::Supported { id, .. } => id.to_string(),
        Classification::Unsupported { reason, .. } => {
            return Err(format!("slot {slot:02X} key has no markl id: {reason}"));
        }
        Classification::Uninitialized { .. } => {
            return Err("the card is not provisioned".into());
        }
    };

    let attestation = token.yk_attest(slot).map_err(|e| {
        format!(
            "the card will not attest slot {slot:02X} ({e}): only a key generated on a YubiKey can be attested, not an imported one"
        )
    })?;
    let intermediate = token
        .read_slot(SLOT_ATTESTATION)
        .map_err(|e| format!("cannot read the card's attestation certificate (slot F9): {e}"))?;

    let mut public_key = slot_key.public_key().clone();
    let short_guid: String = guid.chars().take(8).collect();
    public_key.set_comment(format!(
        "PIV_slot_{slot:02X} card:{}",
        short_guid.to_ascii_lowercase()
    ));
    let line = public_key
        .to_openssh()
        .map_err(|e| format!("encode the public key: {e}"))?;

    assemble_bundle(
        &key_id,
        &line,
        slot_key.cert_der(),
        &attestation,
        intermediate.cert_der(),
    )
}

/// `piggy card export-attestation` entry point: the bundle on stdout. Exit
/// status 2 for a request that is wrong whatever card is attached, 1 for
/// any other failure.
pub fn run(selector: Result<CardSelector, String>, slot: &str) -> i32 {
    let fail = |code: i32, e: &dyn std::fmt::Display| {
        eprintln!("piggy card export-attestation: {e}");
        code
    };
    let slot = match export_slot(slot) {
        Ok(s) => s,
        Err(e) => return fail(2, &e),
    };
    let selector = match selector {
        Ok(s) => s,
        Err(e) => return fail(2, &e),
    };
    let token = match select_provisioned_card(&selector) {
        Ok(t) => t,
        Err(e) => return fail(1, &e),
    };
    match bundle_for(&token, slot) {
        Ok(bundle) => {
            print!("{bundle}");
            0
        }
        Err(e) => fail(1, &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// A certificate for `subject`'s public key signed by `issuer`.
    fn cert(cn: &str, subject: &PKey<Private>, issuer: &PKey<Private>) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(subject).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(issuer, MessageDigest::sha256()).unwrap();
        b.build().to_der().unwrap()
    }

    const KEY_ID: &str = "piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-test";
    const LINE: &str = "ecdsa-sha2-nistp256 AAAA PIV_slot_9C card:5da19c98";

    #[test]
    fn bundle_has_the_five_parts_in_order() {
        let (slot, f9) = (key(), key());
        let bundle = assemble_bundle(
            KEY_ID,
            LINE,
            &cert("piv-sign@5DA19C98", &slot, &slot),
            &cert("attestation 9c", &slot, &f9),
            &cert("f9", &f9, &f9),
        )
        .unwrap();
        let lines: Vec<&str> = bundle.lines().collect();
        assert_eq!(lines[0], BUNDLE_HEADER);
        assert_eq!(lines[1], format!("# key {KEY_ID}"));
        assert_eq!(lines[2], LINE);
        assert_eq!(lines[3], "-----BEGIN CERTIFICATE-----");
        assert_eq!(bundle.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        assert_eq!(bundle.matches("-----END CERTIFICATE-----").count(), 2);
        assert!(bundle.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(
            bundle.matches("# ").count(),
            2,
            "exactly the two comment lines"
        );

        // The first block is the slot attestation, the second the F9 cert.
        let certs = X509::stack_from_pem(bundle.as_bytes()).unwrap();
        let subject = |c: &X509| format!("{:?}", c.subject_name());
        assert!(
            subject(&certs[0]).contains("attestation 9c"),
            "{}",
            subject(&certs[0])
        );
        assert!(subject(&certs[1]).contains("f9"), "{}", subject(&certs[1]));
    }

    #[test]
    fn attestation_for_another_key_is_refused() {
        let (slot, other, f9) = (key(), key(), key());
        let err = assemble_bundle(
            KEY_ID,
            LINE,
            &cert("piv-sign", &slot, &slot),
            &cert("attestation", &other, &f9),
            &cert("f9", &f9, &f9),
        )
        .unwrap_err();
        assert!(err.contains("different key"), "{err}");
    }

    #[test]
    fn attestation_not_signed_by_the_card_certificate_is_refused() {
        let (slot, f9, stranger) = (key(), key(), key());
        let err = assemble_bundle(
            KEY_ID,
            LINE,
            &cert("piv-sign", &slot, &slot),
            &cert("attestation", &slot, &stranger),
            &cert("f9", &f9, &f9),
        )
        .unwrap_err();
        assert!(err.contains("not signed by the card"), "{err}");
    }

    #[test]
    fn only_signing_slots_export() {
        assert_eq!(export_slot("9C"), Ok(0x9C));
        assert_eq!(export_slot("9a"), Ok(0x9A));
        assert!(export_slot("9d").unwrap_err().contains("9c or 9a"));
    }
}
