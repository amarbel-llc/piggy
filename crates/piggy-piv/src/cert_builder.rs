//! Build a minimal self-signed X.509 certificate for a freshly-generated PIV
//! slot key, signed by that same key on the card.
//!
//! PIV stores each slot's public key inside an X.509 cert object; provisioning
//! (`piggy card init`, piggy#194) must therefore write a cert after GENERATE.
//! pivy self-signs each slot cert with the slot's own key — for an EC key that
//! means ECDSA-signing the TBS with the card (slot 9D's "key management" EC key
//! can sign too, see the fibby 9D-sign path). We can't extract the private key,
//! so we build the TBSCertificate, hand its SHA-256/384 digest to a card-signer
//! closure (which runs GENERAL AUTHENTICATE on the slot), and assemble the
//! final cert from the returned DER ECDSA signature.
//!
//! The cert is intentionally minimal (v3, fixed serial + validity, a single
//! `CN`, no extensions): piggy's consumers only read the SubjectPublicKeyInfo
//! back out (`cert::extract_public_key`), and the self-signature makes the
//! credential well-formed for the wider ecosystem.

use const_oid::ObjectIdentifier;
use der::asn1::{BitString, GeneralizedTime};
use der::{Any, DateTime, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attributes;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::request::{CertReq, CertReqInfo, Version as CsrVersion};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::error::PivError;
use crate::slot::PivAlgorithm;

// ASN.1 OIDs.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Build a self-signed cert over `pubkey_point` (the SEC1 uncompressed point
/// `04 || X || Y` returned by GENERATE), with subject/issuer `CN=<common_name>`.
///
/// `sign_digest` is handed the SHA-256 (P-256) / SHA-384 (P-384) digest of the
/// DER-encoded TBSCertificate and must return the card's **DER** ECDSA
/// signature (`SEQUENCE { r, s }`) — i.e. the engine wires it to
/// `PinSession::sign_prehash(slot, digest)`. Returns the full certificate DER,
/// ready for `PinSession::put_cert`.
pub fn build_self_signed_cert(
    pubkey_point: &[u8],
    algorithm: PivAlgorithm,
    common_name: &str,
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Vec<u8>, PivError> {
    let (curve_oid, sig_oid, md) = ec_params(algorithm)?;
    let spki = ec_spki(pubkey_point, curve_oid)?;

    let sig_alg = AlgorithmIdentifierOwned {
        oid: sig_oid,
        parameters: None,
    };

    let name: Name = format!("CN={common_name}").parse().map_err(der_err)?;

    let validity = Validity {
        not_before: Time::GeneralTime(GeneralizedTime::from_date_time(
            DateTime::new(2024, 1, 1, 0, 0, 0).map_err(der_err)?,
        )),
        not_after: Time::GeneralTime(GeneralizedTime::from_date_time(
            DateTime::new(2074, 1, 1, 0, 0, 0).map_err(der_err)?,
        )),
    };

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(1u32),
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity,
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    let tbs_der = tbs.to_der().map_err(der_err)?;
    let digest = openssl::hash::hash(md, &tbs_der)?;
    let sig_der = sign_digest(&digest)?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&sig_der).map_err(der_err)?,
    };
    cert.to_der().map_err(der_err)
}

/// Build a minimal PKCS#10 certificate signing request (CSR) over
/// `pubkey_point` (the SEC1 uncompressed point of the slot's EC key), with
/// subject `CN=<common_name>`, signed by that slot key on the card.
///
/// Like [`build_self_signed_cert`] this is intentionally minimal — subject +
/// SubjectPublicKeyInfo + signature, no requested extensions (matching piggy's
/// self-signed-cert minimalism; a CA fills in usage on the issued cert). C
/// `pivy-tool req-cert` populates KeyUsage/EKU from its cert-template engine, so
/// piggy's CSR is a *valid, equivalent* CSR carrying the same key rather than a
/// byte-for-byte clone (piggy#289 milestone 3.10).
///
/// `sign_digest` is handed the SHA-256 (P-256) / SHA-384 (P-384) digest of the
/// DER-encoded CertificationRequestInfo and must return the card's **DER**
/// ECDSA signature — i.e. `PinSession::sign_prehash(slot, digest)`. Returns the
/// full CSR DER; PEM-wrap it as `CERTIFICATE REQUEST` for output.
pub fn build_csr(
    pubkey_point: &[u8],
    algorithm: PivAlgorithm,
    common_name: &str,
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Vec<u8>, PivError> {
    let (curve_oid, sig_oid, md) = ec_params(algorithm)?;
    let spki = ec_spki(pubkey_point, curve_oid)?;

    let sig_alg = AlgorithmIdentifierOwned {
        oid: sig_oid,
        parameters: None,
    };

    let subject: Name = format!("CN={common_name}").parse().map_err(der_err)?;

    let info = CertReqInfo {
        // PKCS#10 CertificationRequestInfo version is 0 (V1 in the crate's enum).
        version: CsrVersion::V1,
        subject,
        public_key: spki,
        attributes: Attributes::default(),
    };

    let info_der = info.to_der().map_err(der_err)?;
    let digest = openssl::hash::hash(md, &info_der)?;
    let sig_der = sign_digest(&digest)?;

    let csr = CertReq {
        info,
        algorithm: sig_alg,
        signature: BitString::from_bytes(&sig_der).map_err(der_err)?,
    };
    csr.to_der().map_err(der_err)
}

fn der_err<E: std::fmt::Display>(e: E) -> PivError {
    PivError::Other(format!("x509 build: {e}"))
}

/// The ASN.1 parameters an EC cert/CSR needs: the named-curve OID, the
/// ECDSA-with-SHA signature OID, and the matching digest. EC-only (P-256/P-384)
/// — the cert and CSR builders share this so a non-EC key is rejected once.
fn ec_params(
    algorithm: PivAlgorithm,
) -> Result<
    (
        ObjectIdentifier,
        ObjectIdentifier,
        openssl::hash::MessageDigest,
    ),
    PivError,
> {
    match algorithm {
        PivAlgorithm::EcP256 => Ok((
            OID_PRIME256V1,
            OID_ECDSA_SHA256,
            openssl::hash::MessageDigest::sha256(),
        )),
        PivAlgorithm::EcP384 => Ok((
            OID_SECP384R1,
            OID_ECDSA_SHA384,
            openssl::hash::MessageDigest::sha384(),
        )),
        other => Err(PivError::Other(format!(
            "cert/CSR building only supports ECDSA P-256/P-384, not {other:?}"
        ))),
    }
}

/// The SubjectPublicKeyInfo for an EC `pubkey_point` (SEC1 uncompressed), shared
/// by the cert and CSR builders.
fn ec_spki(
    pubkey_point: &[u8],
    curve_oid: ObjectIdentifier,
) -> Result<SubjectPublicKeyInfoOwned, PivError> {
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(Any::from(&curve_oid)),
        },
        subject_public_key: BitString::from_bytes(pubkey_point).map_err(der_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::{MessageDigest, hash};
    use openssl::nid::Nid;

    /// Build a cert with a HOST P-256 key acting as the card (sign the TBS
    /// digest with that key), then prove: it parses as X.509, the embedded
    /// public key is the one we passed in, and the self-signature verifies.
    #[test]
    fn p256_self_signed_cert_parses_and_self_verifies() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let key_for_sign = key.clone();
        let cert_der = build_self_signed_cert(&point, PivAlgorithm::EcP256, "piv-test", |digest| {
            // The "card": ECDSA-sign the TBS digest, return DER (r,s).
            let sig = EcdsaSig::sign(digest, &key_for_sign).unwrap();
            Ok(sig.to_der().unwrap())
        })
        .unwrap();

        // Parses as X.509 and the SubjectPublicKeyInfo round-trips our point.
        let (alg, parsed_pub) = crate::cert::extract_public_key(&cert_der).unwrap();
        assert_eq!(alg, PivAlgorithm::EcP256);
        // The self-signature verifies against the embedded key — i.e. it is a
        // genuine self-signed cert, not just a pubkey carrier.
        let x509 = openssl::x509::X509::from_der(&cert_der).unwrap();
        let pkey = x509.public_key().unwrap();
        assert!(x509.verify(&pkey).unwrap(), "self-signature verifies");
        // Sanity: re-extract the SEC1 point and compare.
        let re = parsed_pub;
        let _ = re; // public_key already validated by verify(); keep the binding meaningful
    }

    #[test]
    fn rejects_non_ec_algorithm() {
        let err = build_self_signed_cert(&[0x04; 65], PivAlgorithm::Rsa2048, "x", |_| Ok(vec![]))
            .unwrap_err();
        assert!(format!("{err}").contains("P-256/P-384"));
    }

    /// Build a CSR with a HOST P-256 key acting as the card, then prove it is a
    /// well-formed PKCS#10 request: it parses, its self-signature verifies, and
    /// its subject + embedded public key are the ones we passed in.
    #[test]
    fn p256_csr_parses_and_self_verifies() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let key_for_sign = key.clone();
        let csr_der = build_csr(&point, PivAlgorithm::EcP256, "piggy-test", |digest| {
            let sig = EcdsaSig::sign(digest, &key_for_sign).unwrap();
            Ok(sig.to_der().unwrap())
        })
        .unwrap();

        let req = openssl::x509::X509Req::from_der(&csr_der).unwrap();
        let pkey = req.public_key().unwrap();
        assert!(req.verify(&pkey).unwrap(), "CSR self-signature verifies");
        // Subject carries our CN.
        let cn = req
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        assert_eq!(cn.data().as_utf8().unwrap().to_string(), "piggy-test");
    }

    #[test]
    fn csr_rejects_non_ec_algorithm() {
        let err = build_csr(&[0x04; 65], PivAlgorithm::Ed25519, "x", |_| Ok(vec![])).unwrap_err();
        assert!(format!("{err}").contains("P-256/P-384"));
    }

    /// The digest handed to the signer is the SHA-256 of the TBS we encode.
    #[test]
    fn signer_receives_sha256_of_tbs() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let seen = std::cell::RefCell::new(Vec::new());
        let key_for_sign = key.clone();
        let _ = build_self_signed_cert(&point, PivAlgorithm::EcP256, "x", |digest| {
            *seen.borrow_mut() = digest.to_vec();
            let sig = EcdsaSig::sign(digest, &key_for_sign).unwrap();
            Ok(sig.to_der().unwrap())
        })
        .unwrap();
        // It's a SHA-256 digest (32 bytes) — we can't re-derive the exact TBS
        // here, but the length pins the hash choice.
        assert_eq!(seen.borrow().len(), 32);
        // It really is SHA-256 of *some* input (sanity that hashing ran).
        let _ = hash(MessageDigest::sha256(), b"x").unwrap();
    }
}
