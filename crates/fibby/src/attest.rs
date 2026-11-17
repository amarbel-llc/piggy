//! fibby's attestation key and the certificates it signs (FDR 0006, the
//! minimal test-surface cut of phase (c)).
//!
//! A YubiKey carries a factory attestation key in slot F9 and answers
//! INS 0xF9 with an X.509 certificate over a slot's public key, signed by
//! that key, for keys it generated itself. The certificate embeds the
//! slot's PIN and touch policy, which is how piggy reads a key's policy
//! (`piggy-piv`'s `attest::parse_policy`).
//!
//! fibby generates one P-256 attestation key per card at construction and
//! a self-signed certificate for it, served as the F9 certificate object.
//! Phase (c) moves the key into guarded memory and phase (f) has the
//! operator's 9C key bless it; the shape (one key per start, policy in
//! the per-slot certificate) is the one those phases keep.

use std::str::FromStr;

use const_oid::ObjectIdentifier;
use der::asn1::{BitString, GeneralizedTime, OctetString};
use der::{Any, DateTime, Encode};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::virtual_card::{SlotPublicKey, push_ber_len};

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// RFC 8410: id-Ed25519, both the key algorithm and the signature
/// algorithm, with absent parameters.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// X.509 basicConstraints (RFC 5280 §4.2.1.9) and its value for a CA:
/// `SEQUENCE { BOOLEAN TRUE }`.
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const BASIC_CONSTRAINTS_CA: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];

/// YubicoPIV attestation extension: firmware version, three bytes
/// `[major, minor, patch]`.
pub const OID_YK_FIRMWARE_VERSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");

/// YubicoPIV attestation extension: the slot's `[pin_policy, touch_policy]`
/// as configured (the bytes GENERATE's `AA`/`AB` tags carried). The one
/// `piggy-piv` and C pivy (`ykpiv_attest_metadata`, vendor/pivy/src/piv.c)
/// read; both require an extnValue of exactly two bytes.
pub const OID_YK_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

/// Subject of the attestation key's own certificate, and so the issuer of
/// every slot attestation.
const ATTESTATION_SUBJECT: &str = "CN=fibby attestation";

/// One card's attestation key and its self-signed F9 certificate.
pub struct AttestationAuthority {
    signing_key: SigningKey,
    name: Name,
    cert_der: Vec<u8>,
}

impl AttestationAuthority {
    /// Generate a fresh attestation key from the OS RNG and self-sign its
    /// certificate. Called once per card, at construction.
    pub fn generate() -> Self {
        Self::from_signing_key(SigningKey::random(&mut rand_core::OsRng))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let name =
            Name::from_str(ATTESTATION_SUBJECT).expect("the attestation subject is a valid DN");
        let point = VerifyingKey::from(&signing_key).to_encoded_point(false);
        // The F9 certificate issues the slot attestations, so it says it is
        // a CA: a verifier that checks the chain with a stock X.509 library
        // (`openssl verify`) rejects an issuer that does not.
        let ca = Extension {
            extn_id: OID_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(BASIC_CONSTRAINTS_CA)
                .expect("a short extension value encodes"),
        };
        let cert_der = issue_certificate(
            &Issuer::P256(&signing_key),
            &name,
            &name,
            1,
            &SlotPublicKey::P256(point.as_bytes().to_vec()),
            Some(vec![ca]),
        );
        AttestationAuthority {
            signing_key,
            name,
            cert_der,
        }
    }

    /// The attestation key's self-signed certificate, DER.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The F9 certificate as a PIV certificate object, the framing every
    /// slot certificate has in GET DATA:
    /// `53 { 70 <cert DER> 71 01 00 FE 00 }`.
    pub fn cert_object(&self) -> Vec<u8> {
        piv_cert_object(&self.cert_der)
    }

    /// Attest a slot key this card generated: an X.509 certificate over
    /// `slot_key` (a P-256 or Ed25519 SubjectPublicKeyInfo), issued and
    /// signed (ECDSA-SHA256) by the attestation key, carrying the firmware
    /// version and the slot's stored `[pin, touch]` policy as non-critical
    /// extensions. Returns the certificate DER.
    pub fn attest_slot(
        &self,
        slot: u8,
        slot_key: &SlotPublicKey,
        policy: [u8; 2],
        firmware_version: [u8; 3],
    ) -> Vec<u8> {
        let subject = Name::from_str(&format!("CN=fibby PIV attestation {slot:02x}"))
            .expect("a slot attestation subject is a valid DN");
        let extensions = vec![
            octet_string_extension(OID_YK_FIRMWARE_VERSION, &firmware_version),
            octet_string_extension(OID_YK_POLICY, &policy),
        ];
        issue_certificate(
            &Issuer::P256(&self.signing_key),
            &self.name,
            &subject,
            // Any positive serial will do; the slot id keeps the four slot
            // attestations of one card distinct from each other and from
            // the F9 certificate's serial 1.
            0x100 + u32::from(slot),
            slot_key,
            Some(extensions),
        )
    }
}

/// A self-signed X.509 certificate over the Ed25519 key with `seed`,
/// subject `CN=<common_name>`: what a client reads from a slot's
/// certificate object to learn its algorithm and public key. Test-double
/// only (the seed flags); a holder's certificates come with item 6 of
/// piggy#382.
#[cfg(feature = "test-double")]
pub fn self_signed_ed25519_certificate(seed: &[u8; 32], common_name: &str) -> Vec<u8> {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    let name = Name::from_str(&format!("CN={common_name}"))
        .expect("a seeded certificate's subject is a valid DN");
    issue_certificate(
        &Issuer::Ed25519(&key),
        &name,
        &name,
        1,
        &SlotPublicKey::Ed25519(key.verifying_key().to_bytes()),
        None,
    )
}

/// The key a certificate is signed with, and so its signature algorithm.
enum Issuer<'a> {
    /// ECDSA-SHA256.
    P256(&'a SigningKey),
    /// Ed25519 (RFC 8410: the whole TBS is signed, no prehash).
    #[cfg_attr(not(feature = "test-double"), allow(dead_code))]
    Ed25519(&'a ed25519_dalek::SigningKey),
}

impl Issuer<'_> {
    fn algorithm(&self) -> AlgorithmIdentifierOwned {
        let oid = match self {
            Issuer::P256(_) => OID_ECDSA_SHA256,
            Issuer::Ed25519(_) => OID_ED25519,
        };
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    fn sign(&self, tbs_der: &[u8]) -> Vec<u8> {
        match self {
            // `Signer` hashes with SHA-256 and signs with RFC 6979 nonces.
            Issuer::P256(key) => {
                let signature: Signature = key.sign(tbs_der);
                signature.to_der().as_bytes().to_vec()
            }
            Issuer::Ed25519(key) => ed25519_dalek::Signer::sign(*key, tbs_der)
                .to_bytes()
                .to_vec(),
        }
    }
}

/// The SubjectPublicKeyInfo of a slot key: id-ecPublicKey over prime256v1
/// with the SEC1 point, or id-Ed25519 (no parameters) with the raw key.
fn subject_public_key_info(key: &SlotPublicKey) -> SubjectPublicKeyInfoOwned {
    let (algorithm, bits) = match key {
        SlotPublicKey::P256(point) => (
            AlgorithmIdentifierOwned {
                oid: OID_EC_PUBLIC_KEY,
                parameters: Some(Any::from(&OID_PRIME256V1)),
            },
            point.as_slice(),
        ),
        SlotPublicKey::Ed25519(raw) => (
            AlgorithmIdentifierOwned {
                oid: OID_ED25519,
                parameters: None,
            },
            raw.as_slice(),
        ),
    };
    SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key: BitString::from_bytes(bits).expect("a public key fits a BIT STRING"),
    }
}

/// A certificate DER framed as a PIV certificate object, as GET DATA
/// serves every slot certificate: `53 { 70 <cert DER> 71 01 00 FE 00 }`.
pub fn piv_cert_object(cert_der: &[u8]) -> Vec<u8> {
    let mut inner = vec![0x70];
    push_ber_len(&mut inner, cert_der.len());
    inner.extend_from_slice(cert_der);
    inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
    let mut object = vec![0x53];
    push_ber_len(&mut object, inner.len());
    object.extend_from_slice(&inner);
    object
}

/// A non-critical extension whose extnValue is the raw `value` bytes.
fn octet_string_extension(oid: ObjectIdentifier, value: &[u8]) -> Extension {
    Extension {
        extn_id: oid,
        critical: false,
        extn_value: OctetString::new(value).expect("a short extension value encodes"),
    }
}

/// Build and sign one certificate. Every input is either a constant or a
/// valid public key produced by this process, so encoding cannot fail;
/// a failure is a programming error and panics with the step that broke.
fn issue_certificate(
    issuer_key: &Issuer,
    issuer: &Name,
    subject: &Name,
    serial: u32,
    subject_key: &SlotPublicKey,
    extensions: Option<Vec<Extension>>,
) -> Vec<u8> {
    let signature_algorithm = issuer_key.algorithm();
    let fixed_time = |year| {
        Time::GeneralTime(GeneralizedTime::from_date_time(
            DateTime::new(year, 1, 1, 0, 0, 0).expect("a fixed calendar date is valid"),
        ))
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(serial),
        signature: signature_algorithm.clone(),
        issuer: issuer.clone(),
        validity: Validity {
            not_before: fixed_time(2024),
            not_after: fixed_time(2074),
        },
        subject: subject.clone(),
        subject_public_key_info: subject_public_key_info(subject_key),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    };
    let tbs_der = tbs.to_der().expect("a TBSCertificate encodes");
    let signature = issuer_key.sign(&tbs_der);
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature: BitString::from_bytes(&signature).expect("a signature fits a BIT STRING"),
    }
    .to_der()
    .expect("a Certificate encodes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use p256::ecdsa::signature::Verifier;

    /// The signature over `cert`'s TBS verifies under `issuer_cert`'s key.
    fn verifies_under(cert: &Certificate, issuer_cert: &Certificate) -> bool {
        let issuer_point = issuer_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let key = VerifyingKey::from_sec1_bytes(issuer_point).unwrap();
        let signature = Signature::from_der(cert.signature.raw_bytes()).unwrap();
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        key.verify(&tbs_der, &signature).is_ok()
    }

    #[test]
    fn attestation_certificate_is_self_signed_x509() {
        let authority = AttestationAuthority::generate();
        let cert = Certificate::from_der(authority.cert_der()).unwrap();
        assert_eq!(
            cert.tbs_certificate.subject.to_string(),
            ATTESTATION_SUBJECT
        );
        assert_eq!(cert.tbs_certificate.issuer, cert.tbs_certificate.subject);
        assert!(verifies_under(&cert, &cert), "self-signature verifies");
    }

    #[test]
    fn each_authority_has_its_own_key() {
        let a = AttestationAuthority::generate();
        let b = AttestationAuthority::generate();
        assert_ne!(a.cert_der(), b.cert_der());
    }

    #[test]
    fn cert_object_wraps_the_certificate_like_a_slot_cert() {
        let authority = AttestationAuthority::generate();
        let object = authority.cert_object();
        let der = authority.cert_der();
        // 53 82 LL LL 70 82 LL LL <der> 71 01 00 FE 00 (a P-256 cert is
        // always between 256 and 65535 bytes).
        assert_eq!(object[0], 0x53);
        assert_eq!(object[1], 0x82);
        assert_eq!(
            usize::from(object[2]) << 8 | usize::from(object[3]),
            object.len() - 4
        );
        assert_eq!(&object[4..6], &[0x70, 0x82]);
        assert_eq!(
            usize::from(object[6]) << 8 | usize::from(object[7]),
            der.len()
        );
        assert_eq!(&object[8..8 + der.len()], der);
        assert_eq!(&object[8 + der.len()..], &[0x71, 0x01, 0x00, 0xFE, 0x00]);
    }

    #[test]
    fn slot_attestation_chains_to_the_authority_and_carries_the_extensions() {
        let authority = AttestationAuthority::generate();
        let slot_key = SigningKey::random(&mut rand_core::OsRng);
        let point = VerifyingKey::from(&slot_key).to_encoded_point(false);

        let der = authority.attest_slot(
            0x9C,
            &SlotPublicKey::P256(point.as_bytes().to_vec()),
            [0x03, 0x02],
            [5, 2, 7],
        );
        let cert = Certificate::from_der(&der).unwrap();
        let f9 = Certificate::from_der(authority.cert_der()).unwrap();

        assert!(verifies_under(&cert, &f9), "signed by the attestation key");
        assert_eq!(cert.tbs_certificate.issuer, f9.tbs_certificate.subject);
        assert_eq!(
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
            point.as_bytes(),
            "the subject key is the slot key"
        );
        let extensions = cert.tbs_certificate.extensions.unwrap();
        let value_of = |oid| {
            let ext = extensions.iter().find(|e| e.extn_id == oid).unwrap();
            assert!(!ext.critical, "{oid} is non-critical");
            ext.extn_value.as_bytes().to_vec()
        };
        assert_eq!(value_of(OID_YK_POLICY), vec![0x03, 0x02]);
        assert_eq!(value_of(OID_YK_FIRMWARE_VERSION), vec![5, 2, 7]);
    }

    #[test]
    fn an_ed25519_slot_attestation_carries_an_rfc8410_spki() {
        let authority = AttestationAuthority::generate();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let raw = key.verifying_key().to_bytes();
        let der =
            authority.attest_slot(0x9A, &SlotPublicKey::Ed25519(raw), [0x02, 0x01], [5, 7, 1]);
        let cert = Certificate::from_der(&der).unwrap();
        let f9 = Certificate::from_der(authority.cert_der()).unwrap();
        assert!(verifies_under(&cert, &f9), "signed by the attestation key");
        let spki = &cert.tbs_certificate.subject_public_key_info;
        assert_eq!(spki.algorithm.oid, OID_ED25519);
        assert!(spki.algorithm.parameters.is_none(), "RFC 8410: absent");
        assert_eq!(spki.subject_public_key.raw_bytes(), raw.as_slice());
    }

    #[cfg(feature = "test-double")]
    #[test]
    fn a_self_signed_ed25519_certificate_verifies_under_its_own_key() {
        let seed = [9u8; 32];
        let der = self_signed_ed25519_certificate(&seed, "piggy-test ed25519");
        let cert = Certificate::from_der(&der).unwrap();
        assert_eq!(cert.signature_algorithm.oid, OID_ED25519);
        let key = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        let signature = ed25519_dalek::Signature::from_slice(cert.signature.raw_bytes()).unwrap();
        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        key.verify_strict(&tbs_der, &signature).unwrap();
    }
}
