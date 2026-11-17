//! The three X.509 certificate profiles of FDR 0007 (a card-held root, a
//! holder-held intermediate, name-constrained leaves), phase (i),
//! piggy#393.
//!
//! Each builder takes the subject's public key, the few values a profile
//! leaves to its caller (a common name, the permitted DNS names, the
//! validity, the serial), and a signer closure of the shape
//! [`crate::cert_builder`] uses: it is handed the SHA-256 (P-256 issuer) or
//! SHA-384 (P-384 issuer) digest of the DER TBSCertificate and returns the
//! issuer's DER ECDSA signature, from a card slot or any other key. Every
//! extension comes from the profile, never from the caller:
//!
//! | Field | Root | Intermediate | Leaf |
//! |---|---|---|---|
//! | basicConstraints | critical, CA, pathlen 1 | critical, CA, pathlen 0 | critical, not a CA |
//! | keyUsage | critical, keyCertSign, cRLSign | same | critical, digitalSignature |
//! | extendedKeyUsage | absent | absent | serverAuth |
//! | subjectAltName | absent | absent | `DNS:` each name |
//! | nameConstraints | critical; permitted `DNS:` each name; excluded every IPv4 and IPv6 address | same | absent |
//! | subjectKeyIdentifier | yes | yes | yes |
//! | authorityKeyIdentifier | own SKI | issuer's SKI | issuer's SKI |
//!
//! The caller supplies the serial and the times, so this crate draws no
//! randomness and reads no clock (it stays portable, piggy#337); the
//! builders refuse a serial shorter than 64 bits and clamp `notAfter` to
//! the issuer certificate's. The subject key identifier is RFC 7093
//! method 1: the leftmost 160 bits of SHA-256 over the subjectPublicKey
//! bits.

use std::time::Duration;

use const_oid::ObjectIdentifier;
use der::asn1::{BitString, GeneralizedTime, Ia5String, OctetString, UtcTime};
use der::flagset::FlagSet;
use der::{Any, DateTime, Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::error::PivError;
use crate::slot::PivAlgorithm;

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// The smallest serial the profiles accept: 64 bits (FDR 0007, "serial").
pub const MIN_SERIAL_BYTES: usize = 8;

/// A certificate's validity as offsets from the Unix epoch. The issuing
/// command computes them (now minus a skew; now plus the profile's
/// lifetime); the builders only clamp `not_after` to the issuer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertValidity {
    pub not_before: Duration,
    pub not_after: Duration,
}

/// The root profile: a self-signed CA certificate over the card slot's
/// key (`pubkey_point`, SEC1 uncompressed), subject `CN=<common_name>`,
/// whose name constraints permit exactly `permitted_dns` (and every name
/// under each, as RFC 5280 DNS constraints do) and exclude every IP
/// address. `sign_digest` signs with that same key.
pub fn build_root_cert(
    pubkey_point: &[u8],
    algorithm: PivAlgorithm,
    common_name: &str,
    permitted_dns: &[String],
    validity: CertValidity,
    serial: &[u8],
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Vec<u8>, PivError> {
    let spki = ec_spki(pubkey_point, algorithm)?;
    let ski = key_identifier(&spki);
    let name = common_name_dn(common_name)?;
    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(1),
            },
            &name,
        )?,
        extension(&ca_key_usage(), &name)?,
        extension(&name_constraints(permitted_dns)?, &name)?,
        extension(&SubjectKeyIdentifier(octets(&ski)?), &name)?,
        extension(&authority_key_id(&ski)?, &name)?,
    ];
    sign_tbs(
        Issuer {
            name: name.clone(),
            algorithm,
            not_after: None,
        },
        name,
        spki,
        validity,
        serial,
        extensions,
        sign_digest,
    )
}

/// The intermediate profile: a CA certificate with `pathlen 0` over the
/// holder key `pubkey_point`, subject `CN=<common_name>`, issued by the
/// certificate `issuer_cert_der` (the root), carrying the root's name
/// constraints (`permitted_dns`, the same set the root's profile names).
// One argument per input the profile leaves to its caller, plus the issuer
// and the signer; bundling some of them would only hide which they are.
#[allow(clippy::too_many_arguments)]
pub fn build_intermediate_cert(
    pubkey_point: &[u8],
    algorithm: PivAlgorithm,
    common_name: &str,
    permitted_dns: &[String],
    issuer_cert_der: &[u8],
    validity: CertValidity,
    serial: &[u8],
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Vec<u8>, PivError> {
    let issuer = Issuer::from_cert_der(issuer_cert_der)?;
    let spki = ec_spki(pubkey_point, algorithm)?;
    let ski = key_identifier(&spki);
    let subject = common_name_dn(common_name)?;
    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
            &subject,
        )?,
        extension(&ca_key_usage(), &subject)?,
        extension(&name_constraints(permitted_dns)?, &subject)?,
        extension(&SubjectKeyIdentifier(octets(&ski)?), &subject)?,
        extension(&authority_key_id(&issuer.key_id)?, &subject)?,
    ];
    let issuer_algorithm = issuer.algorithm;
    sign_tbs(
        Issuer {
            name: issuer.name,
            algorithm: issuer_algorithm,
            not_after: Some(issuer.not_after),
        },
        subject,
        spki,
        validity,
        serial,
        extensions,
        sign_digest,
    )
}

/// The leaf profile: a TLS server certificate over `pubkey_point` naming
/// exactly `dns_names` (subject `CN` = the first, `subjectAltName` = all),
/// issued by `issuer_cert_der` (an intermediate, or the root in the
/// pilot). `dns_names` must be non-empty.
pub fn build_leaf_cert(
    pubkey_point: &[u8],
    algorithm: PivAlgorithm,
    dns_names: &[String],
    issuer_cert_der: &[u8],
    validity: CertValidity,
    serial: &[u8],
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Vec<u8>, PivError> {
    let first = dns_names
        .first()
        .ok_or_else(|| PivError::Other("a leaf needs at least one DNS name".into()))?;
    let issuer = Issuer::from_cert_der(issuer_cert_der)?;
    let spki = ec_spki(pubkey_point, algorithm)?;
    let ski = key_identifier(&spki);
    let subject = common_name_dn(first)?;
    let san = SubjectAltName(
        dns_names
            .iter()
            .map(|n| dns_general_name(n))
            .collect::<Result<_, _>>()?,
    );
    let extensions = vec![
        extension(
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
            &subject,
        )?,
        extension(&KeyUsage(KeyUsages::DigitalSignature.into()), &subject)?,
        extension(&ExtendedKeyUsage(vec![OID_KP_SERVER_AUTH]), &subject)?,
        extension(&san, &subject)?,
        extension(&SubjectKeyIdentifier(octets(&ski)?), &subject)?,
        extension(&authority_key_id(&issuer.key_id)?, &subject)?,
    ];
    let issuer_algorithm = issuer.algorithm;
    sign_tbs(
        Issuer {
            name: issuer.name,
            algorithm: issuer_algorithm,
            not_after: Some(issuer.not_after),
        },
        subject,
        spki,
        validity,
        serial,
        extensions,
        sign_digest,
    )
}

/// What a certificate needs from its issuer.
struct Issuer {
    name: Name,
    algorithm: PivAlgorithm,
    /// The issuer certificate's `notAfter`; `None` for a self-signed root.
    not_after: Option<Duration>,
}

/// An issuer read from its certificate.
struct ParsedIssuer {
    name: Name,
    algorithm: PivAlgorithm,
    not_after: Duration,
    key_id: Vec<u8>,
}

impl Issuer {
    fn from_cert_der(der: &[u8]) -> Result<ParsedIssuer, PivError> {
        let cert = Certificate::from_der(der).map_err(der_err)?;
        let tbs = cert.tbs_certificate;
        let algorithm = ec_algorithm_of(&tbs.subject_public_key_info)?;
        let key_id = tbs
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == SubjectKeyIdentifier::OID)
            .map(|e| SubjectKeyIdentifier::from_der(e.extn_value.as_bytes()).map_err(der_err))
            .transpose()?
            .map(|ski| ski.0.as_bytes().to_vec())
            .ok_or_else(|| {
                PivError::Other("the issuer certificate has no subjectKeyIdentifier".into())
            })?;
        let is_ca = tbs
            .extensions
            .iter()
            .flatten()
            .find(|e| e.extn_id == BasicConstraints::OID)
            .map(|e| BasicConstraints::from_der(e.extn_value.as_bytes()).map_err(der_err))
            .transpose()?
            .is_some_and(|bc| bc.ca);
        if !is_ca {
            return Err(PivError::Other("the issuer certificate is not a CA".into()));
        }
        Ok(ParsedIssuer {
            name: tbs.subject,
            algorithm,
            not_after: tbs.validity.not_after.to_unix_duration(),
            key_id,
        })
    }
}

use der::oid::AssociatedOid;

/// Encode, hash and sign one TBSCertificate, then assemble the certificate.
fn sign_tbs(
    issuer: Issuer,
    subject: Name,
    spki: SubjectPublicKeyInfoOwned,
    validity: CertValidity,
    serial: &[u8],
    extensions: Vec<Extension>,
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Vec<u8>, PivError> {
    let (sig_oid, digest) = signature_params(issuer.algorithm)?;
    let sig_alg = AlgorithmIdentifierOwned {
        oid: sig_oid,
        parameters: None,
    };
    let not_after = match issuer.not_after {
        Some(limit) => validity.not_after.min(limit),
        None => validity.not_after,
    };
    if validity.not_before >= not_after {
        return Err(PivError::Other(
            "the validity is empty (notBefore is not before notAfter, after clamping to the issuer's)"
                .into(),
        ));
    }
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: positive_serial(serial)?,
        signature: sig_alg.clone(),
        issuer: issuer.name,
        validity: Validity {
            not_before: x509_time(validity.not_before)?,
            not_after: x509_time(not_after)?,
        },
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let tbs_der = tbs.to_der().map_err(der_err)?;
    let sig_der = sign_digest(&digest(&tbs_der))?;
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&sig_der).map_err(der_err)?,
    }
    .to_der()
    .map_err(der_err)
}

/// keyCertSign and cRLSign, the CA profiles' key usage.
fn ca_key_usage() -> KeyUsage {
    let usages: FlagSet<KeyUsages> = KeyUsages::KeyCertSign | KeyUsages::CRLSign;
    KeyUsage(usages)
}

/// Permitted `DNS:` each name; excluded every IPv4 and every IPv6 address,
/// because a DNS-only constraint does not constrain an IP SAN.
fn name_constraints(permitted_dns: &[String]) -> Result<NameConstraints, PivError> {
    if permitted_dns.is_empty() {
        return Err(PivError::Other(
            "a CA profile needs at least one permitted DNS name".into(),
        ));
    }
    let subtree = |base| GeneralSubtree {
        base,
        minimum: 0,
        maximum: None,
    };
    Ok(NameConstraints {
        permitted_subtrees: Some(
            permitted_dns
                .iter()
                .map(|n| dns_general_name(n).map(subtree))
                .collect::<Result<_, _>>()?,
        ),
        excluded_subtrees: Some(vec![
            subtree(GeneralName::IpAddress(octets(&[0u8; 8])?)),
            subtree(GeneralName::IpAddress(octets(&[0u8; 32])?)),
        ]),
    })
}

fn dns_general_name(name: &str) -> Result<GeneralName, PivError> {
    if name.is_empty() || !name.is_ascii() || name.contains(char::is_whitespace) {
        return Err(PivError::Other(format!("{name:?} is not a DNS name")));
    }
    Ok(GeneralName::DnsName(Ia5String::new(name).map_err(der_err)?))
}

fn authority_key_id(key_id: &[u8]) -> Result<AuthorityKeyIdentifier, PivError> {
    Ok(AuthorityKeyIdentifier {
        key_identifier: Some(octets(key_id)?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    })
}

/// Encode `value` as an extension of `subject`'s certificate, with the
/// criticality its type declares (`AsExtension`): basicConstraints,
/// keyUsage and nameConstraints critical; the rest not.
fn extension<E: AsExtension>(value: &E, subject: &Name) -> Result<Extension, PivError> {
    value.to_extension(subject, &[]).map_err(der_err)
}

/// RFC 7093 method 1: the leftmost 160 bits of SHA-256 over the
/// subjectPublicKey bits.
fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    use sha2::Digest as _;
    sha2::Sha256::digest(spki.subject_public_key.raw_bytes())[..20].to_vec()
}

/// A positive DER INTEGER from `serial`: leading zero bytes dropped, at
/// least [`MIN_SERIAL_BYTES`] significant bytes left, and a `00` put back
/// in front when the top bit is set.
fn positive_serial(serial: &[u8]) -> Result<SerialNumber, PivError> {
    let significant = &serial[serial.iter().take_while(|b| **b == 0).count()..];
    if significant.len() < MIN_SERIAL_BYTES {
        return Err(PivError::Other(format!(
            "a serial needs at least {} bits; got {}",
            MIN_SERIAL_BYTES * 8,
            significant.len() * 8
        )));
    }
    if significant.len() > 19 {
        return Err(PivError::Other("a serial may be at most 19 bytes".into()));
    }
    let mut bytes = Vec::with_capacity(significant.len() + 1);
    if significant[0] & 0x80 != 0 {
        bytes.push(0);
    }
    bytes.extend_from_slice(significant);
    SerialNumber::new(&bytes).map_err(der_err)
}

/// RFC 5280 4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050.
fn x509_time(since_epoch: Duration) -> Result<Time, PivError> {
    let at = DateTime::from_unix_duration(since_epoch).map_err(der_err)?;
    Ok(if at.year() < 2050 {
        Time::UtcTime(UtcTime::from_date_time(at).map_err(der_err)?)
    } else {
        Time::GeneralTime(GeneralizedTime::from_date_time(at))
    })
}

fn common_name_dn(common_name: &str) -> Result<Name, PivError> {
    format!("CN={common_name}").parse().map_err(der_err)
}

fn octets(bytes: &[u8]) -> Result<OctetString, PivError> {
    OctetString::new(bytes).map_err(der_err)
}

fn ec_spki(point: &[u8], algorithm: PivAlgorithm) -> Result<SubjectPublicKeyInfoOwned, PivError> {
    let curve = match algorithm {
        PivAlgorithm::EcP256 => OID_PRIME256V1,
        PivAlgorithm::EcP384 => OID_SECP384R1,
        other => return Err(unsupported(other)),
    };
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(Any::from(&curve)),
        },
        subject_public_key: BitString::from_bytes(point).map_err(der_err)?,
    })
}

fn ec_algorithm_of(spki: &SubjectPublicKeyInfoOwned) -> Result<PivAlgorithm, PivError> {
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    match (spki.algorithm.oid, curve) {
        (OID_EC_PUBLIC_KEY, Some(OID_PRIME256V1)) => Ok(PivAlgorithm::EcP256),
        (OID_EC_PUBLIC_KEY, Some(OID_SECP384R1)) => Ok(PivAlgorithm::EcP384),
        _ => Err(PivError::Other(
            "the issuer's key is not EC P-256 or P-384".into(),
        )),
    }
}

/// A digest over the DER a signer is handed.
type DigestFn = fn(&[u8]) -> Vec<u8>;

/// The issuer key's signature algorithm and the digest its signer gets.
fn signature_params(algorithm: PivAlgorithm) -> Result<(ObjectIdentifier, DigestFn), PivError> {
    use sha2::Digest as _;
    match algorithm {
        PivAlgorithm::EcP256 => Ok((OID_ECDSA_SHA256, |d| sha2::Sha256::digest(d).to_vec())),
        PivAlgorithm::EcP384 => Ok((OID_ECDSA_SHA384, |d| sha2::Sha384::digest(d).to_vec())),
        other => Err(unsupported(other)),
    }
}

fn unsupported(algorithm: PivAlgorithm) -> PivError {
    PivError::Other(format!(
        "the X.509 profiles support ECDSA P-256/P-384 only, not {algorithm:?}"
    ))
}

fn der_err<E: std::fmt::Display>(e: E) -> PivError {
    PivError::Other(format!("x509 profile: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::{X509, X509StoreContext};

    const DAY: u64 = 86_400;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A software key standing in for a card slot or the holder.
    struct Key {
        ec: EcKey<Private>,
        algorithm: PivAlgorithm,
    }

    impl Key {
        fn new(algorithm: PivAlgorithm) -> Self {
            let nid = match algorithm {
                PivAlgorithm::EcP256 => Nid::X9_62_PRIME256V1,
                _ => Nid::SECP384R1,
            };
            let group = EcGroup::from_curve_name(nid).unwrap();
            Key {
                ec: EcKey::generate(&group).unwrap(),
                algorithm,
            }
        }
        fn point(&self) -> Vec<u8> {
            let mut ctx = BigNumContext::new().unwrap();
            self.ec
                .public_key()
                .to_bytes(self.ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                .unwrap()
        }
        fn signer(&self) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError> + '_ {
            |digest| Ok(EcdsaSig::sign(digest, &self.ec).unwrap().to_der().unwrap())
        }
        fn pkey(&self) -> PKey<Private> {
            PKey::from_ec_key(self.ec.clone()).unwrap()
        }
    }

    fn now() -> Duration {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
    }

    fn validity(days: u64) -> CertValidity {
        CertValidity {
            not_before: now() - Duration::from_secs(300),
            not_after: now() + Duration::from_secs(days * DAY),
        }
    }

    fn root(key: &Key, permitted: &[&str]) -> Vec<u8> {
        build_root_cert(
            &key.point(),
            key.algorithm,
            "piggy-test root",
            &names(permitted),
            validity(3650),
            &[0x5A; 16],
            key.signer(),
        )
        .unwrap()
    }

    /// Whether `leaf` verifies under the trust anchor `root` with
    /// `intermediates` as untrusted chain certificates (OpenSSL, the
    /// verifier nix's curl uses).
    fn verifies(root: &[u8], intermediates: &[&[u8]], leaf: &[u8]) -> Result<(), String> {
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(X509::from_der(root).unwrap()).unwrap();
        let store = store.build();
        let mut chain = Stack::new().unwrap();
        for der in intermediates {
            chain.push(X509::from_der(der).unwrap()).unwrap();
        }
        let leaf = X509::from_der(leaf).unwrap();
        let mut ctx = X509StoreContext::new().unwrap();
        ctx.init(&store, &leaf, &chain, |c| {
            Ok(if c.verify_cert()? {
                Ok(())
            } else {
                Err(c.error().to_string())
            })
        })
        .unwrap()
    }

    fn text(der: &[u8]) -> String {
        String::from_utf8(X509::from_der(der).unwrap().to_text().unwrap()).unwrap()
    }

    #[test]
    fn the_root_profile_has_the_fdr_extensions_and_signs_itself() {
        let key = Key::new(PivAlgorithm::EcP256);
        let der = root(&key, &["github.com"]);
        let cert = X509::from_der(&der).unwrap();
        assert!(cert.verify(&key.pkey()).unwrap(), "self-signed");
        let t = text(&der);
        for want in [
            "X509v3 Basic Constraints: critical",
            "CA:TRUE, pathlen:1",
            "X509v3 Key Usage: critical",
            "Certificate Sign, CRL Sign",
            "X509v3 Name Constraints: critical",
            "DNS:github.com",
            "IP:0.0.0.0/0.0.0.0",
            // `IP:::/0`, as OpenSSL prints it.
            "IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0",
            "X509v3 Subject Key Identifier",
            "X509v3 Authority Key Identifier",
        ] {
            assert!(t.contains(want), "missing {want:?} in\n{t}");
        }
        assert!(!t.contains("Extended Key Usage"), "{t}");
        assert!(!t.contains("Subject Alternative Name"), "{t}");
    }

    #[test]
    fn a_leaf_for_the_permitted_names_verifies_under_root_and_intermediate() {
        let root_key = Key::new(PivAlgorithm::EcP256);
        let root_der = root(&root_key, &["github.com"]);
        let int_key = Key::new(PivAlgorithm::EcP256);
        let int_der = build_intermediate_cert(
            &int_key.point(),
            int_key.algorithm,
            "piggy-test intermediate",
            &names(&["github.com"]),
            &root_der,
            validity(7),
            &[0x11; 16],
            root_key.signer(),
        )
        .unwrap();
        let leaf_key = Key::new(PivAlgorithm::EcP256);
        let leaf_names = names(&["github.com", "api.github.com", "codeload.github.com"]);
        let leaf_der = build_leaf_cert(
            &leaf_key.point(),
            leaf_key.algorithm,
            &leaf_names,
            &int_der,
            validity(1),
            &[0x22; 16],
            int_key.signer(),
        )
        .unwrap();
        verifies(&root_der, &[&int_der], &leaf_der).unwrap();

        let t = text(&int_der);
        assert!(t.contains("CA:TRUE, pathlen:0"), "{t}");
        assert!(t.contains("X509v3 Name Constraints: critical"), "{t}");
        let t = text(&leaf_der);
        for want in [
            "CA:FALSE",
            "Digital Signature",
            "TLS Web Server Authentication",
            "DNS:github.com, DNS:api.github.com, DNS:codeload.github.com",
            "Subject: CN=github.com",
        ] {
            assert!(t.contains(want), "missing {want:?} in\n{t}");
        }
    }

    /// The pilot: the root signs the leaf directly (pathlen 1 allows it).
    #[test]
    fn a_p384_root_signs_a_p256_leaf_directly() {
        let root_key = Key::new(PivAlgorithm::EcP384);
        let root_der = root(&root_key, &["github.com"]);
        let leaf_key = Key::new(PivAlgorithm::EcP256);
        let leaf_der = build_leaf_cert(
            &leaf_key.point(),
            leaf_key.algorithm,
            &names(&["api.github.com"]),
            &root_der,
            validity(30),
            &[0x33; 16],
            root_key.signer(),
        )
        .unwrap();
        assert!(text(&leaf_der).contains("ecdsa-with-SHA384"));
        verifies(&root_der, &[], &leaf_der).unwrap();
    }

    #[test]
    fn a_leaf_for_a_foreign_name_does_not_verify() {
        let root_key = Key::new(PivAlgorithm::EcP256);
        let root_der = root(&root_key, &["github.com"]);
        let leaf_key = Key::new(PivAlgorithm::EcP256);
        let leaf_der = build_leaf_cert(
            &leaf_key.point(),
            leaf_key.algorithm,
            &names(&["example.org"]),
            &root_der,
            validity(1),
            &[0x44; 16],
            root_key.signer(),
        )
        .unwrap();
        let err = verifies(&root_der, &[], &leaf_der).unwrap_err();
        assert!(err.contains("subtree"), "{err}");
    }

    #[test]
    fn not_after_is_clamped_to_the_issuers() {
        let root_key = Key::new(PivAlgorithm::EcP256);
        let root_der = build_root_cert(
            &root_key.point(),
            root_key.algorithm,
            "piggy-test root",
            &names(&["github.com"]),
            validity(10),
            &[0x5A; 16],
            root_key.signer(),
        )
        .unwrap();
        let leaf_key = Key::new(PivAlgorithm::EcP256);
        let leaf_der = build_leaf_cert(
            &leaf_key.point(),
            leaf_key.algorithm,
            &names(&["github.com"]),
            &root_der,
            validity(400),
            &[0x55; 16],
            root_key.signer(),
        )
        .unwrap();
        let root = X509::from_der(&root_der).unwrap();
        let leaf = X509::from_der(&leaf_der).unwrap();
        assert_eq!(
            leaf.not_after().compare(root.not_after()).unwrap(),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn short_or_zero_serials_and_empty_names_are_refused() {
        let key = Key::new(PivAlgorithm::EcP256);
        for serial in [
            &[0x01; 7][..],
            &[0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..],
            &[0u8; 16][..],
        ] {
            let err = build_root_cert(
                &key.point(),
                key.algorithm,
                "x",
                &names(&["github.com"]),
                validity(1),
                serial,
                key.signer(),
            )
            .unwrap_err();
            assert!(format!("{err}").contains("64 bits"), "{err}");
        }
        assert!(
            build_root_cert(
                &key.point(),
                key.algorithm,
                "x",
                &[],
                validity(1),
                &[0x5A; 16],
                key.signer(),
            )
            .is_err()
        );
        let root_der = root(&key, &["github.com"]);
        assert!(
            build_leaf_cert(
                &key.point(),
                key.algorithm,
                &[],
                &root_der,
                validity(1),
                &[0x5A; 16],
                key.signer(),
            )
            .is_err()
        );
    }

    #[test]
    fn a_serial_with_its_top_bit_set_stays_positive() {
        let key = Key::new(PivAlgorithm::EcP256);
        let der = build_root_cert(
            &key.point(),
            key.algorithm,
            "x",
            &names(&["github.com"]),
            validity(1),
            &[0xFF; 16],
            key.signer(),
        )
        .unwrap();
        let serial = X509::from_der(&der)
            .unwrap()
            .serial_number()
            .to_bn()
            .unwrap();
        assert!(!serial.is_negative());
        assert_eq!(serial.num_bytes(), 16);
    }

    #[test]
    fn a_leaf_cannot_be_issued_by_a_non_ca_certificate() {
        let key = Key::new(PivAlgorithm::EcP256);
        let root_der = root(&key, &["github.com"]);
        let leaf_der = build_leaf_cert(
            &key.point(),
            key.algorithm,
            &names(&["github.com"]),
            &root_der,
            validity(1),
            &[0x66; 16],
            key.signer(),
        )
        .unwrap();
        let err = build_leaf_cert(
            &key.point(),
            key.algorithm,
            &names(&["github.com"]),
            &leaf_der,
            validity(1),
            &[0x77; 16],
            key.signer(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not a CA"), "{err}");
    }
}
