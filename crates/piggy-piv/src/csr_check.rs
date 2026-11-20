//! Read and check a PKCS#10 request for `piggy ca sign` / `piggy ca issue`
//! (FDR 0007, "The issuance verbs", steps 1 and 2). Pure: bytes in, a
//! verdict out; nothing here touches a card, a clock or a file.
//!
//! A request is trusted for exactly three things: its public key, its
//! `CN`, and the DNS names it asks for. Everything else in it (requested
//! extensions, other subject attributes) is read only to be refused or
//! ignored, never copied into a certificate.
//!
//! The two refusal families map to the verbs' exit codes: a
//! [`CsrRefusal::Malformed`], [`CsrRefusal::KeyType`] or
//! [`CsrRefusal::BadSignature`] is exit 4; a [`CsrRefusal::Names`] is
//! exit 5.

use const_oid::ObjectIdentifier;
use der::asn1::{PrintableStringRef, Utf8StringRef};
use der::oid::AssociatedOid;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::request::CertReq;

use crate::slot::PivAlgorithm;

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
/// PKCS#9 `extensionRequest`.
const OID_EXTENSION_REQUEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

/// Why a request was refused. The verb prints the message and maps the
/// variant to an exit code (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsrRefusal {
    /// Not a parseable PKCS#10 request (exit 4).
    Malformed(String),
    /// A key other than EC P-256 or P-384, or a signature algorithm that
    /// does not match the key (exit 4).
    KeyType(String),
    /// The request's self-signature does not verify (exit 4).
    BadSignature,
    /// The names it asks for fall outside the profile (exit 5).
    Names(String),
}

impl std::fmt::Display for CsrRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "the request is malformed: {why}"),
            Self::KeyType(why) => write!(f, "the request's key is refused: {why}"),
            Self::BadSignature => f.write_str("the request's self-signature does not verify"),
            Self::Names(why) => write!(f, "the request names outside the profile: {why}"),
        }
    }
}

impl std::error::Error for CsrRefusal {}

/// What a verified request is trusted for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCsr {
    pub algorithm: PivAlgorithm,
    /// SEC1 uncompressed point of the requested key.
    pub pubkey_point: Vec<u8>,
    /// The subject's `CN`, when the subject has exactly one.
    pub common_name: Option<String>,
    /// Every `dNSName` the request's `extensionRequest` asks for.
    pub dns_names: Vec<String>,
    /// The request asks for a `subjectAltName` of a kind other than DNS
    /// (an IP address, an email, a URI, ...).
    pub other_san: bool,
}

/// Parse `der`, require an EC P-256 or P-384 key whose signature
/// algorithm matches it, and verify the request's self-signature.
pub fn parse_csr(der: &[u8]) -> Result<ParsedCsr, CsrRefusal> {
    let req = CertReq::from_der(der).map_err(|e| CsrRefusal::Malformed(e.to_string()))?;
    let (algorithm, pubkey_point) = ec_key_of(&req.info.public_key)?;
    let expected_sig = match algorithm {
        PivAlgorithm::EcP256 => OID_ECDSA_SHA256,
        _ => OID_ECDSA_SHA384,
    };
    if req.algorithm.oid != expected_sig {
        return Err(CsrRefusal::KeyType(format!(
            "signature algorithm {} does not match the {algorithm:?} key",
            req.algorithm.oid
        )));
    }
    let info_der = req
        .info
        .to_der()
        .map_err(|e| CsrRefusal::Malformed(e.to_string()))?;
    let sig_der = req
        .signature
        .as_bytes()
        .ok_or_else(|| CsrRefusal::Malformed("the signature has unused bits".into()))?;
    if !verifies(algorithm, &pubkey_point, &info_der, sig_der) {
        return Err(CsrRefusal::BadSignature);
    }

    let common_name = common_name_of(&req)?;
    let (dns_names, other_san) = requested_names(&req)?;
    Ok(ParsedCsr {
        algorithm,
        pubkey_point,
        common_name,
        dns_names,
        other_san,
    })
}

/// A leaf profile's check (FDR 0007 step 2): the request's `CN` and every
/// requested name must be among `permitted` (ASCII case-insensitive), and
/// it may not ask for a name of any other kind. The leaf is issued with
/// the profile's full set, not the request's, so an empty request passes.
pub fn check_leaf_names(permitted: &[String], csr: &ParsedCsr) -> Result<(), CsrRefusal> {
    if csr.other_san {
        return Err(CsrRefusal::Names(
            "a subjectAltName other than a DNS name is requested".into(),
        ));
    }
    let outside = |name: &str| !permitted.iter().any(|p| p.eq_ignore_ascii_case(name));
    if let Some(cn) = &csr.common_name {
        if outside(cn) {
            return Err(CsrRefusal::Names(format!("CN {cn:?} is not permitted")));
        }
    }
    if let Some(name) = csr.dns_names.iter().find(|n| outside(n)) {
        return Err(CsrRefusal::Names(format!(
            "DNS name {name:?} is not permitted"
        )));
    }
    Ok(())
}

/// An intermediate profile's check: the request's `CN` must equal the
/// profile's, and no `subjectAltName` of any kind may be requested.
pub fn check_intermediate_name(common_name: &str, csr: &ParsedCsr) -> Result<(), CsrRefusal> {
    if csr.other_san || !csr.dns_names.is_empty() {
        return Err(CsrRefusal::Names(
            "an intermediate request may not ask for a subjectAltName".into(),
        ));
    }
    match &csr.common_name {
        Some(cn) if cn == common_name => Ok(()),
        Some(cn) => Err(CsrRefusal::Names(format!(
            "CN {cn:?} is not the profile's {common_name:?}"
        ))),
        None => Err(CsrRefusal::Names(format!(
            "the request has no single CN; the profile's is {common_name:?}"
        ))),
    }
}

fn ec_key_of(spki: &SubjectPublicKeyInfoOwned) -> Result<(PivAlgorithm, Vec<u8>), CsrRefusal> {
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    let algorithm = match (spki.algorithm.oid, curve) {
        (OID_EC_PUBLIC_KEY, Some(OID_PRIME256V1)) => PivAlgorithm::EcP256,
        (OID_EC_PUBLIC_KEY, Some(OID_SECP384R1)) => PivAlgorithm::EcP384,
        _ => {
            return Err(CsrRefusal::KeyType(
                "only EC P-256 and P-384 keys are accepted".into(),
            ));
        }
    };
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CsrRefusal::Malformed("the public key has unused bits".into()))?
        .to_vec();
    Ok((algorithm, point))
}

/// Whether `sig_der` (DER ECDSA) over `message` verifies with the P-256 or
/// P-384 key at `point`, hashing with the curve's digest. Shared with the
/// chain check (`x509_verify`).
pub(crate) fn verifies(
    algorithm: PivAlgorithm,
    point: &[u8],
    message: &[u8],
    sig_der: &[u8],
) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    match algorithm {
        PivAlgorithm::EcP256 => {
            let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return false;
            };
            let Ok(sig) = p256::ecdsa::Signature::from_der(sig_der) else {
                return false;
            };
            key.verify(message, &sig).is_ok()
        }
        _ => {
            let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                return false;
            };
            let Ok(sig) = p384::ecdsa::Signature::from_der(sig_der) else {
                return false;
            };
            key.verify(message, &sig).is_ok()
        }
    }
}

/// The subject's `CN` when the subject carries exactly one, `None` when
/// it carries none. Two `CN`s are refused: which one a name check means
/// would be a guess.
fn common_name_of(req: &CertReq) -> Result<Option<String>, CsrRefusal> {
    let mut found = Vec::new();
    for rdn in req.info.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid != OID_COMMON_NAME {
                continue;
            }
            let text = if let Ok(s) = atv.value.decode_as::<Utf8StringRef<'_>>() {
                s.as_str().to_owned()
            } else if let Ok(s) = atv.value.decode_as::<PrintableStringRef<'_>>() {
                s.as_str().to_owned()
            } else {
                return Err(CsrRefusal::Malformed(
                    "the CN is neither a UTF8String nor a PrintableString".into(),
                ));
            };
            found.push(text);
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(CsrRefusal::Names("the subject has more than one CN".into())),
    }
}

/// The names in the request's `extensionRequest` `subjectAltName`:
/// the DNS names, and whether anything else is there. No other requested
/// extension is read.
fn requested_names(req: &CertReq) -> Result<(Vec<String>, bool), CsrRefusal> {
    let mut dns = Vec::new();
    let mut other = false;
    for attr in req.info.attributes.iter() {
        if attr.oid != OID_EXTENSION_REQUEST {
            continue;
        }
        for value in attr.values.iter() {
            let extensions = value
                .decode_as::<Vec<Extension>>()
                .map_err(|e| CsrRefusal::Malformed(format!("extensionRequest: {e}")))?;
            for ext in extensions
                .iter()
                .filter(|e| e.extn_id == SubjectAltName::OID)
            {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| CsrRefusal::Malformed(format!("subjectAltName: {e}")))?;
                for name in san.0 {
                    match name {
                        GeneralName::DnsName(n) => dns.push(n.as_str().to_owned()),
                        _ => other = true,
                    }
                }
            }
        }
    }
    Ok((dns, other))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Any;
    use der::asn1::{BitString, Ia5String, OctetString, SetOfVec};
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use sha2::Digest as _;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::attr::{Attribute, Attributes};
    use x509_cert::name::Name;
    use x509_cert::request::{CertReqInfo, Version};

    /// What a test request asks for.
    struct Ask<'a> {
        subject: &'a str,
        dns: &'a [&'a str],
        ip: bool,
        p384: bool,
        /// Sign with a different key than the one the request names.
        wrong_signer: bool,
    }

    impl Default for Ask<'_> {
        fn default() -> Self {
            Ask {
                subject: "CN=github.com",
                dns: &[],
                ip: false,
                p384: false,
                wrong_signer: false,
            }
        }
    }

    fn make(ask: &Ask) -> Vec<u8> {
        let (nid, curve_oid, sig_oid) = if ask.p384 {
            (Nid::SECP384R1, OID_SECP384R1, OID_ECDSA_SHA384)
        } else {
            (Nid::X9_62_PRIME256V1, OID_PRIME256V1, OID_ECDSA_SHA256)
        };
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let other = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let subject: Name = ask.subject.parse().unwrap();
        let mut names: Vec<GeneralName> = ask
            .dns
            .iter()
            .map(|n| GeneralName::DnsName(Ia5String::new(*n).unwrap()))
            .collect();
        if ask.ip {
            names.push(GeneralName::IpAddress(
                OctetString::new([127u8, 0, 0, 1]).unwrap(),
            ));
        }
        let mut attributes = Attributes::default();
        if !names.is_empty() {
            let ext = Extension {
                extn_id: SubjectAltName::OID,
                critical: false,
                extn_value: OctetString::new(SubjectAltName(names).to_der().unwrap()).unwrap(),
            };
            let value = Any::from_der(&vec![ext].to_der().unwrap()).unwrap();
            attributes
                .insert(Attribute {
                    oid: OID_EXTENSION_REQUEST,
                    values: SetOfVec::try_from(vec![value]).unwrap(),
                })
                .unwrap();
        }
        let info = CertReqInfo {
            version: Version::V1,
            subject,
            public_key: SubjectPublicKeyInfoOwned {
                algorithm: AlgorithmIdentifierOwned {
                    oid: OID_EC_PUBLIC_KEY,
                    parameters: Some(Any::from(&curve_oid)),
                },
                subject_public_key: BitString::from_bytes(&point).unwrap(),
            },
            attributes,
        };
        let info_der = info.to_der().unwrap();
        let digest = if ask.p384 {
            sha2::Sha384::digest(&info_der).to_vec()
        } else {
            sha2::Sha256::digest(&info_der).to_vec()
        };
        let signer = if ask.wrong_signer { &other } else { &key };
        let sig = EcdsaSig::sign(&digest, signer).unwrap().to_der().unwrap();
        CertReq {
            info,
            algorithm: AlgorithmIdentifierOwned {
                oid: sig_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&sig).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_p256_and_a_p384_request_parse_with_their_key_and_names() {
        let p256 = parse_csr(&make(&Ask {
            dns: &["github.com", "api.github.com"],
            ..Ask::default()
        }))
        .unwrap();
        assert_eq!(p256.algorithm, PivAlgorithm::EcP256);
        assert_eq!(p256.pubkey_point.len(), 65);
        assert_eq!(p256.common_name.as_deref(), Some("github.com"));
        assert_eq!(p256.dns_names, ["github.com", "api.github.com"]);
        assert!(!p256.other_san);

        let p384 = parse_csr(&make(&Ask {
            p384: true,
            ..Ask::default()
        }))
        .unwrap();
        assert_eq!(p384.algorithm, PivAlgorithm::EcP384);
        assert_eq!(p384.pubkey_point.len(), 97);
    }

    #[test]
    fn a_signature_by_another_key_or_a_flipped_byte_is_refused() {
        let forged = make(&Ask {
            wrong_signer: true,
            ..Ask::default()
        });
        assert_eq!(parse_csr(&forged), Err(CsrRefusal::BadSignature));

        let mut tampered = make(&Ask::default());
        let at = tampered.len() - 5;
        tampered[at] ^= 0x01;
        assert!(parse_csr(&tampered).is_err());
    }

    #[test]
    fn garbage_and_truncation_are_malformed() {
        assert!(matches!(parse_csr(b""), Err(CsrRefusal::Malformed(_))));
        assert!(matches!(
            parse_csr(b"not a request"),
            Err(CsrRefusal::Malformed(_))
        ));
        let whole = make(&Ask::default());
        assert!(matches!(
            parse_csr(&whole[..whole.len() - 3]),
            Err(CsrRefusal::Malformed(_))
        ));
    }

    #[test]
    fn a_non_ec_key_is_refused_as_a_key_type() {
        // An RSA-shaped SPKI in an otherwise valid request.
        let ok = make(&Ask::default());
        let mut req = CertReq::from_der(&ok).unwrap();
        req.info.public_key.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        assert!(matches!(
            parse_csr(&req.to_der().unwrap()),
            Err(CsrRefusal::KeyType(_))
        ));
    }

    #[test]
    fn a_leaf_may_ask_for_a_subset_of_the_permitted_names_in_any_case() {
        let permitted = names(&["github.com", "api.github.com", "codeload.github.com"]);
        let csr = parse_csr(&make(&Ask {
            subject: "CN=GitHub.com",
            dns: &["API.github.com"],
            ..Ask::default()
        }))
        .unwrap();
        assert_eq!(check_leaf_names(&permitted, &csr), Ok(()));
    }

    #[test]
    fn a_leaf_naming_a_foreign_name_or_an_ip_is_refused() {
        let permitted = names(&["github.com"]);
        let foreign_cn = parse_csr(&make(&Ask {
            subject: "CN=evil.example",
            ..Ask::default()
        }))
        .unwrap();
        assert!(matches!(
            check_leaf_names(&permitted, &foreign_cn),
            Err(CsrRefusal::Names(_))
        ));

        let foreign_san = parse_csr(&make(&Ask {
            dns: &["github.com", "evil.example"],
            ..Ask::default()
        }))
        .unwrap();
        assert!(matches!(
            check_leaf_names(&permitted, &foreign_san),
            Err(CsrRefusal::Names(_))
        ));

        // A name merely under a permitted one is not the permitted set.
        let under = parse_csr(&make(&Ask {
            dns: &["x.github.com"],
            ..Ask::default()
        }))
        .unwrap();
        assert!(matches!(
            check_leaf_names(&permitted, &under),
            Err(CsrRefusal::Names(_))
        ));

        let ip = parse_csr(&make(&Ask {
            ip: true,
            ..Ask::default()
        }))
        .unwrap();
        assert!(ip.other_san);
        assert!(matches!(
            check_leaf_names(&permitted, &ip),
            Err(CsrRefusal::Names(_))
        ));
    }

    #[test]
    fn an_intermediate_needs_the_profiles_cn_and_no_san() {
        let good = parse_csr(&make(&Ask {
            subject: "CN=shithub intermediate",
            ..Ask::default()
        }))
        .unwrap();
        assert_eq!(
            check_intermediate_name("shithub intermediate", &good),
            Ok(())
        );
        assert!(matches!(
            check_intermediate_name("another", &good),
            Err(CsrRefusal::Names(_))
        ));

        let with_san = parse_csr(&make(&Ask {
            subject: "CN=shithub intermediate",
            dns: &["github.com"],
            ..Ask::default()
        }))
        .unwrap();
        assert!(matches!(
            check_intermediate_name("shithub intermediate", &with_san),
            Err(CsrRefusal::Names(_))
        ));

        let no_cn = parse_csr(&make(&Ask {
            subject: "O=nobody",
            ..Ask::default()
        }))
        .unwrap();
        assert_eq!(no_cn.common_name, None);
        assert!(matches!(
            check_intermediate_name("shithub intermediate", &no_cn),
            Err(CsrRefusal::Names(_))
        ));
    }

    #[test]
    fn two_cns_in_the_subject_are_refused() {
        let two = make(&Ask {
            subject: "CN=github.com,CN=api.github.com",
            ..Ask::default()
        });
        assert!(matches!(parse_csr(&two), Err(CsrRefusal::Names(_))));
    }
}
