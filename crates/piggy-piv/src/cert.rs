use const_oid::ObjectIdentifier;
use der::{Decode, Tagged};
use elliptic_curve::sec1::ToEncodedPoint;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::x509::X509;
use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use x509_cert::Certificate;

use crate::error::PivError;
use crate::slot::PivAlgorithm;

/// Verify a DER-encoded ECDSA signature over `prehash` against an EC public
/// key.
///
/// Used by the agent's CAK (Card Authentication Key) challenge/response
/// (`piggy agent -K`, piggy#143): the card signs a random challenge with its
/// slot-9E key (GENERAL AUTHENTICATE, PIN-never) and we check the signature
/// against the operator-configured CAK public key. A valid signature proves
/// the card holds the private key for the configured CAK — i.e. it is the
/// expected card, not a swapped one.
///
/// Returns `Ok(true)` for a valid signature, `Ok(false)` for a well-formed
/// but non-matching one, and `Err` for malformed inputs or a non-EC CAK.
pub fn verify_ec_signature(
    pubkey: &KeyData,
    prehash: &[u8],
    der_sig: &[u8],
) -> Result<bool, PivError> {
    let ec = match pubkey {
        KeyData::Ecdsa(ec) => ec,
        _ => {
            return Err(PivError::UnsupportedAlgorithm(
                "CAK is not an EC public key".into(),
            ));
        }
    };
    let nid = match ec {
        EcdsaPublicKey::NistP256(_) => Nid::X9_62_PRIME256V1,
        EcdsaPublicKey::NistP384(_) => Nid::SECP384R1,
        other => {
            return Err(PivError::UnsupportedAlgorithm(format!(
                "unsupported CAK curve {:?}",
                other.curve()
            )));
        }
    };

    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, ec.as_sec1_bytes(), &mut ctx)?;
    let eckey = EcKey::from_public_key(&group, &point)?;
    let sig = EcdsaSig::from_der(der_sig)?;
    Ok(sig.verify(prehash, &eckey)?)
}

/// Extract the raw 32-byte Ed25519 public key from a parsed SPKI. RFC
/// 8410 stores Ed25519 keys as the raw point with no inner DER
/// structure. Shared by [`extract_public_key`] and piggy-ids' slot
/// classifier (which needs the raw bytes as a markl payload).
pub fn raw_ed25519_from_spki(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<[u8; 32], PivError> {
    if pkey.id() != openssl::pkey::Id::ED25519 {
        return Err(PivError::UnsupportedAlgorithm(format!(
            "expected an Ed25519 SPKI, got openssl key id {:?}",
            pkey.id()
        )));
    }
    let raw = pkey.raw_public_key()?;
    raw.as_slice()
        .try_into()
        .map_err(|_| PivError::Crypto(format!("Ed25519 pubkey length {} != 32", raw.len())))
}

const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// A certificate's SubjectPublicKeyInfo, read without OpenSSL (piggy#337):
/// the key algorithm, the named curve for an EC key, and the key bits.
struct CertKey {
    algorithm: ObjectIdentifier,
    curve: Option<ObjectIdentifier>,
    key: Vec<u8>,
}

fn cert_key(cert_der: &[u8]) -> Result<CertKey, PivError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| PivError::Crypto(format!("X.509 certificate: {e}")))?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| PivError::Crypto("public key BIT STRING has unused bits".into()))?
        .to_vec();
    let curve = match &spki.algorithm.parameters {
        Some(params) if params.tag() == der::Tag::ObjectIdentifier => Some(
            params
                .decode_as::<ObjectIdentifier>()
                .map_err(|e| PivError::Crypto(format!("EC curve parameter: {e}")))?,
        ),
        _ => None,
    };
    Ok(CertKey {
        algorithm: spki.algorithm.oid,
        curve,
        key,
    })
}

/// The SEC1 uncompressed point (`04 || X || Y`) of an EC key on a named
/// curve, whichever SEC1 form the cert carried (as OpenSSL normalized it).
fn ec_uncompressed(
    curve: Option<ObjectIdentifier>,
    sec1: &[u8],
) -> Result<(PivAlgorithm, Vec<u8>), PivError> {
    let bad_point = |e: elliptic_curve::Error| PivError::Crypto(format!("EC point: {e}"));
    match curve {
        Some(oid) if oid == OID_PRIME256V1 => {
            let key = p256::PublicKey::from_sec1_bytes(sec1).map_err(bad_point)?;
            Ok((
                PivAlgorithm::EcP256,
                key.to_encoded_point(false).as_bytes().to_vec(),
            ))
        }
        Some(oid) if oid == OID_SECP384R1 => {
            let key = p384::PublicKey::from_sec1_bytes(sec1).map_err(bad_point)?;
            Ok((
                PivAlgorithm::EcP384,
                key.to_encoded_point(false).as_bytes().to_vec(),
            ))
        }
        Some(oid) => Err(PivError::UnsupportedAlgorithm(format!("EC curve {oid}"))),
        None => Err(PivError::UnsupportedAlgorithm("unnamed EC curve".into())),
    }
}

/// Extract the public key algorithm and ssh_key::PublicKey from a DER-encoded X.509 cert.
pub fn extract_public_key(cert_der: &[u8]) -> Result<(PivAlgorithm, PublicKey), PivError> {
    let CertKey {
        algorithm,
        curve,
        key,
    } = cert_key(cert_der)?;

    if algorithm == OID_RSA_ENCRYPTION {
        let rsa = pkcs1::RsaPublicKey::from_der(&key)
            .map_err(|e| PivError::Crypto(format!("RSA public key: {e}")))?;
        let n_bytes = rsa.modulus.as_bytes();
        let alg = match n_bytes.len() {
            128 | 129 => PivAlgorithm::Rsa1024,
            256 | 257 => PivAlgorithm::Rsa2048,
            _ => {
                return Err(PivError::UnsupportedAlgorithm(format!(
                    "RSA key size {} bits",
                    n_bytes.len() * 8
                )));
            }
        };
        let key_data = KeyData::Rsa(ssh_key::public::RsaPublicKey {
            e: ssh_key::Mpint::from_positive_bytes(rsa.public_exponent.as_bytes())
                .map_err(|e| PivError::Crypto(e.to_string()))?,
            n: ssh_key::Mpint::from_positive_bytes(n_bytes)
                .map_err(|e| PivError::Crypto(e.to_string()))?,
        });
        Ok((alg, PublicKey::new(key_data, "")))
    } else if algorithm == OID_ED25519 {
        // Ed25519 (YubicoPIV 5.7+ extension slots, see apdu.rs). RFC 8410
        // stores the raw 32-byte point with no inner DER structure.
        let arr: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| PivError::Crypto(format!("Ed25519 pubkey length {} != 32", key.len())))?;
        Ok((
            PivAlgorithm::Ed25519,
            PublicKey::new(KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(arr)), ""),
        ))
    } else if algorithm == OID_EC_PUBLIC_KEY {
        let (alg, point) = ec_uncompressed(curve, &key)?;
        let ec_key =
            EcdsaPublicKey::from_sec1_bytes(&point).map_err(|e| PivError::Crypto(e.to_string()))?;
        Ok((alg, PublicKey::new(KeyData::Ecdsa(ec_key), "")))
    } else {
        Err(PivError::UnsupportedAlgorithm(
            "not an RSA, EC, or Ed25519 key".into(),
        ))
    }
}

/// Render an X.509 Name in OpenSSL's `X509_NAME_oneline` slash form
/// (`/CN=.../O=...`) — what C pivy's `piv_slot_subject`/`piv_slot_issuer` carry
/// (they store `X509_NAME_oneline(...)`). Each RDN is `/<short-name>=<value>`;
/// printable ASCII (`0x20..=0x7e`) is emitted verbatim and any other byte is
/// escaped `\xHH`. Standard RDN types use their OpenSSL short name (CN, O, OU,
/// C, …); an OID with no short name falls back to its text form. Byte-exact
/// with C for the common printable-DN case (the only case the fibby differential
/// and virtually all real certs exercise); exotic-byte DNs are approximated.
fn name_oneline(name: &openssl::x509::X509NameRef) -> String {
    let mut out = String::new();
    for entry in name.entries() {
        out.push('/');
        let obj = entry.object();
        let label = obj
            .nid()
            .short_name()
            .map(str::to_string)
            .unwrap_or_else(|_| obj.to_string());
        out.push_str(&label);
        out.push('=');
        for &b in entry.data().as_slice() {
            if (0x20..=0x7e).contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("\\x{b:02X}"));
            }
        }
    }
    out
}

/// The SEC1 uncompressed EC point (`04 || X || Y`) of a DER cert's public key —
/// the SubjectPublicKeyInfo bytes a CSR/cert builder needs. Errors if the cert's
/// key is not EC. Reuses the same SPKI path as [`extract_public_key`].
pub fn ec_sec1_point(cert_der: &[u8]) -> Result<Vec<u8>, PivError> {
    let CertKey {
        algorithm,
        curve,
        key,
    } = cert_key(cert_der)?;
    if algorithm != OID_EC_PUBLIC_KEY {
        return Err(PivError::UnsupportedAlgorithm(
            "certificate key is not EC".into(),
        ));
    }
    Ok(ec_uncompressed(curve, &key)?.1)
}

/// Subject, issuer (both `X509_NAME_oneline`), and cert serial (`BN_bn2hex` —
/// uppercase, even-length) from a DER cert, for the `piggy tool list` port.
/// The serial goes through the same `BN_bn2hex` as C (`BigNum::to_hex_str`), so
/// it is byte-identical; the DNs are byte-identical for printable names.
pub fn display_fields(cert_der: &[u8]) -> Result<(String, String, String), PivError> {
    let cert = X509::from_der(cert_der)?;
    let subject = name_oneline(cert.subject_name());
    let issuer = name_oneline(cert.issuer_name());
    let serial = cert.serial_number().to_bn()?.to_hex_str()?.to_string();
    Ok((subject, issuer, serial))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::PointConversionForm;

    fn p256_pubkey(key: &EcKey<openssl::pkey::Private>) -> KeyData {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&bytes).unwrap())
    }

    /// The OpenSSL-backed `extract_public_key` this crate shipped before
    /// piggy#337, kept as the oracle the pure-Rust parser must match.
    fn openssl_extract_public_key(cert_der: &[u8]) -> (PivAlgorithm, PublicKey) {
        let cert = X509::from_der(cert_der).unwrap();
        let pkey = cert.public_key().unwrap();
        if let Ok(rsa) = pkey.rsa() {
            let n = rsa.n().to_vec();
            let alg = match n.len() {
                128 | 129 => PivAlgorithm::Rsa1024,
                _ => PivAlgorithm::Rsa2048,
            };
            let key_data = KeyData::Rsa(ssh_key::public::RsaPublicKey {
                e: ssh_key::Mpint::from_positive_bytes(&rsa.e().to_vec()).unwrap(),
                n: ssh_key::Mpint::from_positive_bytes(&n).unwrap(),
            });
            return (alg, PublicKey::new(key_data, ""));
        }
        if pkey.id() == openssl::pkey::Id::ED25519 {
            let arr = raw_ed25519_from_spki(&pkey).unwrap();
            let key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(arr));
            return (PivAlgorithm::Ed25519, PublicKey::new(key_data, ""));
        }
        let ec = pkey.ec_key().unwrap();
        let alg = match ec.group().curve_name().unwrap() {
            Nid::X9_62_PRIME256V1 => PivAlgorithm::EcP256,
            _ => PivAlgorithm::EcP384,
        };
        let mut ctx = BigNumContext::new().unwrap();
        let point = ec
            .public_key()
            .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let key_data = KeyData::Ecdsa(EcdsaPublicKey::from_sec1_bytes(&point).unwrap());
        (alg, PublicKey::new(key_data, ""))
    }

    fn self_signed_der(
        pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
        md: openssl::hash::MessageDigest,
    ) -> Vec<u8> {
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "piggy-test:cert").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(pkey).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        let serial = openssl::bn::BigNum::from_u32(1)
            .unwrap()
            .to_asn1_integer()
            .unwrap();
        b.set_serial_number(&serial).unwrap();
        b.sign(pkey, md).unwrap();
        b.build().to_der().unwrap()
    }

    fn ec_cert(nid: Nid) -> Vec<u8> {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = openssl::pkey::PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        self_signed_der(&key, openssl::hash::MessageDigest::sha256())
    }

    /// piggy#337: the pure-Rust SPKI read returns exactly what the OpenSSL
    /// path did, for every key type a PIV slot cert can carry.
    #[test]
    fn extract_public_key_matches_the_openssl_path() {
        use openssl::pkey::PKey;
        let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let ed = PKey::generate_ed25519().unwrap();
        let corpus = [
            ("P-256", ec_cert(Nid::X9_62_PRIME256V1)),
            ("P-384", ec_cert(Nid::SECP384R1)),
            (
                "RSA-2048",
                self_signed_der(&rsa, openssl::hash::MessageDigest::sha256()),
            ),
            (
                "Ed25519",
                self_signed_der(&ed, openssl::hash::MessageDigest::null()),
            ),
        ];
        for (what, der) in corpus {
            let got = extract_public_key(&der).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(got, openssl_extract_public_key(&der), "{what}");
        }
    }

    /// A compressed SEC1 point in the SPKI comes back uncompressed, as
    /// OpenSSL normalized it.
    #[test]
    fn ec_point_is_normalized_to_uncompressed() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let compressed = key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        let uncompressed = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        assert_eq!(compressed.len(), 33);
        let der = crate::cert_builder::build_self_signed_cert(
            &compressed,
            PivAlgorithm::EcP256,
            "piggy-test:compressed",
            |digest| Ok(EcdsaSig::sign(digest, &key).unwrap().to_der().unwrap()),
        )
        .unwrap();
        assert_eq!(ec_sec1_point(&der).unwrap(), uncompressed);
        assert_eq!(
            extract_public_key(&der).unwrap(),
            openssl_extract_public_key(&der)
        );
    }

    #[test]
    fn ec_sec1_point_rejects_a_non_ec_key() {
        let ed = openssl::pkey::PKey::generate_ed25519().unwrap();
        let der = self_signed_der(&ed, openssl::hash::MessageDigest::null());
        assert!(ec_sec1_point(&der).is_err());
    }

    #[test]
    fn verify_ec_signature_accepts_good_rejects_tampered_and_wrong_key() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let digest = [0x42u8; 32];
        let der = EcdsaSig::sign(&digest, &key).unwrap().to_der().unwrap();
        let kd = p256_pubkey(&key);

        // Good signature over the right digest with the matching key.
        assert!(verify_ec_signature(&kd, &digest, &der).unwrap());

        // Same signature, a different digest -> reject.
        assert!(!verify_ec_signature(&kd, &[0x00u8; 32], &der).unwrap());

        // Right digest + signature, but a different (non-matching) key ->
        // reject. This is the CAK anti-swap check: a wrong card's 9E key
        // would produce a signature that fails against the configured CAK.
        let other = EcKey::generate(&group).unwrap();
        let kd_other = p256_pubkey(&other);
        assert!(!verify_ec_signature(&kd_other, &digest, &der).unwrap());

        // A non-EC CAK is a hard error, not a silent reject.
        let ed = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([0u8; 32]));
        assert!(verify_ec_signature(&ed, &digest, &der).is_err());
    }
}
