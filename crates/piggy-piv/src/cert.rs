use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::x509::X509;
use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};

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

/// Extract the public key algorithm and ssh_key::PublicKey from a DER-encoded X.509 cert.
pub fn extract_public_key(cert_der: &[u8]) -> Result<(PivAlgorithm, PublicKey), PivError> {
    let cert = X509::from_der(cert_der)?;
    let pkey = cert.public_key()?;

    if let Ok(rsa) = pkey.rsa() {
        let n_bytes = rsa.n().to_vec();
        let e_bytes = rsa.e().to_vec();

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
            e: ssh_key::Mpint::from_positive_bytes(&e_bytes)
                .map_err(|e| PivError::Crypto(e.to_string()))?,
            n: ssh_key::Mpint::from_positive_bytes(&n_bytes)
                .map_err(|e| PivError::Crypto(e.to_string()))?,
        });
        let pubkey = PublicKey::new(key_data, "");
        return Ok((alg, pubkey));
    }

    // Ed25519 (YubicoPIV 5.7+ extension slots, see apdu.rs). RFC 8410
    // stores the key as the raw 32-byte point in the SPKI.
    if pkey.id() == openssl::pkey::Id::ED25519 {
        let raw = pkey.raw_public_key()?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            PivError::Crypto(format!("Ed25519 pubkey length {} != 32", raw.len()))
        })?;
        let key_data = KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(arr));
        let pubkey = PublicKey::new(key_data, "");
        return Ok((PivAlgorithm::Ed25519, pubkey));
    }

    if let Ok(ec) = pkey.ec_key() {
        let group = ec.group();
        let nid = group
            .curve_name()
            .ok_or_else(|| PivError::UnsupportedAlgorithm("unnamed EC curve".into()))?;

        let mut ctx = openssl::bn::BigNumContext::new()?;
        let point_bytes = ec.public_key().to_bytes(
            group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?;

        let alg = match nid {
            Nid::X9_62_PRIME256V1 => PivAlgorithm::EcP256,
            Nid::SECP384R1 => PivAlgorithm::EcP384,
            _ => {
                return Err(PivError::UnsupportedAlgorithm(format!(
                    "EC curve NID {:?}",
                    nid
                )));
            }
        };

        // from_sec1_bytes infers the curve from point size (65=P256, 97=P384)
        let ec_key = EcdsaPublicKey::from_sec1_bytes(&point_bytes)
            .map_err(|e| PivError::Crypto(e.to_string()))?;
        let key_data = KeyData::Ecdsa(ec_key);
        let pubkey = PublicKey::new(key_data, "");
        Ok((alg, pubkey))
    } else {
        Err(PivError::UnsupportedAlgorithm(
            "not an RSA, EC, or Ed25519 key".into(),
        ))
    }
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
