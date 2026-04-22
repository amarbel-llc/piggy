use openssl::nid::Nid;
use openssl::x509::X509;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::PublicKey;

use crate::error::PivError;
use crate::slot::PivAlgorithm;

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
                )))
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

    if let Ok(ec) = pkey.ec_key() {
        let group = ec.group();
        let nid = group.curve_name().ok_or_else(|| {
            PivError::UnsupportedAlgorithm("unnamed EC curve".into())
        })?;

        let mut ctx = openssl::bn::BigNumContext::new()?;
        let point_bytes = ec
            .public_key()
            .to_bytes(group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)?;

        let alg = match nid {
            Nid::X9_62_PRIME256V1 => PivAlgorithm::EcP256,
            Nid::SECP384R1 => PivAlgorithm::EcP384,
            _ => {
                return Err(PivError::UnsupportedAlgorithm(format!(
                    "EC curve NID {:?}",
                    nid
                )))
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
            "not RSA or EC key".into(),
        ))
    }
}
