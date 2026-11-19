//! `piggy ca csr`: the PKCS#10 request for a holder-held intermediate key
//! (FDR 0007 phase (iii-a), piggy#392).
//!
//! The key lives in the holder's fibby and is reached only through the
//! holder agent, from inside the scope it is bound to (FDR 0006 phase (d)),
//! so the request is signed by an ordinary agent sign request: the agent
//! hashes the CertificationRequestInfo with SHA-256 and signs with the P-256
//! key, and the SSH signature is reframed to the DER X.509 carries. No new
//! agent extension, no PIN, no touch. The CSR is public data; it travels to
//! the operator's machine as a file, where `piggy ca sign` (phase (ii)) or
//! openssl under the card-held root turns it into the intermediate
//! certificate (FDR 0007 "Transport and placement").
//!
//! The subject is one `CN` (the intermediate profile's); no SAN and no
//! requested extension, as the profile table requires: every extension
//! comes from the issuer's profile.

use std::io::Write;
use std::path::PathBuf;

use clap::Args;
use ssh_key::public::{EcdsaPublicKey, KeyData};

use piggy::agent_client::{AgentSignError, agent_sign_ecdsa_der};

use super::{Exit, Failure, failure};

/// The intermediate profile's common name when none is given (FDR 0007:
/// "one `CN`, the profile's").
pub const DEFAULT_CN: &str = "piggy-ca-intermediate";

#[derive(Args, Debug)]
pub struct CsrArgs {
    /// The key's OpenSSH public key line, as `piggy holder mint` printed it.
    /// Must be an ecdsa-sha2-nistp256 key the agent serves.
    #[arg(long, value_name = "FILE")]
    pub key: PathBuf,
    /// The subject common name (the intermediate profile's CN).
    #[arg(long, value_name = "NAME", default_value = DEFAULT_CN)]
    pub cn: String,
    /// Write the PEM here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// The SEC1 uncompressed point of a P-256 OpenSSH key, or why not.
fn p256_point(key: &ssh_key::PublicKey) -> Result<Vec<u8>, String> {
    match key.key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) => Ok(point.as_bytes().to_vec()),
        other => Err(format!(
            "the key is {}; an intermediate is a P-256 key (mint it with `piggy holder mint --type p256`)",
            other.algorithm()
        )),
    }
}

/// PEM, 64 columns, as `openssl req` reads it.
pub fn pem_certificate_request(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE REQUEST-----\n");
    out
}

fn exit_of(error: &AgentSignError) -> Exit {
    match error {
        AgentSignError::Unreachable(_) => Exit::NotServed,
        AgentSignError::NoKey(_) | AgentSignError::Refused(_) => Exit::Refused,
    }
}

pub(crate) fn execute(args: CsrArgs) -> Result<(), Failure> {
    let text = std::fs::read_to_string(&args.key)
        .map_err(|e| failure(Exit::Usage)(format!("read {}: {e}", args.key.display())))?;
    let key = ssh_key::PublicKey::from_openssh(text.trim()).map_err(|e| {
        failure(Exit::Usage)(format!(
            "{}: not an OpenSSH public key line: {e}",
            args.key.display()
        ))
    })?;
    let point = p256_point(&key).map_err(failure(Exit::Usage))?;
    let blob = key
        .to_bytes()
        .map_err(|e| failure(Exit::Usage)(format!("encode the key: {e}")))?;
    if args.cn.is_empty() {
        return Err(failure(Exit::Usage)("--cn must not be empty".into()));
    }
    let socket = super::agent_socket().map_err(failure(Exit::NotServed))?;

    // The agent call happens inside the builder's closure; its error is
    // carried out through PivError's text and classified afterwards.
    let agent_error = std::cell::RefCell::new(None);
    let csr_der = piggy_piv::cert_builder::build_csr_over_info(
        &point,
        piggy_piv::PivAlgorithm::EcP256,
        &args.cn,
        |info_der| {
            agent_sign_ecdsa_der(&socket, &blob, info_der).map_err(|e| {
                let text = e.to_string();
                *agent_error.borrow_mut() = Some(e);
                piggy_piv::PivError::Other(text)
            })
        },
    )
    .map_err(|e| match agent_error.borrow().as_ref() {
        Some(agent) => {
            failure(exit_of(agent))(format!("the agent did not sign the request: {agent}"))
        }
        None => failure(Exit::Refused)(format!("build the request: {e}")),
    })?;

    let pem = pem_certificate_request(&csr_der);
    match &args.out {
        Some(path) => std::fs::write(path, pem)
            .map_err(|e| failure(Exit::Refused)(format!("write {}: {e}", path.display())))?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(pem.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| failure(Exit::Refused)(format!("write stdout: {e}")))?;
        }
    }
    eprintln!(
        "piggy ca csr: request for CN={} over {} signed through the agent",
        args.cn,
        key.comment()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_wraps_at_64_columns_with_the_request_armor() {
        let pem = pem_certificate_request(&[0xAB; 100]);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE REQUEST-----");
        assert_eq!(*lines.last().unwrap(), "-----END CERTIFICATE REQUEST-----");
        let body = &lines[1..lines.len() - 1];
        assert!(body.iter().all(|l| l.len() <= 64 && !l.is_empty()));
        assert_eq!(body[0].len(), 64);
    }

    #[test]
    fn only_a_p256_key_makes_an_intermediate_request() {
        let ed = ssh_key::PublicKey::new(
            KeyData::Ed25519(ssh_key::public::Ed25519PublicKey([7; 32])),
            "holder:piggy-holder 1",
        );
        let err = p256_point(&ed).unwrap_err();
        assert!(
            err.contains("ssh-ed25519") && err.contains("--type p256"),
            "{err}"
        );
    }

    /// The whole glue off the agent: a software P-256 key signs the info the
    /// way the agent does (SHA-256, SSH framing), the SSH signature is
    /// reframed to DER through `ecdsa_sig`, and openssl verifies the CSR.
    #[test]
    fn a_request_signed_the_agents_way_verifies() {
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        use openssl::ecdsa::EcdsaSig;
        use openssl::hash::{MessageDigest, hash};
        use openssl::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();

        let csr_der = piggy_piv::cert_builder::build_csr_over_info(
            &point,
            piggy_piv::PivAlgorithm::EcP256,
            "piggy-ca-intermediate",
            |info_der| {
                // What the agent does: hash, sign, SSH-frame.
                let digest = hash(MessageDigest::sha256(), info_der).unwrap();
                let der = EcdsaSig::sign(&digest, &key).unwrap().to_der().unwrap();
                let raw = piggy::ecdsa_sig::der_to_raw_rs(&der, 32).unwrap();
                let ssh_blob = piggy::ecdsa_sig::raw_rs_to_ssh_ecdsa_blob(&raw).unwrap();
                // What this verb does with the answer.
                piggy::ecdsa_sig::ssh_ecdsa_blob_to_der(&ssh_blob)
                    .map_err(piggy_piv::PivError::Other)
            },
        )
        .unwrap();

        let req = openssl::x509::X509Req::from_der(&csr_der).unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        let cn = req
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap();
        assert_eq!(
            cn.data().as_utf8().unwrap().to_string(),
            "piggy-ca-intermediate"
        );
        // And the PEM round-trips through openssl's reader.
        let pem = pem_certificate_request(&csr_der);
        assert!(openssl::x509::X509Req::from_pem(pem.as_bytes()).is_ok());
    }
}
