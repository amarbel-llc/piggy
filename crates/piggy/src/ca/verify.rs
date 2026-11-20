//! `piggy ca verify --root ROOT [--untrusted FILE]... [--key FILE] [--at UNIX]
//! LEAF`: the chain check of FDR 0007 over `piggy_piv::x509_verify`, one
//! TAP-14 point per check. A checker, not a gate: issuance never calls it.
//!
//! Exit 0 valid, 1 the chain does not hold (the failing points say why), 2
//! usage, 4 a file that is unreadable or not a certificate (the `ca`
//! table's malformed-input row; verify has no profile, so 3 is not used).
//! The given root is the only trust anchor; no system store is consulted.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;
use piggy_piv::x509_verify::{self, Expect, Report};

use super::{Exit, Failure, failure};

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// The trust anchor: one certificate, PEM or DER. The only anchor.
    #[arg(long, value_name = "FILE")]
    pub root: PathBuf,
    /// Intermediates, PEM (any number per file) or DER; may be repeated.
    #[arg(long, value_name = "FILE")]
    pub untrusted: Vec<PathBuf>,
    /// The key the leaf must carry: an OpenSSH public key line, a PEM
    /// public or private key, or a PKCS#10 request (PEM or DER).
    #[arg(long, value_name = "FILE")]
    pub key: Option<PathBuf>,
    /// Read the validity windows at this time (Unix seconds) instead of now.
    #[arg(long, value_name = "UNIX")]
    pub at: Option<u64>,
    /// The leaf, PEM or DER. A PEM holding several certificates (a chain
    /// file) gives its first as the leaf and the rest as untrusted.
    pub leaf: PathBuf,
}

/// Every certificate in `path`: the PEM blocks in order, or one DER
/// certificate. Exit 4 for a file that cannot be read or holds none.
pub(crate) fn certificates_in(path: &Path) -> Result<Vec<Vec<u8>>, Failure> {
    let refuse = failure(Exit::Csr);
    let bytes = std::fs::read(path).map_err(|e| refuse(format!("read {}: {e}", path.display())))?;
    let ders = if bytes.windows(10).any(|w| w == b"-----BEGIN") {
        openssl::x509::X509::stack_from_pem(&bytes)
            .map_err(|e| refuse(format!("{}: not PEM certificates: {e}", path.display())))?
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| refuse(format!("{}: {e}", path.display())))?
    } else {
        openssl::x509::X509::from_der(&bytes)
            .map_err(|e| refuse(format!("{}: not a certificate: {e}", path.display())))?;
        vec![bytes]
    };
    if ders.is_empty() {
        return Err(refuse(format!("{}: no certificate in it", path.display())));
    }
    Ok(ders)
}

/// The SEC1 uncompressed point of the key in `path`: an OpenSSH public
/// key line, a PEM public or private key, or a PKCS#10 request (PEM or
/// DER). Exit 4 when it is none of these.
pub(crate) fn key_point_in(path: &Path) -> Result<Vec<u8>, Failure> {
    use openssl::ec::PointConversionForm;
    use ssh_key::public::{EcdsaPublicKey, KeyData};
    let refuse = failure(Exit::Csr);
    let bytes = std::fs::read(path).map_err(|e| refuse(format!("read {}: {e}", path.display())))?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim();
    if text.starts_with("ecdsa-sha2-") || text.starts_with("ssh-") {
        let key = ssh_key::PublicKey::from_openssh(text).map_err(|e| {
            refuse(format!(
                "{}: not an OpenSSH public key line: {e}",
                path.display()
            ))
        })?;
        return match key.key_data() {
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => Ok(p.as_bytes().to_vec()),
            KeyData::Ecdsa(EcdsaPublicKey::NistP384(p)) => Ok(p.as_bytes().to_vec()),
            other => Err(refuse(format!(
                "{}: the key is {}, not EC P-256 or P-384",
                path.display(),
                other.algorithm()
            ))),
        };
    }
    use openssl::pkey::{PKey, Public};
    let pkey: Result<PKey<Public>, _> = if text.contains("BEGIN CERTIFICATE REQUEST") {
        openssl::x509::X509Req::from_pem(&bytes).and_then(|r| r.public_key())
    } else if text.contains("BEGIN PUBLIC KEY") {
        PKey::public_key_from_pem(&bytes)
    } else if text.contains("PRIVATE KEY") {
        PKey::private_key_from_pem(&bytes)
            .and_then(|k| k.public_key_to_der())
            .and_then(|der| PKey::public_key_from_der(&der))
    } else {
        openssl::x509::X509Req::from_der(&bytes).and_then(|r| r.public_key())
    };
    let pkey = pkey.map_err(|e| {
        refuse(format!(
            "{}: not an OpenSSH key line, a PEM key or a PKCS#10 request: {e}",
            path.display()
        ))
    })?;
    let ec = pkey
        .ec_key()
        .map_err(|_| refuse(format!("{}: the key is not an EC key", path.display())))?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| refuse(e.to_string()))?;
    ec.public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| refuse(e.to_string()))
}

fn now() -> Result<Duration, Failure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| failure(Exit::Refused)(format!("the clock is before 1970: {e}")))
}

/// The report as TAP-14 on stdout: one point per check, its detail as a
/// diagnostic.
pub(crate) fn print_tap(report: &Report) -> std::io::Result<()> {
    let points: Vec<piggy::tap_print::Point<'_>> = report
        .checks
        .iter()
        .map(|check| piggy::tap_print::Point {
            name: &check.name,
            ok: check.ok,
            diags: check
                .detail
                .iter()
                .map(|d| ("detail", serde_json::Value::String(d.clone())))
                .collect(),
        })
        .collect();
    piggy::tap_print::print_tap(&points)
}

pub(crate) fn execute(args: VerifyArgs) -> Result<(), Failure> {
    let mut leaf_file = certificates_in(&args.leaf)?;
    let leaf = leaf_file.remove(0);
    let mut untrusted = leaf_file;
    for path in &args.untrusted {
        untrusted.extend(certificates_in(path)?);
    }
    let root = certificates_in(&args.root)?;
    if root.len() != 1 {
        return Err(failure(Exit::Csr)(format!(
            "{}: the root must be one certificate, not {}",
            args.root.display(),
            root.len()
        )));
    }
    let key_point = args.key.as_deref().map(key_point_in).transpose()?;
    let at = match args.at {
        Some(secs) => Duration::from_secs(secs),
        None => now()?,
    };
    let untrusted_refs: Vec<&[u8]> = untrusted.iter().map(Vec::as_slice).collect();
    let report = x509_verify::verify_chain(
        &root[0],
        &untrusted_refs,
        &leaf,
        &Expect {
            at,
            leaf_key_point: key_point.as_deref(),
        },
    )
    .map_err(|e| failure(Exit::Csr)(e.to_string()))?;
    print_tap(&report).map_err(|e| failure(Exit::Refused)(format!("write stdout: {e}")))?;
    let failed = report.checks.iter().filter(|c| !c.ok).count();
    if failed > 0 {
        return Err(failure(Exit::Refused)(format!(
            "the chain does not verify: {failed} of {} checks failed",
            report.checks.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Cli {
        #[command(flatten)]
        args: VerifyArgs,
    }

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("piggy-ca-verify-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn verify_needs_a_root_and_a_leaf_and_takes_many_untrusted() {
        assert!(
            Cli::try_parse_from(["x", "leaf.pem"]).is_err(),
            "--root is required"
        );
        assert!(
            Cli::try_parse_from(["x", "--root", "r.pem"]).is_err(),
            "the leaf is required"
        );
        let cli = Cli::try_parse_from([
            "x",
            "--root",
            "r.pem",
            "--untrusted",
            "a.pem",
            "--untrusted",
            "b.pem",
            "--key",
            "k.pub",
            "--at",
            "1800000000",
            "leaf.pem",
        ])
        .unwrap();
        assert_eq!(cli.args.untrusted.len(), 2);
        assert_eq!(cli.args.at, Some(1_800_000_000));
        assert_eq!(cli.args.leaf.to_string_lossy(), "leaf.pem");
    }

    #[test]
    fn files_are_read_as_pem_stacks_or_one_der_and_junk_is_exit_4() {
        let dir = tmp("files");
        let key = openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(key).unwrap();
        let mut b = openssl::x509::X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_pubkey(&pkey).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let cert = b.build();
        let pem = cert.to_pem().unwrap();
        let der = cert.to_der().unwrap();

        let one = dir.join("one.pem");
        std::fs::write(&one, &pem).unwrap();
        assert_eq!(certificates_in(&one).unwrap(), vec![der.clone()]);
        let two = dir.join("two.pem");
        std::fs::write(&two, [pem.clone(), pem.clone()].concat()).unwrap();
        assert_eq!(certificates_in(&two).unwrap().len(), 2);
        let raw = dir.join("one.der");
        std::fs::write(&raw, &der).unwrap();
        assert_eq!(certificates_in(&raw).unwrap(), vec![der]);
        let junk = dir.join("junk");
        std::fs::write(&junk, b"hello").unwrap();
        assert_eq!(certificates_in(&junk).unwrap_err().exit, Exit::Csr);
        assert_eq!(
            certificates_in(&dir.join("missing")).unwrap_err().exit,
            Exit::Csr
        );
        let empty = dir.join("empty.pem");
        std::fs::write(&empty, b"-----BEGIN NOTHING-----\n").unwrap();
        assert_eq!(certificates_in(&empty).unwrap_err().exit, Exit::Csr);

        // The key, in each form, is the same point.
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let ec = pkey.ec_key().unwrap();
        let want = ec
            .public_key()
            .to_bytes(
                ec.group(),
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )
            .unwrap();
        let pub_pem = dir.join("k.pub.pem");
        std::fs::write(&pub_pem, pkey.public_key_to_pem().unwrap()).unwrap();
        assert_eq!(key_point_in(&pub_pem).unwrap(), want);
        let priv_pem = dir.join("k.key");
        std::fs::write(&priv_pem, pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
        assert_eq!(key_point_in(&priv_pem).unwrap(), want);
        let mut rb = openssl::x509::X509ReqBuilder::new().unwrap();
        rb.set_pubkey(&pkey).unwrap();
        rb.sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let req = rb.build();
        let csr = dir.join("k.csr");
        std::fs::write(&csr, req.to_pem().unwrap()).unwrap();
        assert_eq!(key_point_in(&csr).unwrap(), want);
        let csr_der = dir.join("k.csr.der");
        std::fs::write(&csr_der, req.to_der().unwrap()).unwrap();
        assert_eq!(key_point_in(&csr_der).unwrap(), want);
        let line = dir.join("k.pub");
        std::fs::write(
            &line,
            super::super::openssh_ecdsa_line(&want, "test").unwrap(),
        )
        .unwrap();
        assert_eq!(key_point_in(&line).unwrap(), want);
        assert_eq!(key_point_in(&junk).unwrap_err().exit, Exit::Csr);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
