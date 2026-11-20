//! `piggy ca leaf-csr`: a software P-256 leaf key and its PKCS#10 request
//! in one step, with no agent, no holder and no card (FDR 0007 "Transport
//! and placement": the host that serves a leaf makes its own key and the
//! key never leaves; the pilot's shim reads a key file).
//!
//! The key is written first, as PKCS#8 PEM with mode 0600 and created
//! fresh (`O_EXCL`): a file that exists is refused and left alone. The
//! request carries the subject `CN` alone, no SAN and no requested
//! extension, because the leaf profile supplies the names (`ca_issue`); it
//! is signed ECDSA-SHA256 by the new key through
//! `cert_builder::build_csr` and read back through `csr_check::parse_csr`
//! before anything is written, so a request this verb emits is one `piggy
//! ca issue` accepts. When anything fails after the key file was created,
//! the verb removes the file it created (never one that was there) and
//! says so. The key's public half is printed as an OpenSSH line on stderr,
//! the form `piggy ca verify --key` compares later.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use clap::Args;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use piggy_piv::{PivAlgorithm, PivError, cert_builder, csr_check};
use zeroize::Zeroizing;

use super::csr::pem_certificate_request;
use super::{Exit, Failure, failure};

#[derive(Args, Debug)]
pub struct LeafCsrArgs {
    /// Where the new P-256 private key goes: PKCS#8 PEM, mode 0600,
    /// created fresh. A file that exists is refused and left alone.
    #[arg(long, value_name = "FILE")]
    pub key_out: PathBuf,
    /// The subject common name: a plain DNS name the leaf profile permits
    /// (the leaf is issued with the profile's whole name set).
    #[arg(long, value_name = "NAME")]
    pub cn: String,
    /// Write the request PEM here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// A fresh key and the request that names it, in memory.
pub(crate) struct LeafRequest {
    /// The private key, PKCS#8 PEM.
    pub key_pem: Zeroizing<Vec<u8>>,
    pub csr_der: Vec<u8>,
    /// The key's public half as an OpenSSH line.
    pub public_line: String,
}

/// The comment on the OpenSSH line [`make`] prints.
const PUBLIC_LINE_COMMENT: &str = "piggy-ca-leaf";

fn ssl(e: openssl::error::ErrorStack) -> String {
    e.to_string()
}

/// Generate a P-256 key and sign a request whose one subject attribute is
/// `cn`; the request is parsed back the way `issue` parses it, so what
/// this returns is what `issue` accepts.
pub(crate) fn make(cn: &str) -> Result<LeafRequest, String> {
    piggy::ca_profile::check_dns_name(cn).map_err(|e| e.0)?;
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(ssl)?;
    let key = EcKey::generate(&group).map_err(ssl)?;
    let mut ctx = BigNumContext::new().map_err(ssl)?;
    let point = key
        .public_key()
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(ssl)?;
    let csr_der = cert_builder::build_csr(&point, PivAlgorithm::EcP256, cn, |digest| {
        EcdsaSig::sign(digest, &key)
            .and_then(|sig| sig.to_der())
            .map_err(|e| PivError::Other(e.to_string()))
    })
    .map_err(|e| format!("build the request: {e}"))?;
    let parsed = csr_check::parse_csr(&csr_der)
        .map_err(|e| format!("the request this verb built does not pass piggy's own check: {e}"))?;
    if parsed.pubkey_point != point
        || parsed.common_name.as_deref() != Some(cn)
        || !parsed.dns_names.is_empty()
        || parsed.other_san
    {
        return Err("the request this verb built does not name its own key and CN alone".into());
    }
    let key_pem = Zeroizing::new(
        PKey::from_ec_key(key)
            .and_then(|k| k.private_key_to_pem_pkcs8())
            .map_err(ssl)?,
    );
    Ok(LeafRequest {
        key_pem,
        csr_der,
        public_line: openssh_line(&point),
    })
}

/// The OpenSSH public key line of a P-256 SEC1 point (RFC 5656 §3.1):
/// `ecdsa-sha2-nistp256`, the curve name and the point, each
/// length-prefixed, base64.
fn openssh_line(point: &[u8]) -> String {
    use base64::Engine;
    fn put(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s);
    }
    let mut blob = Vec::new();
    put(&mut blob, b"ecdsa-sha2-nistp256");
    put(&mut blob, b"nistp256");
    put(&mut blob, point);
    format!(
        "ecdsa-sha2-nistp256 {} {PUBLIC_LINE_COMMENT}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

/// Create `path` fresh with mode 0600 and write the key into it. A file
/// that exists is an error and is not touched.
pub(crate) fn write_key(path: &Path, pem: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "{} exists; this verb never writes over a key (remove it, or name another file)",
                path.display()
            ),
            _ => format!("create {}: {e}", path.display()),
        })?;
    file.write_all(pem)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

pub(crate) fn execute(args: LeafCsrArgs) -> Result<(), Failure> {
    piggy::ca_profile::check_dns_name(&args.cn)
        .map_err(|e| failure(Exit::Usage)(format!("--cn: {}", e.0)))?;
    // Judged before any key is drawn, so a taken path costs nothing; the
    // O_EXCL create below is the guard that holds under a race.
    if args.key_out.exists() {
        return Err(failure(Exit::Refused)(format!(
            "{} exists; this verb never writes over a key (remove it, or name another file)",
            args.key_out.display()
        )));
    }
    let made = make(&args.cn).map_err(failure(Exit::Refused))?;
    write_key(&args.key_out, &made.key_pem).map_err(failure(Exit::Refused))?;

    let pem = pem_certificate_request(&made.csr_der);
    let written = match &args.out {
        Some(path) => {
            std::fs::write(path, pem).map_err(|e| format!("write {}: {e}", path.display()))
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(pem.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| format!("write stdout: {e}"))
        }
    };
    if let Err(why) = written {
        // The key this run created goes with its failed request; a key
        // that was there before is never reached (the create above refused
        // it).
        let key = args.key_out.display();
        let removed = match std::fs::remove_file(&args.key_out) {
            Ok(()) => format!("the key {key} this run created was removed"),
            Err(e) => {
                format!("the key {key} this run created was NOT removed ({e}): remove it by hand")
            }
        };
        return Err(failure(Exit::Refused)(format!("{why}; {removed}")));
    }
    eprintln!(
        "piggy ca leaf-csr: P-256 key written to {} (0600); request for CN={} signed by it; public key: {}",
        args.key_out.display(),
        args.cn,
        made.public_line
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::x509::X509Req;
    use ssh_key::public::{EcdsaPublicKey, KeyData};
    use std::os::unix::fs::PermissionsExt;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("piggy-ca-leaf-csr-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_request_for_a_fresh_key_passes_issues_own_check_and_names_the_cn() {
        let made = make("github.com").unwrap();
        let parsed = csr_check::parse_csr(&made.csr_der).unwrap();
        assert_eq!(parsed.algorithm, PivAlgorithm::EcP256);
        assert_eq!(parsed.common_name.as_deref(), Some("github.com"));
        assert!(parsed.dns_names.is_empty() && !parsed.other_san);
        // The leaf check a profile makes passes for the one CN.
        csr_check::check_leaf_names(&["github.com".into(), "api.github.com".into()], &parsed)
            .unwrap();

        // The key file is PKCS#8 and holds the request's key; openssl is
        // the oracle for the self-signature.
        let text = std::str::from_utf8(&made.key_pem).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----"), "{text}");
        let pkey = PKey::private_key_from_pem(&made.key_pem).unwrap();
        let req = X509Req::from_der(&made.csr_der).unwrap();
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
        assert!(pkey.public_eq(&req.public_key().unwrap()));
        assert!(X509Req::from_pem(pem_certificate_request(&made.csr_der).as_bytes()).is_ok());

        // The OpenSSH line is the same key, as `ca verify --key` will read it.
        let line = ssh_key::PublicKey::from_openssh(&made.public_line).unwrap();
        assert_eq!(line.comment(), PUBLIC_LINE_COMMENT);
        match line.key_data() {
            KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => {
                assert_eq!(p.as_bytes(), parsed.pubkey_point.as_slice());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_call_draws_a_new_key() {
        let a = make("github.com").unwrap();
        let b = make("github.com").unwrap();
        assert_ne!(*a.key_pem, *b.key_pem);
        assert_ne!(a.csr_der, b.csr_der);
        assert_ne!(a.public_line, b.public_line);
    }

    #[test]
    fn a_cn_that_is_not_a_plain_dns_name_is_refused_before_any_key_is_drawn() {
        for bad in ["", "*.github.com", "a b", "github..com", "-x.com"] {
            // `LeafRequest` holds a private key and so has no Debug for
            // `unwrap_err` to print; the error is taken by hand.
            let err = make(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad:?} was accepted as a CN"));
            assert!(err.contains("not a plain DNS name"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn the_key_file_is_created_fresh_private_and_never_written_over() {
        let dir = tmp("key");
        let path = dir.join("leaf.key");
        write_key(&path, b"first").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let err = write_key(&path, b"second").unwrap_err();
        assert!(err.contains("exists"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_request_that_cannot_be_written_takes_the_new_key_with_it() {
        let dir = tmp("exec");
        let key = dir.join("leaf.key");
        let err = execute(LeafCsrArgs {
            key_out: key.clone(),
            cn: "github.com".into(),
            out: Some(dir.join("nonexistent").join("leaf.csr")),
        })
        .unwrap_err();
        assert_eq!(err.exit, Exit::Refused);
        assert!(err.message.contains("was removed"), "{}", err.message);
        assert!(!key.exists(), "the key this run made must not stay behind");

        // A key that was there before is refused and left alone.
        std::fs::write(&key, b"keep").unwrap();
        let err = execute(LeafCsrArgs {
            key_out: key.clone(),
            cn: "github.com".into(),
            out: Some(dir.join("leaf.csr")),
        })
        .unwrap_err();
        assert_eq!(err.exit, Exit::Refused);
        assert!(err.message.contains("exists"), "{}", err.message);
        assert_eq!(std::fs::read(&key).unwrap(), b"keep");
        assert!(!dir.join("leaf.csr").exists());

        // A bad CN is usage, with no key drawn.
        let bad = dir.join("bad.key");
        let err = execute(LeafCsrArgs {
            key_out: bad.clone(),
            cn: "*.github.com".into(),
            out: None,
        })
        .unwrap_err();
        assert_eq!(err.exit, Exit::Usage);
        assert!(!bad.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
