//! x509-profile-probe OUTDIR
//!
//! Writes the certificates the FDR 0007 phase (i) lane checks with
//! `openssl verify` (piggy#393). Every name below is a fixture; every key
//! is a fresh software key, never a card's.
//!
//! Made by piggy-piv's builders (`x509_profile`), signed through the same
//! digest-signing closure a card slot fills:
//!
//! - `p256/root.pem`: the root profile, permitting `github.com`.
//! - `p256/intermediate.pem`: the intermediate profile under it.
//! - `p256/leaf.pem`: a leaf for github.com, api.github.com and
//!   codeload.github.com under the intermediate (verifies).
//! - `p256/leaf-direct.pem`: the pilot's leaf, signed by the root itself
//!   (verifies).
//! - `p256/leaf-foreign.pem`: a leaf for example.org under the root (fails).
//! - `p256/leaf-foreign-int.pem`: the same under the intermediate (fails).
//! - `p256/wide-intermediate.pem`, `p256/leaf-foreign-wide.pem`: an
//!   intermediate whose own constraints permit example.org, and an
//!   example.org leaf under it (fails: the root's constraints still apply);
//!   `p256/leaf-wide.pem`, a github.com leaf under it (verifies: the
//!   control).
//! - `p384/root.pem`, `p384/leaf-direct.pem`: a P-384 root signing a P-256
//!   leaf (verifies).
//!
//! Made with openssl, because no builder makes them:
//!
//! - `p256/leaf-ip.pem`: a root-signed leaf whose SAN is github.com and an
//!   IP address (fails: every IP address is excluded).
//! - `p256/rogue-intermediate.pem`: a root-signed CA with no name
//!   constraints at all; `p256/leaf-foreign-rogue.pem`: an example.org leaf
//!   under it, made by the leaf builder (fails); `p256/leaf-rogue.pem`, a
//!   github.com leaf under it (verifies: the control).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use piggy_piv::PivAlgorithm;
use piggy_piv::error::PivError;
use piggy_piv::x509_profile::{
    CertValidity, build_intermediate_cert, build_leaf_cert, build_root_cert,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Key {
    ec: EcKey<Private>,
    algorithm: PivAlgorithm,
}

impl Key {
    fn new(algorithm: PivAlgorithm) -> Result<Self> {
        let nid = match algorithm {
            PivAlgorithm::EcP384 => Nid::SECP384R1,
            _ => Nid::X9_62_PRIME256V1,
        };
        let group = EcGroup::from_curve_name(nid)?;
        Ok(Key {
            ec: EcKey::generate(&group)?,
            algorithm,
        })
    }
    fn point(&self) -> Result<Vec<u8>> {
        let mut ctx = BigNumContext::new()?;
        Ok(self.ec.public_key().to_bytes(
            self.ec.group(),
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?)
    }
    /// The signer closure a card slot fills: digest in, DER ECDSA out.
    fn signer(&self) -> impl FnOnce(&[u8]) -> std::result::Result<Vec<u8>, PivError> + '_ {
        |digest| {
            EcdsaSig::sign(digest, &self.ec)
                .and_then(|s| s.to_der())
                .map_err(|e| PivError::Other(e.to_string()))
        }
    }
    fn pkey(&self) -> Result<PKey<Private>> {
        Ok(PKey::from_ec_key(self.ec.clone())?)
    }
}

fn serial() -> Result<Vec<u8>> {
    let mut bn = BigNum::new()?;
    bn.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let mut bytes = bn.to_vec();
    while bytes.len() < 16 {
        bytes.insert(0, 0x5A);
    }
    Ok(bytes)
}

fn validity(days: u64) -> CertValidity {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970");
    CertValidity {
        not_before: now - Duration::from_secs(300),
        not_after: now + Duration::from_secs(days * 86_400),
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn write_pem(dir: &Path, file: &str, der: &[u8]) -> Result<()> {
    std::fs::write(dir.join(file), X509::from_der(der)?.to_pem()?)?;
    Ok(())
}

/// A certificate under `issuer` (signed by `issuer_key`) that no builder
/// makes: `ca` true gives a CA with no name constraints, else a leaf whose
/// SAN is `san`.
fn openssl_cert(
    issuer: &X509,
    issuer_key: &Key,
    subject_key: &Key,
    common_name: &str,
    ca: bool,
    san: Option<&[&str]>,
) -> Result<Vec<u8>> {
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    let name = name.build();
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    let serial_number = BigNum::from_slice(&serial()?)?.to_asn1_integer()?;
    b.set_serial_number(&serial_number)?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(issuer.subject_name())?;
    let subject_pkey = subject_key.pkey()?;
    b.set_pubkey(&subject_pkey)?;
    let (not_before, not_after) = (Asn1Time::days_from_now(0)?, Asn1Time::days_from_now(1)?);
    b.set_not_before(&not_before)?;
    b.set_not_after(&not_after)?;
    if ca {
        b.append_extension(BasicConstraints::new().critical().ca().pathlen(0).build()?)?;
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
    } else {
        b.append_extension(BasicConstraints::new().critical().build()?)?;
        b.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    }
    if let Some(entries) = san {
        let mut s = SubjectAlternativeName::new();
        for entry in entries {
            match entry.strip_prefix("IP:") {
                Some(ip) => s.ip(ip),
                None => s.dns(entry),
            };
        }
        let ext = s.build(&b.x509v3_context(Some(issuer), None))?;
        b.append_extension(ext)?;
    }
    let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(Some(issuer), None))?;
    b.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&b.x509v3_context(Some(issuer), None))?;
    b.append_extension(aki)?;
    let issuer_pkey = issuer_key.pkey()?;
    b.sign(&issuer_pkey, MessageDigest::sha256())?;
    Ok(b.build().to_der()?)
}

fn p256_set(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let permitted = names(&["github.com"]);
    let root_key = Key::new(PivAlgorithm::EcP256)?;
    let root = build_root_cert(
        &root_key.point()?,
        root_key.algorithm,
        "piggy-test root",
        &permitted,
        validity(3650),
        &serial()?,
        root_key.signer(),
    )?;
    write_pem(dir, "root.pem", &root)?;

    let int_key = Key::new(PivAlgorithm::EcP256)?;
    let intermediate = build_intermediate_cert(
        &int_key.point()?,
        int_key.algorithm,
        "piggy-test intermediate",
        &permitted,
        &root,
        validity(7),
        &serial()?,
        root_key.signer(),
    )?;
    write_pem(dir, "intermediate.pem", &intermediate)?;

    let leaf_key = Key::new(PivAlgorithm::EcP256)?;
    let leaf = |names_: &[&str], issuer: &[u8], issuer_key: &Key| -> Result<Vec<u8>> {
        Ok(build_leaf_cert(
            &leaf_key.point()?,
            leaf_key.algorithm,
            &names(names_),
            issuer,
            validity(1),
            &serial()?,
            issuer_key.signer(),
        )?)
    };
    let three = ["github.com", "api.github.com", "codeload.github.com"];
    write_pem(dir, "leaf.pem", &leaf(&three, &intermediate, &int_key)?)?;
    write_pem(dir, "leaf-direct.pem", &leaf(&three, &root, &root_key)?)?;
    write_pem(
        dir,
        "leaf-foreign.pem",
        &leaf(&["example.org"], &root, &root_key)?,
    )?;
    write_pem(
        dir,
        "leaf-foreign-int.pem",
        &leaf(&["example.org"], &intermediate, &int_key)?,
    )?;

    let wide_key = Key::new(PivAlgorithm::EcP256)?;
    let wide = build_intermediate_cert(
        &wide_key.point()?,
        wide_key.algorithm,
        "piggy-test wide intermediate",
        &names(&["github.com", "example.org"]),
        &root,
        validity(7),
        &serial()?,
        root_key.signer(),
    )?;
    write_pem(dir, "wide-intermediate.pem", &wide)?;
    write_pem(
        dir,
        "leaf-foreign-wide.pem",
        &leaf(&["example.org"], &wide, &wide_key)?,
    )?;
    write_pem(
        dir,
        "leaf-wide.pem",
        &leaf(&["github.com"], &wide, &wide_key)?,
    )?;

    let root_x509 = X509::from_der(&root)?;
    let ip_leaf = openssl_cert(
        &root_x509,
        &root_key,
        &leaf_key,
        "github.com",
        false,
        Some(&["github.com", "IP:192.0.2.1"]),
    )?;
    write_pem(dir, "leaf-ip.pem", &ip_leaf)?;

    let rogue_key = Key::new(PivAlgorithm::EcP256)?;
    let rogue = openssl_cert(
        &root_x509,
        &root_key,
        &rogue_key,
        "piggy-test rogue intermediate",
        true,
        None,
    )?;
    write_pem(dir, "rogue-intermediate.pem", &rogue)?;
    write_pem(
        dir,
        "leaf-foreign-rogue.pem",
        &leaf(&["example.org"], &rogue, &rogue_key)?,
    )?;
    write_pem(
        dir,
        "leaf-rogue.pem",
        &leaf(&["github.com"], &rogue, &rogue_key)?,
    )?;
    Ok(())
}

fn p384_set(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let root_key = Key::new(PivAlgorithm::EcP384)?;
    let root = build_root_cert(
        &root_key.point()?,
        root_key.algorithm,
        "piggy-test p384 root",
        &names(&["github.com"]),
        validity(3650),
        &serial()?,
        root_key.signer(),
    )?;
    write_pem(dir, "root.pem", &root)?;
    let leaf_key = Key::new(PivAlgorithm::EcP256)?;
    let leaf = build_leaf_cert(
        &leaf_key.point()?,
        leaf_key.algorithm,
        &names(&["api.github.com"]),
        &root,
        validity(30),
        &serial()?,
        root_key.signer(),
    )?;
    write_pem(dir, "leaf-direct.pem", &leaf)?;
    Ok(())
}

fn main() -> Result<()> {
    let Some(out) = std::env::args().nth(1) else {
        eprintln!("usage: x509-profile-probe OUTDIR");
        std::process::exit(2);
    };
    let out = Path::new(&out);
    p256_set(&out.join("p256"))?;
    p384_set(&out.join("p384"))?;
    Ok(())
}
