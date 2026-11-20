//! `piggy ca`: X.509 issuance (FDR 0007). Phase (iii-a) brought the first
//! verb, `csr`, the certificate request for a holder-held intermediate
//! key; phase (ii) adds `root-cert` (here), `sign` and `issue` for a
//! card-held issuer beside it (each verb its own module, so they land
//! without conflict); `leaf-csr` is the card-free leaf key and request
//! for a host with no holder.
//!
//! Exit codes, one table for every verb (FDR 0007 "The issuance verbs"), so
//! a renewal timer reads one meaning per code: 0 done; 1 refused for any
//! other reason (on stderr); 2 usage; 3 the profile is unknown or
//! unreadable; 4 the request is malformed or its key type refused; 5 the
//! request's names are outside the profile; 6 the issuer key is
//! unavailable (card absent, slot empty or not proven on-card, PIN
//! refused, no agent serving the key); 7 rate limited.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod card_signer;
mod certificate_act;
mod csr;
mod holder_issuer;
mod issuance;
mod leaf_csr;
mod root_cert;
mod verify;

pub(crate) use verify::certificates_in;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    Refused = 1,
    Usage = 2,
    Profile = 3,
    Csr = 4,
    Names = 5,
    IssuerUnavailable = 6,
    RateLimited = 7,
}

#[derive(Debug)]
pub(crate) struct Failure {
    pub exit: Exit,
    pub message: String,
}

pub(crate) fn failure(exit: Exit) -> impl Fn(String) -> Failure {
    move |message| Failure { exit, message }
}

#[derive(Parser, Debug)]
#[command(
    name = "piggy ca",
    about = "X.509 issuance: a card-held root, a holder-held intermediate (FDR 0007)",
    disable_help_subcommand = true
)]
struct CaCli {
    #[command(subcommand)]
    cmd: CaCommand,
}

#[derive(Subcommand, Debug)]
enum CaCommand {
    /// A PKCS#10 certificate request for a key the agent serves (a holder
    /// intermediate key minted with `piggy holder mint --type p256`),
    /// signed through the agent; PEM on stdout.
    Csr(csr::CsrArgs),
    /// A fresh software P-256 leaf key (PKCS#8 PEM, 0600, never written
    /// over) and its PKCS#10 request for one CN, with no agent, no holder
    /// and no card; the request PEM on stdout.
    LeafCsr(leaf_csr::LeafCsrArgs),
    /// The self-signed root certificate of the card-held CA key a root
    /// profile names, signed on the local card after one PIN prompt; PEM
    /// on stdout. The slot is not written: `piggy tool write-cert` does
    /// that.
    RootCert(root_cert::RootCertArgs),
    /// An intermediate certificate for the PKCS#10 request on stdin, signed
    /// by the card-held root an intermediate profile names; PEM on stdout.
    Sign(issuance::IssuanceArgs),
    /// A leaf certificate for the PKCS#10 request on stdin, under a leaf
    /// profile's name constraints; PEM on stdout. One per profile per ten
    /// minutes.
    Issue(issuance::IssuanceArgs),
    /// Check a leaf under intermediates under one given root: signatures,
    /// validity, CA constraints, the leaf's profile, name constraints; TAP
    /// on stdout. A checker, not a gate.
    Verify(verify::VerifyArgs),
}

pub fn run(argv: &[String]) -> i32 {
    let full: Vec<String> = std::iter::once("piggy ca".to_string())
        .chain(argv.iter().cloned())
        .collect();
    let args = match CaCli::try_parse_from(&full) {
        Ok(a) => a,
        Err(e) => e.exit(),
    };
    let result = match args.cmd {
        CaCommand::Csr(args) => csr::execute(args),
        CaCommand::LeafCsr(args) => leaf_csr::execute(args),
        CaCommand::RootCert(args) => root_cert::execute(args),
        CaCommand::Sign(args) => issuance::execute(piggy::ca_issue::Verb::Sign, args),
        CaCommand::Issue(args) => issuance::execute(piggy::ca_issue::Verb::Issue, args),
        CaCommand::Verify(args) => verify::execute(args),
    };
    match result {
        Ok(()) => 0,
        Err(failure) => {
            eprintln!("piggy ca: {}", failure.message);
            failure.exit as i32
        }
    }
}

/// The OpenSSH public key line of an EC P-256 or P-384 SEC1 point (RFC
/// 5656 §3.1: the key type, the curve name and the point, each
/// length-prefixed, base64), with `comment` after it when not empty;
/// `None` for any other algorithm.
pub(crate) fn openssh_ecdsa_line(
    algorithm: piggy_piv::PivAlgorithm,
    point: &[u8],
    comment: &str,
) -> Option<String> {
    use base64::Engine;
    let (key_type, curve): (&[u8], &[u8]) = match algorithm {
        piggy_piv::PivAlgorithm::EcP256 => (b"ecdsa-sha2-nistp256", b"nistp256"),
        piggy_piv::PivAlgorithm::EcP384 => (b"ecdsa-sha2-nistp384", b"nistp384"),
        _ => return None,
    };
    fn put(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s);
    }
    let mut blob = Vec::new();
    put(&mut blob, key_type);
    put(&mut blob, curve);
    put(&mut blob, point);
    let mut line = format!(
        "{} {}",
        std::str::from_utf8(key_type).expect("ASCII"),
        base64::engine::general_purpose::STANDARD.encode(blob)
    );
    if !comment.is_empty() {
        line.push(' ');
        line.push_str(comment);
    }
    Some(line)
}

/// The agent socket every verb that signs through the agent uses.
pub(crate) fn agent_socket() -> Result<std::path::PathBuf, String> {
    piggy::agent_client::piggy_auth_sock_override()
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            "no agent socket: set PIGGY_AUTH_SOCK or SSH_AUTH_SOCK to the agent serving the key"
                .to_string()
        })
}

/// piggy's config home, where `ca-profiles/NAME.toml` lives:
/// `$PIGGY_CONFIG_HOME`, else `$XDG_CONFIG_HOME/piggy`, else
/// `~/.config/piggy` (the NixOS module sets the first). `None` when none
/// of the three can be formed.
pub(crate) fn config_home() -> Option<PathBuf> {
    config_home_from(
        std::env::var_os("PIGGY_CONFIG_HOME"),
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn config_home_from(
    piggy: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let set = |v: Option<std::ffi::OsString>| v.filter(|s| !s.is_empty()).map(PathBuf::from);
    set(piggy)
        .or_else(|| set(xdg).map(|d| d.join("piggy")))
        .or_else(|| set(home).map(|h| h.join(".config").join("piggy")))
}

/// Read and check the profile `name` (exit 3 for a name that is not a
/// plain word, a file that is missing or unreadable, or a profile that
/// does not parse; the message names the path tried).
pub(crate) fn load_profile(name: &str) -> Result<piggy::ca_profile::Profile, Failure> {
    let refuse = failure(Exit::Profile);
    let home = config_home().ok_or_else(|| {
        refuse("no config home: set PIGGY_CONFIG_HOME, XDG_CONFIG_HOME or HOME".into())
    })?;
    let path = piggy::ca_profile::profile_path(&home, name).map_err(|e| refuse(e.to_string()))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| refuse(format!("profile {name}: {}: {e}", path.display())))?;
    piggy::ca_profile::parse(&text)
        .map_err(|e| refuse(format!("profile {name} ({}): {e}", path.display())))
}

/// The root the profile's `attestation_root` names, read and checked to be
/// a PEM certificate (exit 3, the profile's, when it is missing or not
/// one: a root that cannot be read never falls back to the embedded one),
/// or `None` for the embedded Yubico root.
pub(crate) fn attestation_root_pem(
    issuer: &piggy::ca_profile::Issuer,
) -> Result<Option<Vec<u8>>, Failure> {
    let Some(path) = &issuer.attestation_root else {
        return Ok(None);
    };
    let refuse = failure(Exit::Profile);
    let pem = std::fs::read(path).map_err(|e| refuse(format!("attestation_root {path}: {e}")))?;
    openssl::x509::X509::from_pem(&pem).map_err(|e| {
        refuse(format!(
            "attestation_root {path} is not a PEM certificate: {e}"
        ))
    })?;
    Ok(Some(pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_needs_a_key_and_root_cert_a_profile() {
        assert!(CaCli::try_parse_from(["piggy ca"]).is_err());
        assert!(
            CaCli::try_parse_from(["piggy ca", "csr"]).is_err(),
            "--key is required"
        );
        let cli = CaCli::try_parse_from(["piggy ca", "csr", "--key", "id.pub"]).unwrap();
        match cli.cmd {
            CaCommand::Csr(args) => {
                assert_eq!(args.key.to_string_lossy(), "id.pub");
                assert_eq!(args.cn, csr::DEFAULT_CN);
                assert!(args.out.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert!(
            CaCli::try_parse_from(["piggy ca", "root-cert"]).is_err(),
            "--profile is required"
        );
        assert!(
            CaCli::try_parse_from(["piggy ca", "root-cert", "--profile", "x", "--slot", "82"])
                .is_err(),
            "the profile is the only source of the issuer: no slot flag"
        );
        let cli = CaCli::try_parse_from(["piggy ca", "root-cert", "--profile", "shithub"]).unwrap();
        match cli.cmd {
            CaCommand::RootCert(args) => {
                assert_eq!(args.profile, "shithub");
                assert!(args.out.is_none());
                assert!(args.act_out.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn leaf_csr_needs_a_key_path_and_a_cn() {
        assert!(CaCli::try_parse_from(["piggy ca", "leaf-csr"]).is_err());
        assert!(
            CaCli::try_parse_from(["piggy ca", "leaf-csr", "--cn", "github.com"]).is_err(),
            "--key-out is required"
        );
        assert!(
            CaCli::try_parse_from(["piggy ca", "leaf-csr", "--key-out", "leaf.key"]).is_err(),
            "--cn is required: a leaf CN is never defaulted"
        );
        let cli = CaCli::try_parse_from([
            "piggy ca",
            "leaf-csr",
            "--key-out",
            "leaf.key",
            "--cn",
            "github.com",
        ])
        .unwrap();
        match cli.cmd {
            CaCommand::LeafCsr(args) => {
                assert_eq!(args.key_out.to_string_lossy(), "leaf.key");
                assert_eq!(args.cn, "github.com");
                assert!(args.out.is_none());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_exit_table_is_the_fdrs() {
        assert_eq!(Exit::Refused as i32, 1);
        assert_eq!(Exit::Usage as i32, 2);
        assert_eq!(Exit::Profile as i32, 3);
        assert_eq!(Exit::Csr as i32, 4);
        assert_eq!(Exit::Names as i32, 5);
        assert_eq!(Exit::IssuerUnavailable as i32, 6);
        assert_eq!(Exit::RateLimited as i32, 7);
    }

    #[test]
    fn the_config_home_is_piggys_then_xdgs_then_the_users() {
        let s = |v: &str| Some(std::ffi::OsString::from(v));
        assert_eq!(
            config_home_from(s("/etc/piggy"), s("/x"), s("/h")),
            Some(PathBuf::from("/etc/piggy"))
        );
        assert_eq!(
            config_home_from(None, s("/x"), s("/h")),
            Some(PathBuf::from("/x/piggy"))
        );
        assert_eq!(
            config_home_from(s(""), None, s("/h")),
            Some(PathBuf::from("/h/.config/piggy")),
            "an empty variable is unset"
        );
        assert_eq!(config_home_from(None, None, None), None);
    }

    #[test]
    fn an_attestation_root_that_cannot_be_read_is_the_profiles_fault() {
        let issuer = |root: Option<&str>| piggy::ca_profile::Issuer {
            slot: Some("82".into()),
            guid: Some("0123456789abcdef0123456789abcdef".into()),
            holder_key: None,
            issuer_cert: None,
            attestation_root: root.map(str::to_owned),
        };
        assert_eq!(attestation_root_pem(&issuer(None)).unwrap(), None);
        let missing = attestation_root_pem(&issuer(Some("/nonexistent/f9.pem"))).unwrap_err();
        assert_eq!(missing.exit, Exit::Profile);
        assert!(
            missing.message.contains("/nonexistent/f9.pem"),
            "{}",
            missing.message
        );

        let dir = std::env::temp_dir().join(format!("piggy-ca-root-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let not_pem = dir.join("not.pem");
        std::fs::write(&not_pem, b"hello").unwrap();
        let bad = attestation_root_pem(&issuer(Some(not_pem.to_str().unwrap()))).unwrap_err();
        assert_eq!(bad.exit, Exit::Profile);
        assert!(
            bad.message.contains("not a PEM certificate"),
            "{}",
            bad.message
        );
        let good = dir.join("root.pem");
        std::fs::write(&good, piggy::cmd::tool::YUBICO_PIV_ROOT_CA_PEM).unwrap();
        assert!(
            attestation_root_pem(&issuer(Some(good.to_str().unwrap())))
                .unwrap()
                .is_some()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bad_profile_name_is_exit_3() {
        // No directory is read for a name that cannot be a profile's; a
        // test environment with no HOME fails one step earlier, on the
        // config home, with the same exit.
        let failure = load_profile("../x").unwrap_err();
        assert_eq!(failure.exit, Exit::Profile);
        assert!(
            failure.message.contains("../x") || failure.message.contains("no config home"),
            "{}",
            failure.message
        );
    }
}
