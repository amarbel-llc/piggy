//! `piggy ca sign --profile NAME` and `piggy ca issue --profile NAME`: an
//! intermediate or a leaf certificate for the PKCS#10 request on stdin,
//! signed by the card-held root a profile names (FDR 0007 phase (ii),
//! piggy#391, "The issuance verbs").
//!
//! The decision is `piggy::ca_issue::issue`, which checks the request
//! against the profile and calls the signer last. This module is what
//! surrounds it: the profile, the request on stdin, the card, the
//! per-profile rate limit, the audit line and the PEM out. Every refusal
//! before the signer issues nothing and costs no PIN prompt; the issuer's
//! certificate is read and its key proven the card's (no PIN) first.
//!
//! State (the rate-limit stamp per profile and the audit file) lives under
//! `$PIGGY_CA_STATE`, else `$XDG_STATE_HOME/piggy/ca`, else
//! `~/.local/state/piggy/ca`. The stamp is written after a certificate is
//! issued, so a refused or failed run does not block the next; two runs
//! racing inside one window can both pass the check (the limit is a guard
//! against a runaway timer, not a lock).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake2::{Blake2b, Digest, digest::consts::U32};
use clap::Args;
use piggy::ca_issue::{self, ExitCode, Inputs, Refusal, Verb};
use piggy_markl::{FormatId, Id, PurposeId};

use super::card_signer::CardSigner;
use super::certificate_act::{self, CertifiedAs};
use super::root_cert::{SERIAL_BYTES, pem_certificate};
use super::{Exit, Failure, failure};

#[derive(Args, Debug)]
pub struct IssuanceArgs {
    /// The profile, `ca-profiles/NAME.toml` under piggy's config home:
    /// an intermediate profile for `sign`, a leaf profile for `issue`.
    #[arg(long, value_name = "NAME")]
    pub profile: String,
    /// Write the PEM here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Where the certificate act (RFC 0012 §3.2) goes: by default `--out`'s
    /// path plus `.act`, required when the PEM goes to stdout. Never
    /// written over an existing file.
    #[arg(long, value_name = "FILE")]
    pub act_out: Option<PathBuf>,
}

/// `$PIGGY_CA_STATE`, else `$XDG_STATE_HOME/piggy/ca`, else
/// `~/.local/state/piggy/ca`; `None` when none can be formed.
pub(crate) fn state_dir() -> Option<PathBuf> {
    state_dir_from(
        std::env::var_os("PIGGY_CA_STATE"),
        std::env::var_os("XDG_STATE_HOME"),
        std::env::var_os("HOME"),
    )
}

fn state_dir_from(
    ca_state: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let set = |v: Option<std::ffi::OsString>| v.filter(|s| !s.is_empty()).map(PathBuf::from);
    set(ca_state)
        .or_else(|| set(xdg).map(|d| d.join("piggy").join("ca")))
        .or_else(|| set(home).map(|h| h.join(".local/state/piggy/ca")))
}

/// When the profile last issued, from its stamp file (Unix seconds). A
/// missing file is `None`; one that does not hold a number is an error,
/// not "never": a damaged stamp must not lift the limit.
pub(crate) fn read_stamp(path: &Path) -> Result<Option<Duration>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .map(|s| Some(Duration::from_secs(s)))
            .map_err(|e| format!("rate-limit stamp {}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("rate-limit stamp {}: {e}", path.display())),
    }
}

/// Record `now` as the profile's last issuance, through a rename so a
/// crash leaves the old stamp or the new one, never half of one.
pub(crate) fn write_stamp(path: &Path, now: Duration) -> Result<(), String> {
    let dir = path.parent().ok_or("stamp path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}\n", now.as_secs()))
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// One line appended to the audit file.
pub(crate) fn append_audit(path: &Path, line: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("audit path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| format!("write {}: {e}", path.display()))
}

/// The request as DER, from PEM (`CERTIFICATE REQUEST`) or raw DER bytes.
pub(crate) fn csr_der_from(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.windows(10).any(|w| w == b"-----BEGIN") {
        openssl::x509::X509Req::from_pem(input)
            .and_then(|req| req.to_der())
            .map_err(|e| format!("the request is not a PEM PKCS#10: {e}"))
    } else if input.is_empty() {
        Err("no request on stdin".into())
    } else {
        Ok(input.to_vec())
    }
}

/// A `piggy-record-digest-v1` markl id (blake2b256) over `bytes`, the form
/// the audit line carries for the certificate and the request.
pub(crate) fn record_digest(bytes: &[u8]) -> String {
    Id::new(
        Some(PurposeId::PiggyRecordDigestV1),
        FormatId::Blake2b256,
        Blake2b::<U32>::digest(bytes).to_vec(),
    )
    .expect("a 32-byte digest under its own purpose")
    .to_wire()
}

fn exit_of(code: ExitCode) -> Exit {
    match code {
        ExitCode::Other => Exit::Refused,
        ExitCode::Usage => Exit::Usage,
        ExitCode::ProfileUnknown => Exit::Profile,
        ExitCode::CsrMalformed => Exit::Csr,
        ExitCode::NamesOutsideProfile => Exit::Names,
        ExitCode::IssuerUnavailable => Exit::IssuerUnavailable,
        ExitCode::RateLimited => Exit::RateLimited,
    }
}

fn refused(refusal: Refusal) -> Failure {
    Failure {
        exit: exit_of(refusal.exit_code()),
        message: refusal.to_string(),
    }
}

fn now() -> Result<Duration, Failure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| failure(Exit::Refused)(format!("the clock is before 1970: {e}")))
}

pub(crate) fn execute(verb: Verb, args: IssuanceArgs) -> Result<(), Failure> {
    let profile = super::load_profile(&args.profile)?;
    // The profile's kind is the verb's before the clock, the state, stdin
    // or the card: a wrong-kind profile is the profile's fault (exit 3),
    // as `root-cert` answers a profile that is not a root.
    if profile.kind != verb.kind() {
        return Err(refused(Refusal::WrongKind {
            verb,
            profile: profile.kind,
        }));
    }
    let now = now()?;
    let state = state_dir().ok_or_else(|| {
        failure(Exit::Refused)(
            "no state directory: set PIGGY_CA_STATE, XDG_STATE_HOME or HOME".into(),
        )
    })?;
    let stamp = state.join("rate").join(&args.profile);
    let last = read_stamp(&stamp).map_err(failure(Exit::Refused))?;
    ca_issue::check_rate(last, now).map_err(refused)?;
    let attestation_root = super::attestation_root_pem(&profile.issuer)?;

    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(1 << 20)
        .read_to_end(&mut input)
        .map_err(|e| failure(Exit::Csr)(format!("read the request from stdin: {e}")))?;
    let csr_der = csr_der_from(&input).map_err(failure(Exit::Csr))?;

    let mut random = [0u8; SERIAL_BYTES];
    openssl::rand::rand_bytes(&mut random)
        .map_err(|e| failure(Exit::Refused)(format!("random serial: {e}")))?;
    random[0] &= 0x7F;

    // The act names the certified key, so its type is read now; a request
    // that does not parse is refused here with the exit `issue` would give.
    let csr_algorithm = piggy_piv::csr_check::parse_csr(&csr_der)
        .map_err(|e| refused(Refusal::Csr(e)))?
        .algorithm;
    // A P-384 request gets no act: refused with no card touched.
    certificate_act::check_certified_key(csr_algorithm)?;
    // The act's path is judged before the card is looked for: a taken path
    // or a missing directory is refused with nothing else touched.
    let act_out = certificate_act::act_out_path(args.out.as_deref(), args.act_out.clone())?;
    certificate_act::precheck(&act_out, args.out.as_deref())?;
    let subject = profile.principal_for(&args.profile);

    let mut signer = CardSigner::open(&profile.issuer)?;
    signer.verify_on_card(attestation_root.as_deref())?;
    let issuer_cert = signer.cert_der()?.to_vec();
    // Everything the act needs from the card and the agent is settled
    // before the first PIN prompt, so a missing agent never costs a card
    // signature.
    let operator = certificate_act::preflight(&signer, csr_algorithm, act_out)?;
    let describing = format!(
        "{} certificate under profile {} for {} (serial {})",
        verb.article_kind(),
        args.profile,
        profile.names.join(", "),
        hex::encode(random)
    );
    eprintln!(
        "piggy ca: card {} slot {:02X} signs {describing}; two PIN prompts and touches: the certificate's, then the certificate act's (slot 9C, through the agent)",
        signer.card_label(),
        signer.slot()
    );

    let inputs = Inputs {
        verb,
        profile: &profile,
        csr_der: &csr_der,
        issuer_cert_der: &issuer_cert,
        now,
        serial: &random,
    };
    let issued = match ca_issue::issue(&inputs, |digest| signer.sign_digest(digest, &describing)) {
        Ok(issued) => issued,
        Err(refusal) => {
            // A card or operator refusal carries the card's own words.
            return Err(match (&refusal, signer.take_sign_failure()) {
                (Refusal::IssuerUnavailable(_), Some(card)) => card,
                _ => refused(refusal),
            });
        }
    };

    // The act names the signed DER, so it comes after the signature; the
    // certificate is written only once the act is sealed and on disk.
    let act = certificate_act::plan(
        &issued.cert_der,
        &subject,
        CertifiedAs::Link,
        &operator.key,
        now.as_secs(),
        &describing,
    )?;
    let act_digest = certificate_act::seal_and_write(&act, &operator)?;
    eprintln!(
        "piggy ca: the certificate act {act_digest} is written to {}",
        operator.act_out.display()
    );

    let pem = pem_certificate(&issued.cert_der);
    match &args.out {
        Some(path) => std::fs::write(path, &pem)
            .map_err(|e| failure(Exit::Refused)(format!("write {}: {e}", path.display())))?,
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(pem.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| failure(Exit::Refused)(format!("write stdout: {e}")))?;
        }
    }

    // The certificate is out: the stamp and the audit line are the record
    // of it. Failing to write them is reported, but the exit stays 0 only
    // if both land; a certificate nobody recorded is exit 1.
    let line = ca_issue::audit_line(
        &args.profile,
        &random,
        &record_digest(&issued.cert_der),
        &record_digest(&csr_der),
        Some(act_digest.as_str()),
        issued.requested_not_after,
    );
    let recorded =
        write_stamp(&stamp, now).and_then(|()| append_audit(&state.join("audit"), &line));
    recorded.map_err(|e| {
        failure(Exit::Refused)(format!(
            "the certificate was issued and written, but not recorded ({e}); the rate limit is not armed"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn s(v: &str) -> Option<std::ffi::OsString> {
        Some(std::ffi::OsString::from(v))
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("piggy-ca-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_state_dir_is_the_cas_then_xdgs_then_the_users() {
        assert_eq!(
            state_dir_from(s("/var/ca"), s("/x"), s("/h")),
            Some(PathBuf::from("/var/ca"))
        );
        assert_eq!(
            state_dir_from(None, s("/x"), s("/h")),
            Some(PathBuf::from("/x/piggy/ca"))
        );
        assert_eq!(
            state_dir_from(s(""), None, s("/h")),
            Some(PathBuf::from("/h/.local/state/piggy/ca"))
        );
        assert_eq!(state_dir_from(None, None, None), None);
    }

    #[test]
    fn a_stamp_round_trips_and_a_damaged_one_is_not_never() {
        let dir = tmp("stamp");
        let path = dir.join("rate").join("leaf");
        assert_eq!(read_stamp(&path).unwrap(), None, "no file: never issued");
        write_stamp(&path, Duration::from_secs(1_800_000_123)).unwrap();
        assert_eq!(
            read_stamp(&path).unwrap(),
            Some(Duration::from_secs(1_800_000_123))
        );
        std::fs::write(&path, "yesterday\n").unwrap();
        assert!(read_stamp(&path).is_err(), "damaged is an error");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_audit_file_grows_one_line_per_issuance() {
        let dir = tmp("audit");
        let path = dir.join("audit");
        append_audit(&path, "first").unwrap();
        append_audit(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_request_is_read_as_pem_or_der_and_nothing_is_not_a_request() {
        let key = openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap();
        let pkey = openssl::pkey::PKey::from_ec_key(key).unwrap();
        let mut builder = openssl::x509::X509ReqBuilder::new().unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let req = builder.build();
        let der = req.to_der().unwrap();
        assert_eq!(csr_der_from(&req.to_pem().unwrap()).unwrap(), der);
        assert_eq!(csr_der_from(&der).unwrap(), der);
        assert!(csr_der_from(b"").is_err());
        assert!(csr_der_from(b"-----BEGIN CERTIFICATE REQUEST-----\nnope\n").is_err());
    }

    #[test]
    fn the_digest_is_a_blake2b256_record_digest() {
        let digest = record_digest(b"x");
        assert!(
            digest.starts_with("piggy-record-digest-v1@blake2b256-"),
            "{digest}"
        );
        assert_ne!(digest, record_digest(b"y"));
    }

    #[test]
    fn every_refusal_has_the_fdrs_exit() {
        assert_eq!(
            exit_of(
                Refusal::RateLimited {
                    retry_after: Duration::ZERO
                }
                .exit_code()
            ),
            Exit::RateLimited
        );
        assert_eq!(exit_of(Refusal::KeyTypeNotInProfile.exit_code()), Exit::Csr);
        assert_eq!(
            exit_of(
                Refusal::WrongKind {
                    verb: Verb::Sign,
                    profile: piggy::ca_profile::Kind::Leaf
                }
                .exit_code()
            ),
            Exit::Profile,
            "a profile of another kind is the profile's fault, as root-cert's"
        );
        assert_eq!(
            exit_of(Refusal::IssuerUnavailable(String::new()).exit_code()),
            Exit::IssuerUnavailable
        );
        assert_eq!(
            exit_of(Refusal::Other(String::new()).exit_code()),
            Exit::Refused
        );
    }

    #[test]
    fn the_verbs_need_a_profile_and_no_slot() {
        #[derive(Parser, Debug)]
        struct Cli {
            #[command(flatten)]
            args: IssuanceArgs,
        }
        assert!(Cli::try_parse_from(["x"]).is_err(), "--profile is required");
        assert!(
            Cli::try_parse_from(["x", "--profile", "p", "--slot", "82"]).is_err(),
            "the profile is the only source of the issuer"
        );
        let cli = Cli::try_parse_from(["x", "--profile", "shithub-leaf"]).unwrap();
        assert_eq!(cli.args.profile, "shithub-leaf");
        assert!(cli.args.out.is_none());
    }
}
