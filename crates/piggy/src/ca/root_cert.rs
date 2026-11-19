//! `piggy ca root-cert --profile NAME`: the self-signed root certificate of
//! a card-held CA key (FDR 0007 phase (ii), piggy#391).
//!
//! The profile is the only input: its `kind` must be `root`, its
//! `common_name` and `names` become the subject and the name constraints,
//! its `lifetime_hours` and `not_before_skew_minutes` the validity, and its
//! `[issuer]` names the card and the slot (82). Everything else in the
//! certificate is the root profile of `piggy_piv::x509_profile`. The slot's
//! key is proven to be the card's (its attestation verifies) before the
//! one PIN prompt, which describes what is being certified.
//!
//! Every root signature also leaves a `piggy-certificate-v1` act in the
//! ledger (RFC 0012 §3.2, `super::certificate_act`): a second PIN and
//! touch, through the agent, under the `certificate` banner, after the
//! certificate is signed and before anything is written. Only the PEM goes
//! to stdout; the act goes to `--act-out` (else the PEM's path plus
//! `.act`); every notice goes to stderr. Writing the certificate back into
//! the slot is a separate, deliberate step (`piggy tool write-cert 82`).

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;
use piggy::ca_profile::{Kind, Profile};
use piggy_piv::PivAlgorithm;
use piggy_piv::x509_profile::{CertValidity, build_root_cert};

use super::card_signer::CardSigner;
use super::certificate_act::{self, CertifiedAs};
use super::{Exit, Failure, failure};

/// The serial's size: 128 random bits, well over the profile's 64-bit
/// floor and under RFC 5280's 20 octets once made positive.
pub(crate) const SERIAL_BYTES: usize = 16;

#[derive(Args, Debug)]
pub struct RootCertArgs {
    /// The root profile, `ca-profiles/NAME.toml` under piggy's config home.
    #[arg(long, value_name = "NAME")]
    pub profile: String,
    /// Write the PEM here instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Write the sealed piggy-certificate-v1 act here (RFC 0012 §3.2);
    /// default --out's path plus `.act`, required when the PEM goes to
    /// stdout. Never written over an existing file.
    #[arg(long, value_name = "FILE")]
    pub act_out: Option<PathBuf>,
}

/// What the profile and the clock decide about the certificate, before
/// any card is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootPlan {
    pub common_name: String,
    pub permitted_dns: Vec<String>,
    pub validity: CertValidity,
    pub serial: Vec<u8>,
}

impl RootPlan {
    /// One line naming the certificate, for the PIN prompt and the notice.
    pub(crate) fn describe(&self) -> String {
        format!(
            "the root certificate CN={} for {} (valid {} days, serial {})",
            self.common_name,
            self.permitted_dns.join(", "),
            (self.validity.not_after.as_secs() - self.validity.not_before.as_secs()) / 86_400,
            hex::encode(&self.serial)
        )
    }
}

/// The plan a root profile makes at `now` with `random` as the serial's
/// bytes: `notBefore` is `now` minus the profile's skew, `notAfter` is
/// `now` plus its lifetime, and the serial is `random` made positive
/// (top bit cleared). A profile of another kind is refused: the verb
/// certifies roots only.
pub(crate) fn plan_root(
    profile: &Profile,
    now: Duration,
    random: [u8; SERIAL_BYTES],
) -> Result<RootPlan, Failure> {
    if profile.kind != Kind::Root {
        return Err(failure(Exit::Profile)(format!(
            "the profile is a {} profile; root-cert needs a root profile",
            kind_name(profile.kind)
        )));
    }
    let common_name = profile
        .common_name
        .clone()
        .ok_or_else(|| failure(Exit::Profile)("a root profile needs a common_name".into()))?;
    let skew = Duration::from_secs(profile.not_before_skew_minutes * 60);
    let lifetime = Duration::from_secs(profile.lifetime_hours * 3600);
    let mut serial = random.to_vec();
    serial[0] &= 0x7F;
    Ok(RootPlan {
        common_name,
        permitted_dns: profile.names.clone(),
        validity: CertValidity {
            not_before: now.saturating_sub(skew),
            not_after: now + lifetime,
        },
        serial,
    })
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Root => "root",
        Kind::Intermediate => "intermediate",
        Kind::Leaf => "leaf",
    }
}

/// Build the root certificate over `point` from `plan`, signed by
/// `sign_digest` (the card, or a software key in tests). DER out.
pub(crate) fn issue_root(
    plan: &RootPlan,
    point: &[u8],
    algorithm: PivAlgorithm,
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, piggy_piv::PivError>,
) -> Result<Vec<u8>, piggy_piv::PivError> {
    build_root_cert(
        point,
        algorithm,
        &plan.common_name,
        &plan.permitted_dns,
        plan.validity,
        &plan.serial,
        sign_digest,
    )
}

/// PEM, 64 columns, as `openssl x509` reads it.
pub(crate) fn pem_certificate(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

pub(crate) fn execute(args: RootCertArgs) -> Result<(), Failure> {
    let profile = super::load_profile(&args.profile)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| failure(Exit::Refused)(format!("the clock is before 1970: {e}")))?;
    let mut random = [0u8; SERIAL_BYTES];
    openssl::rand::rand_bytes(&mut random)
        .map_err(|e| failure(Exit::Refused)(format!("random serial: {e}")))?;
    let plan = plan_root(&profile, now, random)?;
    // The profile's half is checked whole before the card is touched.
    let attestation_root = super::attestation_root_pem(&profile.issuer)?;
    let act_out = certificate_act::act_out_path(args.out.as_deref(), args.act_out.clone())?;
    // The paths are judged before the card is looked for: a taken act path
    // or a missing directory is refused with nothing else touched.
    certificate_act::precheck(&act_out, args.out.as_deref())?;
    let subject = profile.principal_for(&args.profile);

    let mut signer = CardSigner::open(&profile.issuer)?;
    // A key the act cannot name is refused on its type alone, before the
    // attestation is read.
    certificate_act::check_certified_key(signer.algorithm())?;
    signer.verify_on_card(attestation_root.as_deref())?;
    // Everything the act needs from the card and the agent is settled
    // before the first PIN prompt, so a missing agent never costs a card
    // signature.
    let operator = certificate_act::preflight(&signer, signer.algorithm(), act_out)?;
    let describing = plan.describe();
    eprintln!(
        "piggy ca root-cert: card {} slot {:02X} signs {describing}; two PIN prompts and touches: the certificate's, then the certificate act's (slot 9C, through the agent)",
        signer.card_label(),
        signer.slot()
    );
    let point = signer.pubkey_point().to_vec();
    let algorithm = signer.algorithm();
    let der = match issue_root(&plan, &point, algorithm, |digest| {
        signer.sign_digest(digest, &describing)
    }) {
        Ok(der) => der,
        Err(e) => {
            return Err(signer.take_sign_failure().unwrap_or_else(|| {
                failure(Exit::Refused)(format!("build the root certificate: {e}"))
            }));
        }
    };

    // The act names the signed DER, so it comes after the signature; the
    // certificate is written only once the act is sealed and on disk.
    let act = certificate_act::plan(
        &der,
        &subject,
        CertifiedAs::Root,
        &operator.key,
        now.as_secs(),
        &describing,
    )?;
    let act_digest = certificate_act::seal_and_write(&act, &operator)?;
    eprintln!(
        "piggy ca root-cert: the certificate act {act_digest} is written to {}",
        operator.act_out.display()
    );

    let pem = pem_certificate(&der);
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
        "piggy ca root-cert: signed; the slot still holds what it held: write the certificate back with `piggy tool write-cert {:02x}` when it is the one to serve",
        signer.slot()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "0123456789abcdef0123456789abcdef";

    fn root_profile(extra: &str) -> Profile {
        piggy::ca_profile::parse(&format!(
            "kind = \"root\"\ncommon_name = \"shithub root\"\nnames = [\"github.com\", \"api.github.com\"]\nlifetime_hours = 87600\n{extra}\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        ))
        .unwrap()
    }

    const NOW: Duration = Duration::from_secs(1_800_000_000);

    #[test]
    fn the_plan_takes_everything_from_the_profile_and_the_clock() {
        let plan = plan_root(&root_profile(""), NOW, [0xFF; SERIAL_BYTES]).unwrap();
        assert_eq!(plan.common_name, "shithub root");
        assert_eq!(plan.permitted_dns, ["github.com", "api.github.com"]);
        assert_eq!(
            plan.validity.not_before,
            NOW - Duration::from_secs(5 * 60),
            "5 minutes of skew by default"
        );
        assert_eq!(
            plan.validity.not_after,
            NOW + Duration::from_secs(87600 * 3600)
        );
        assert_eq!(plan.serial.len(), SERIAL_BYTES);
        assert_eq!(
            plan.serial[0], 0x7F,
            "the top bit is cleared: a positive INTEGER"
        );
        assert_eq!(&plan.serial[1..], &[0xFF; SERIAL_BYTES - 1]);

        let skewed = plan_root(
            &root_profile("not_before_skew_minutes = 0"),
            NOW,
            [1; SERIAL_BYTES],
        )
        .unwrap();
        assert_eq!(skewed.validity.not_before, NOW);
        assert!(plan.describe().contains("CN=shithub root"));
        assert!(plan.describe().contains("github.com, api.github.com"));
        assert!(plan.describe().contains("3650 days"));
    }

    #[test]
    fn only_a_root_profile_is_certified() {
        let leaf = piggy::ca_profile::parse(&format!(
            "kind = \"leaf\"\nnames = [\"github.com\"]\nlifetime_hours = 720\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        ))
        .unwrap();
        let refusal = plan_root(&leaf, NOW, [1; SERIAL_BYTES]).unwrap_err();
        assert_eq!(refusal.exit, Exit::Profile);
        assert!(
            refusal.message.contains("leaf profile"),
            "{}",
            refusal.message
        );
    }

    /// The whole verb off the card: a software P-256 key stands in for the
    /// slot, signs the digest the builder hands it the way the card does
    /// (DER ECDSA over the prehash), and openssl reads back a self-signed
    /// CA certificate with the plan's subject, validity and serial.
    #[test]
    fn a_root_signed_by_a_software_key_verifies_and_carries_the_plan() {
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        use openssl::ecdsa::EcdsaSig;
        use openssl::nid::Nid;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let plan = plan_root(&root_profile(""), NOW, [0x42; SERIAL_BYTES]).unwrap();

        let der = issue_root(&plan, &point, PivAlgorithm::EcP256, |digest| {
            Ok(EcdsaSig::sign(digest, &key).unwrap().to_der().unwrap())
        })
        .unwrap();

        let cert = openssl::x509::X509::from_der(&der).unwrap();
        assert!(
            cert.verify(&cert.public_key().unwrap()).unwrap(),
            "self-signed"
        );
        let cn = cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string();
        assert_eq!(cn, "shithub root");
        assert_eq!(
            cert.subject_name().to_der().unwrap(),
            cert.issuer_name().to_der().unwrap()
        );
        assert_eq!(
            cert.serial_number().to_bn().unwrap().to_vec(),
            plan.serial,
            "the serial is the plan's, positive as given"
        );
        let not_before =
            openssl::asn1::Asn1Time::from_unix(plan.validity.not_before.as_secs() as i64).unwrap();
        let not_after =
            openssl::asn1::Asn1Time::from_unix(plan.validity.not_after.as_secs() as i64).unwrap();
        assert_eq!(
            cert.not_before().compare(&not_before).unwrap(),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            cert.not_after().compare(&not_after).unwrap(),
            std::cmp::Ordering::Equal
        );

        // And the PEM round-trips through openssl's reader.
        let pem = pem_certificate(&der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(
            openssl::x509::X509::from_pem(pem.as_bytes())
                .unwrap()
                .to_der()
                .unwrap(),
            der
        );
    }
}
