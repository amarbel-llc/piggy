//! The decision core of `piggy ca sign` and `piggy ca issue` (FDR 0007,
//! "The issuance verbs", steps 1 to 4 and the refusal table).
//!
//! Pure: the profile, the request, the issuer's certificate, the clock and
//! the serial come in as values, and the issuer's signature comes in as a
//! closure (a card through `PinSession`, wired by the verb). Reading the
//! profile file, the rate-limit state, the audit file and the card are the
//! verb's business, so every refusal below can be tested without any of
//! them.
//!
//! A refusal issues nothing: [`issue`] returns the certificate or a
//! [`Refusal`], never both, and calls the signer only after every check
//! has passed.

use std::cell::Cell;
use std::time::Duration;

use piggy_piv::PivError;
use piggy_piv::csr_check::{self, CsrRefusal};
use piggy_piv::x509_profile::{self, CertValidity, MIN_SERIAL_BYTES};

use crate::ca_profile::{Kind, Profile};

/// One issuance per profile per this window (FDR 0007: a runaway timer
/// cannot mint a leaf stream).
pub const RATE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// Which verb is asking. `sign` issues an intermediate, `issue` a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Sign,
    Issue,
}

impl Verb {
    pub fn kind(self) -> Kind {
        match self {
            Self::Sign => Kind::Intermediate,
            Self::Issue => Kind::Leaf,
        }
    }

    /// The kind this verb issues, with its article: "an intermediate", "a
    /// leaf" (the words the PIN prompt, the notice and the act's
    /// description carry).
    pub fn article_kind(self) -> &'static str {
        match self {
            Self::Sign => "an intermediate",
            Self::Issue => "a leaf",
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Issue => "issue",
        }
    }
}

/// The verbs' exit codes (FDR 0007), so a renewal timer can tell the
/// refusals apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Other = 1,
    Usage = 2,
    ProfileUnknown = 3,
    CsrMalformed = 4,
    NamesOutsideProfile = 5,
    IssuerUnavailable = 6,
    RateLimited = 7,
}

/// Why nothing was issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The profile's kind is not the one this verb issues.
    WrongKind { verb: Verb, profile: Kind },
    /// The request failed parsing, the key check or the name check.
    Csr(CsrRefusal),
    /// The request's key type is valid but this profile does not accept it.
    KeyTypeNotInProfile,
    /// The profile was used less than [`RATE_WINDOW`] ago.
    RateLimited { retry_after: Duration },
    /// The profile names what the issuer certificate's name constraints do
    /// not admit: the profile is at fault, not the request (exit 3).
    NamesOutsideIssuer(String),
    /// The issuer's key could not sign (card absent, PIN or touch refused).
    IssuerUnavailable(String),
    /// Anything else: a serial that is too short, an issuer certificate
    /// that is not a CA, an empty validity.
    Other(String),
}

impl Refusal {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            // The profile is not the verb's: exit 3, as `root-cert` answers
            // a profile that is not a root (FDR 0007 exit table).
            Self::WrongKind { .. } | Self::NamesOutsideIssuer(_) => ExitCode::ProfileUnknown,
            Self::Csr(CsrRefusal::Names(_)) => ExitCode::NamesOutsideProfile,
            Self::Csr(_) | Self::KeyTypeNotInProfile => ExitCode::CsrMalformed,
            Self::RateLimited { .. } => ExitCode::RateLimited,
            Self::IssuerUnavailable(_) => ExitCode::IssuerUnavailable,
            Self::Other(_) => ExitCode::Other,
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongKind { verb, profile } => write!(
                f,
                "`piggy ca {}` issues {} certificate; this profile is {}",
                verb.word(),
                verb.article_kind(),
                format!("{profile:?}").to_lowercase()
            ),
            Self::Csr(why) => write!(f, "{why}"),
            Self::NamesOutsideIssuer(why) => write!(
                f,
                "the profile names what its issuer's name constraints do not admit: {why}"
            ),
            Self::KeyTypeNotInProfile => f.write_str("the profile does not accept this key type"),
            Self::RateLimited { retry_after } => write!(
                f,
                "rate limited: this profile issued a certificate less than {} minutes ago; \
                 try again in {} seconds",
                RATE_WINDOW.as_secs() / 60,
                retry_after.as_secs() + 1
            ),
            Self::IssuerUnavailable(why) => write!(f, "the issuer key is unavailable: {why}"),
            Self::Other(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether a profile last used at `last` (since the Unix epoch) may issue
/// again at `now`. A `last` in the future (a clock set back) counts as
/// just used: the refusal is the safe side of a clock step.
pub fn check_rate(last: Option<Duration>, now: Duration) -> Result<(), Refusal> {
    let Some(last) = last else { return Ok(()) };
    let since = now.saturating_sub(last);
    if now >= last && since >= RATE_WINDOW {
        return Ok(());
    }
    Err(Refusal::RateLimited {
        retry_after: RATE_WINDOW.saturating_sub(since),
    })
}

/// What `issue` is given.
pub struct Inputs<'a> {
    pub verb: Verb,
    pub profile: &'a Profile,
    pub csr_der: &'a [u8],
    /// The issuer's certificate (the root, or in a later phase the
    /// intermediate), DER.
    pub issuer_cert_der: &'a [u8],
    /// Now, since the Unix epoch.
    pub now: Duration,
    /// Random, at least 64 bits (the caller draws it).
    pub serial: &'a [u8],
}

/// A certificate that was issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub cert_der: Vec<u8>,
    /// `notAfter` the certificate asked for, before any clamping to the
    /// issuer's; the certificate itself holds the clamped value.
    pub requested_not_after: Duration,
}

/// How the issuer's key signs: a card's prehash signer is handed the digest
/// of the DER TBSCertificate; an agent (the holder's, FDR 0007 phase
/// (iii-b)) is handed the TBSCertificate and hashes it itself. Either runs
/// last and at most once.
pub enum Signer<'a> {
    Digest(Box<dyn FnOnce(&[u8]) -> Result<Vec<u8>, PivError> + 'a>),
    Tbs(Box<dyn FnOnce(&[u8]) -> Result<Vec<u8>, PivError> + 'a>),
}

/// Steps 1 to 4 of the verbs: check the request against the profile, then
/// build the certificate and have `sign_digest` sign it. `sign_digest`
/// runs last and at most once; an `Err` from it is the issuer being
/// unavailable, exit 6.
pub fn issue(
    inputs: &Inputs<'_>,
    sign_digest: impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError>,
) -> Result<Issued, Refusal> {
    issue_with(inputs, Signer::Digest(Box::new(sign_digest)))
}

/// [`issue`] with either kind of [`Signer`]. An intermediate is signed on
/// the card only (a prehash signer): a `Tbs` signer for one is refused.
pub fn issue_with(inputs: &Inputs<'_>, signer: Signer<'_>) -> Result<Issued, Refusal> {
    let profile = inputs.profile;
    if profile.kind != inputs.verb.kind() {
        return Err(Refusal::WrongKind {
            verb: inputs.verb,
            profile: profile.kind,
        });
    }
    if inputs.serial.len() < MIN_SERIAL_BYTES {
        return Err(Refusal::Other(format!(
            "the serial must be at least {MIN_SERIAL_BYTES} bytes"
        )));
    }
    check_issuer_admits(profile, inputs.issuer_cert_der)?;

    let csr = csr_check::parse_csr(inputs.csr_der).map_err(Refusal::Csr)?;
    if !profile.accepts(csr.algorithm) {
        return Err(Refusal::KeyTypeNotInProfile);
    }
    match profile.kind {
        Kind::Leaf => csr_check::check_leaf_names(&profile.names, &csr),
        _ => {
            let cn = profile.common_name.as_deref().unwrap_or_default();
            csr_check::check_intermediate_name(cn, &csr)
        }
    }
    .map_err(Refusal::Csr)?;

    let validity = CertValidity {
        not_before: inputs
            .now
            .saturating_sub(Duration::from_secs(profile.not_before_skew_minutes * 60)),
        not_after: inputs.now + Duration::from_secs(profile.lifetime_hours * 3600),
    };

    // Told apart from a builder error: the signer failing is the issuer's
    // key (the card, the holder), not a bad input.
    let signer_failed = Cell::new(false);
    let signer_error = Cell::new(None::<String>);
    let track = |r: Result<Vec<u8>, PivError>| {
        r.inspect_err(|e| {
            signer_failed.set(true);
            signer_error.set(Some(e.to_string()));
        })
    };

    let built = match (profile.kind, signer) {
        (Kind::Leaf, Signer::Digest(sign)) => x509_profile::build_leaf_cert(
            &csr.pubkey_point,
            csr.algorithm,
            &profile.names,
            inputs.issuer_cert_der,
            validity,
            inputs.serial,
            |digest| track(sign(digest)),
        ),
        (Kind::Leaf, Signer::Tbs(sign)) => x509_profile::build_leaf_cert_over_tbs(
            &csr.pubkey_point,
            csr.algorithm,
            &profile.names,
            inputs.issuer_cert_der,
            validity,
            inputs.serial,
            |tbs| track(sign(tbs)),
        ),
        (_, Signer::Digest(sign)) => x509_profile::build_intermediate_cert(
            &csr.pubkey_point,
            csr.algorithm,
            profile.common_name.as_deref().unwrap_or_default(),
            &profile.names,
            inputs.issuer_cert_der,
            validity,
            inputs.serial,
            |digest| track(sign(digest)),
        ),
        (_, Signer::Tbs(_)) => Err(PivError::Other(
            "an intermediate is signed on the card, never through an agent".into(),
        )),
    };
    match built {
        Ok(cert_der) => Ok(Issued {
            cert_der,
            requested_not_after: validity.not_after,
        }),
        Err(_) if signer_failed.get() => Err(Refusal::IssuerUnavailable(
            signer_error.take().unwrap_or_default(),
        )),
        Err(e) => Err(Refusal::Other(e.to_string())),
    }
}

/// Whether the issuer certificate's name constraints admit every name the
/// profile would certify (the leaf's SAN set, or the names an intermediate
/// would constrain to). A profile that names more than its issuer may
/// certify would yield a certificate every verifier rejects, so it is
/// refused as the profile's fault (exit 3) before anything is signed. The
/// verbs ask this before the request is read; `issue` asks it again, so
/// the pure core never signs past it.
pub fn check_issuer_admits(profile: &Profile, issuer_cert_der: &[u8]) -> Result<(), Refusal> {
    let refused = piggy_piv::x509_verify::dns_names_refused_by(issuer_cert_der, &profile.names)
        .map_err(|e| Refusal::Other(format!("the issuer certificate: {e}")))?;
    if refused.is_empty() {
        Ok(())
    } else {
        Err(Refusal::NamesOutsideIssuer(refused.join("; ")))
    }
}

/// The one audit line per issuance (FDR 0007 step 6): profile, serial,
/// the issued certificate's and the request's digests, and `notAfter`.
/// The digests are the caller's markl-id strings; nothing here hashes.
/// One line, `key=value` pairs, no free text from the request.
pub fn audit_line(
    profile_name: &str,
    serial: &[u8],
    cert_digest: &str,
    csr_digest: &str,
    act_digest: Option<&str>,
    not_after: Duration,
) -> String {
    // The authorizing act's digest (a markl id, never its contents), left
    // out, not empty, when there is no act.
    let act = act_digest.map(|d| format!(" act={d}")).unwrap_or_default();
    format!(
        "piggy-ca issued profile={profile_name} serial={} cert={cert_digest} csr={csr_digest}{act} not_after={}",
        hex::encode(serial),
        not_after.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca_profile;
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use piggy_piv::{PivAlgorithm, cert_builder};

    const NOW: Duration = Duration::from_secs(1_800_000_000);
    const SERIAL: [u8; 16] = [7; 16];
    const GUID: &str = "0123456789abcdef0123456789abcdef";

    struct Pair {
        key: EcKey<openssl::pkey::Private>,
        point: Vec<u8>,
    }

    fn pair() -> Pair {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        Pair { key, point }
    }

    fn sign_with(
        key: &EcKey<openssl::pkey::Private>,
    ) -> impl FnOnce(&[u8]) -> Result<Vec<u8>, PivError> + '_ {
        move |digest| Ok(EcdsaSig::sign(digest, key).unwrap().to_der().unwrap())
    }

    fn root(names: &[String], root_key: &Pair) -> Vec<u8> {
        x509_profile::build_root_cert(
            &root_key.point,
            PivAlgorithm::EcP256,
            "test root",
            names,
            CertValidity {
                not_before: NOW - Duration::from_secs(3600),
                not_after: NOW + Duration::from_secs(10 * 365 * 86400),
            },
            &SERIAL,
            sign_with(&root_key.key),
        )
        .unwrap()
    }

    fn csr(cn: &str, key: &Pair) -> Vec<u8> {
        cert_builder::build_csr(&key.point, PivAlgorithm::EcP256, cn, sign_with(&key.key)).unwrap()
    }

    fn leaf_profile() -> Profile {
        ca_profile::parse(&format!(
            "kind = \"leaf\"\nnames = [\"github.com\", \"api.github.com\"]\nlifetime_hours = 720\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        ))
        .unwrap()
    }

    fn inter_profile() -> Profile {
        ca_profile::parse(&format!(
            "kind = \"intermediate\"\ncommon_name = \"test intermediate\"\nnames = [\"github.com\"]\nlifetime_hours = 24\n[issuer]\nslot = \"82\"\nguid = \"{GUID}\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn a_leaf_for_a_permitted_name_is_issued_with_the_full_set_and_verifies() {
        let issuer = pair();
        let profile = leaf_profile();
        let root_der = root(&profile.names, &issuer);
        let leaf_key = pair();
        let issued = issue(
            &Inputs {
                verb: Verb::Issue,
                profile: &profile,
                csr_der: &csr("github.com", &leaf_key),
                issuer_cert_der: &root_der,
                now: NOW,
                serial: &SERIAL,
            },
            sign_with(&issuer.key),
        )
        .unwrap();

        let leaf = openssl::x509::X509::from_der(&issued.cert_der).unwrap();
        let root = openssl::x509::X509::from_der(&root_der).unwrap();
        assert!(leaf.verify(&root.public_key().unwrap()).unwrap());
        // The SAN is the profile's full set, not the request's one name.
        let sans: Vec<String> = leaf
            .subject_alt_names()
            .unwrap()
            .iter()
            .map(|g| g.dnsname().unwrap().to_owned())
            .collect();
        assert_eq!(sans, ["github.com", "api.github.com"]);
        assert_eq!(
            issued.requested_not_after,
            NOW + Duration::from_secs(720 * 3600)
        );
    }

    #[test]
    fn an_intermediate_for_the_profiles_cn_is_issued() {
        let issuer = pair();
        let profile = inter_profile();
        let root_der = root(&profile.names, &issuer);
        let key = pair();
        let issued = issue(
            &Inputs {
                verb: Verb::Sign,
                profile: &profile,
                csr_der: &csr("test intermediate", &key),
                issuer_cert_der: &root_der,
                now: NOW,
                serial: &SERIAL,
            },
            sign_with(&issuer.key),
        )
        .unwrap();
        let cert = openssl::x509::X509::from_der(&issued.cert_der).unwrap();
        let root = openssl::x509::X509::from_der(&root_der).unwrap();
        assert!(cert.verify(&root.public_key().unwrap()).unwrap());
    }

    /// Every refusal below must leave the signer uncalled.
    fn refused(inputs: Inputs<'_>) -> Refusal {
        let called = Cell::new(false);
        let err = issue(&inputs, |_| {
            called.set(true);
            Ok(vec![])
        })
        .unwrap_err();
        assert!(!called.get(), "a refusal must not reach the signer");
        err
    }

    #[test]
    fn refusals_carry_their_exit_codes_and_never_reach_the_signer() {
        let issuer = pair();
        let leaf = leaf_profile();
        let root_der = root(&leaf.names, &issuer);
        let key = pair();
        let base = |verb, profile, csr_der| Inputs {
            verb,
            profile,
            csr_der,
            issuer_cert_der: &root_der,
            now: NOW,
            serial: &SERIAL,
        };

        let foreign = csr("evil.example", &key);
        let r = refused(base(Verb::Issue, &leaf, &foreign));
        assert_eq!(r.exit_code(), ExitCode::NamesOutsideProfile);

        let r = refused(base(Verb::Issue, &leaf, b"not a csr"));
        assert_eq!(r.exit_code(), ExitCode::CsrMalformed);

        let good = csr("github.com", &key);
        let r = refused(base(Verb::Sign, &leaf, &good));
        assert_eq!(r.exit_code(), ExitCode::ProfileUnknown);
        assert_eq!(
            r.to_string(),
            "`piggy ca sign` issues an intermediate certificate; this profile is leaf"
        );

        let mut p384_only = leaf.clone();
        p384_only.key_types = vec![crate::ca_profile::KeyType::P384];
        let r = refused(base(Verb::Issue, &p384_only, &good));
        assert_eq!(r, Refusal::KeyTypeNotInProfile);
        assert_eq!(r.exit_code(), ExitCode::CsrMalformed);

        let short = Inputs {
            serial: &[1, 2, 3],
            ..base(Verb::Issue, &leaf, &good)
        };
        assert_eq!(refused(short).exit_code(), ExitCode::Other);
    }

    /// The holder's way: a signer that is handed the TBSCertificate and
    /// hashes for itself issues a leaf under an intermediate; the same
    /// signer is refused for an intermediate, and a leaf's notAfter is the
    /// intermediate's when the profile's lifetime outlives it.
    #[test]
    fn a_tbs_signer_issues_a_leaf_under_the_intermediate_and_never_an_intermediate() {
        use openssl::hash::{MessageDigest, hash};
        let root_key = pair();
        let root_der = root(&["github.com".to_string()], &root_key);
        let int_key = pair();
        let int_der = x509_profile::build_intermediate_cert(
            &int_key.point,
            PivAlgorithm::EcP256,
            "test intermediate",
            &["github.com".to_string()],
            &root_der,
            CertValidity {
                not_before: NOW - Duration::from_secs(3600),
                not_after: NOW + Duration::from_secs(24 * 3600),
            },
            &SERIAL,
            sign_with(&root_key.key),
        )
        .unwrap();
        let profile = leaf_profile();
        let leaf_key = pair();
        let over_tbs = |key: &'static EcKey<openssl::pkey::Private>| {
            Signer::Tbs(Box::new(move |tbs: &[u8]| {
                let digest = hash(MessageDigest::sha256(), tbs).unwrap();
                Ok(EcdsaSig::sign(&digest, key).unwrap().to_der().unwrap())
            }))
        };
        let int_key_ref: &'static EcKey<_> = Box::leak(Box::new(int_key.key.clone()));
        let issued = issue_with(
            &Inputs {
                verb: Verb::Issue,
                profile: &profile,
                csr_der: &csr("github.com", &leaf_key),
                issuer_cert_der: &int_der,
                now: NOW,
                serial: &SERIAL,
            },
            over_tbs(int_key_ref),
        )
        .unwrap();
        let leaf = openssl::x509::X509::from_der(&issued.cert_der).unwrap();
        let int = openssl::x509::X509::from_der(&int_der).unwrap();
        assert!(leaf.verify(&int.public_key().unwrap()).unwrap());
        // The profile asked for 720 hours; the intermediate ends in 24.
        assert_eq!(
            leaf.not_after().compare(int.not_after()).unwrap(),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            issued.requested_not_after,
            NOW + Duration::from_secs(720 * 3600)
        );

        let inter = inter_profile();
        let err = issue_with(
            &Inputs {
                verb: Verb::Sign,
                profile: &inter,
                csr_der: &csr("test intermediate", &pair()),
                issuer_cert_der: &root_der,
                now: NOW,
                serial: &SERIAL,
            },
            over_tbs(Box::leak(Box::new(root_key.key.clone()))),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Other);
        assert!(err.to_string().contains("signed on the card"), "{err}");
    }

    #[test]
    fn a_profile_naming_what_the_issuer_may_not_certify_is_the_profiles_fault() {
        let issuer = pair();
        let root_der = root(&["github.com".to_string()], &issuer);
        let key = pair();
        let mut wide = leaf_profile();
        wide.names = vec!["github.com".into(), "evil.example".into()];
        let r = refused(Inputs {
            verb: Verb::Issue,
            profile: &wide,
            csr_der: &csr("github.com", &key),
            issuer_cert_der: &root_der,
            now: NOW,
            serial: &SERIAL,
        });
        assert_eq!(r.exit_code(), ExitCode::ProfileUnknown);
        let text = r.to_string();
        assert!(
            text.contains("evil.example") && text.contains("permitted: github.com"),
            "{text}"
        );
        // The names under the permitted subtree pass; an intermediate's
        // names are held to the same rule; a root with no constraints
        // admits anything; an unreadable issuer is Other.
        assert_eq!(check_issuer_admits(&leaf_profile(), &root_der), Ok(()));
        let mut inter = inter_profile();
        inter.names = vec!["example.org".into()];
        assert!(matches!(
            check_issuer_admits(&inter, &root_der),
            Err(Refusal::NamesOutsideIssuer(_))
        ));
        assert!(matches!(
            check_issuer_admits(&wide, b"junk"),
            Err(Refusal::Other(_))
        ));
    }

    #[test]
    fn a_signer_that_fails_is_the_issuer_being_unavailable() {
        let issuer = pair();
        let profile = leaf_profile();
        let root_der = root(&profile.names, &issuer);
        let key = pair();
        let err = issue(
            &Inputs {
                verb: Verb::Issue,
                profile: &profile,
                csr_der: &csr("github.com", &key),
                issuer_cert_der: &root_der,
                now: NOW,
                serial: &SERIAL,
            },
            |_| Err(PivError::Other("card absent".into())),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::IssuerUnavailable);
        assert!(err.to_string().contains("card absent"));
    }

    #[test]
    fn a_leaf_cannot_be_issued_by_a_non_ca_issuer() {
        let issuer = pair();
        let profile = leaf_profile();
        let root_der = root(&profile.names, &issuer);
        let key = pair();
        let first = issue(
            &Inputs {
                verb: Verb::Issue,
                profile: &profile,
                csr_der: &csr("github.com", &key),
                issuer_cert_der: &root_der,
                now: NOW,
                serial: &SERIAL,
            },
            sign_with(&issuer.key),
        )
        .unwrap();
        // The leaf just issued is not a CA: using it as the issuer is Other.
        let err = issue(
            &Inputs {
                verb: Verb::Issue,
                profile: &profile,
                csr_der: &csr("github.com", &key),
                issuer_cert_der: &first.cert_der,
                now: NOW,
                serial: &SERIAL,
            },
            sign_with(&issuer.key),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::Other);
    }

    #[test]
    fn the_rate_limit_allows_the_first_use_and_a_use_after_the_window() {
        assert_eq!(check_rate(None, NOW), Ok(()));
        assert_eq!(check_rate(Some(NOW - RATE_WINDOW), NOW), Ok(()));
        let just = check_rate(Some(NOW - RATE_WINDOW + Duration::from_secs(1)), NOW).unwrap_err();
        assert_eq!(just.exit_code(), ExitCode::RateLimited);
        assert_eq!(
            just,
            Refusal::RateLimited {
                retry_after: Duration::from_secs(1)
            }
        );
    }

    #[test]
    fn a_state_timestamp_in_the_future_is_refused_not_allowed() {
        let err = check_rate(Some(NOW + Duration::from_secs(60)), NOW).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::RateLimited);
    }

    #[test]
    fn the_audit_line_is_one_line_of_key_value_pairs() {
        let line = audit_line(
            "shithub-github",
            &[0xab, 0xcd],
            "blake2b256-aa",
            "blake2b256-bb",
            None,
            Duration::from_secs(1_802_592_000),
        );
        assert_eq!(
            line,
            "piggy-ca issued profile=shithub-github serial=abcd cert=blake2b256-aa csr=blake2b256-bb not_after=1802592000",
            "no act: the field is absent, not empty"
        );
        assert!(!line.contains('\n'));
        let with_act = audit_line(
            "shithub-github",
            &[0xab, 0xcd],
            "blake2b256-aa",
            "blake2b256-bb",
            Some("blake2b256-cc"),
            Duration::from_secs(1_802_592_000),
        );
        assert_eq!(
            with_act,
            "piggy-ca issued profile=shithub-github serial=abcd cert=blake2b256-aa csr=blake2b256-bb act=blake2b256-cc not_after=1802592000"
        );
    }
}
