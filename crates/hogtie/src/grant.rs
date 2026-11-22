//! The checks hogtie makes on a grant itself, from the parsed sshsig and
//! certificate, before and besides ssh-keygen's. ssh-keygen (OpenSSH 10.5)
//! refuses expired, not-yet-valid and host certificates and a principal not
//! in the certificate, but ACCEPTS a certificate with critical options, and
//! honours any `-O verify-time` it is given (hogtie passes none); see the
//! `explore-hogtie-sshsig-grant-edges` recipe. So, fail closed, hogtie
//! refuses here:
//!
//! - an sshsig whose namespace is not `hogtie-v1` or whose hash is unknown;
//! - a signing key that is not a user certificate;
//! - a certificate signed by a key that is not one of the configured CAs;
//! - any critical option at all;
//! - a principal holding a pattern character (`*?!,`), even though 10.5
//!   matches principals literally: older OpenSSH did not;
//! - a grant not pinned to this host: the principal must be exactly
//!   `<host>:<action>`, the host being this host's configured name; a bare
//!   `<action>` (unpinned) and another host's `<other>:<action>` are refused
//!   with their own reasons;
//! - a certificate outside its validity at `now`, or whose validity span is
//!   longer than the configured maximum.

use crate::message::{NAMESPACE, principal};
use crate::sshwire::{Certificate, SSH2_CERT_TYPE_USER, Sshsig, WireError};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    Wire(WireError),
    WrongNamespace(String),
    UnknownHash(String),
    NotAUserCertificate,
    UnknownCa,
    CriticalOption(String),
    PatternPrincipal(String),
    ActionNotGranted(String),
    /// The grant names the action with no host.
    Unpinned(String),
    /// The grant names the action for another host (the principal given).
    OtherHost(String),
    NotYetValid,
    Expired,
    SpanTooLong {
        span: u64,
        max: u64,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantError::Wire(e) => write!(f, "signature: {e}"),
            GrantError::WrongNamespace(n) => {
                write!(f, "signature namespace is {n:?}, not {NAMESPACE:?}")
            }
            GrantError::UnknownHash(h) => write!(f, "signature hash {h:?} is not sha256 or sha512"),
            GrantError::NotAUserCertificate => f.write_str("grant is not a user certificate"),
            GrantError::UnknownCa => f.write_str("grant is not signed by a configured CA"),
            GrantError::CriticalOption(o) => {
                write!(f, "grant carries critical option {o:?}; hogtie refuses all")
            }
            GrantError::PatternPrincipal(p) => {
                write!(f, "grant principal {p:?} holds a pattern character")
            }
            GrantError::ActionNotGranted(a) => write!(f, "grant does not name action {a:?}"),
            GrantError::Unpinned(a) => {
                write!(
                    f,
                    "grant names {a:?} with no host; a principal must be <host>:<action>"
                )
            }
            GrantError::OtherHost(p) => write!(f, "grant names {p:?}, for another host"),
            GrantError::NotYetValid => f.write_str("grant is not yet valid"),
            GrantError::Expired => f.write_str("grant has expired"),
            GrantError::SpanTooLong { span, max } => {
                write!(
                    f,
                    "grant is valid for {span} s, more than the {max} s this host allows"
                )
            }
        }
    }
}

/// What a grant allows, as read from it: what the audit line records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub key_id: String,
    pub serial: u64,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
}

pub struct GrantPolicy<'a> {
    /// This host's configured name.
    pub host: &'a str,
    /// The configured CA public key blobs.
    pub ca_blobs: &'a [Vec<u8>],
    pub max_span_seconds: u64,
}

/// Check the sshsig's grant for `action` at `now`.
pub fn check_grant(
    sig: &Sshsig,
    action: &str,
    now: u64,
    policy: &GrantPolicy<'_>,
) -> Result<Grant, GrantError> {
    if sig.namespace != NAMESPACE {
        return Err(GrantError::WrongNamespace(sig.namespace.clone()));
    }
    if sig.hash_algorithm != "sha512" && sig.hash_algorithm != "sha256" {
        return Err(GrantError::UnknownHash(sig.hash_algorithm.clone()));
    }
    let cert = Certificate::parse(&sig.public_key).map_err(GrantError::Wire)?;
    if cert.cert_type != SSH2_CERT_TYPE_USER {
        return Err(GrantError::NotAUserCertificate);
    }
    if !policy.ca_blobs.contains(&cert.signature_key) {
        return Err(GrantError::UnknownCa);
    }
    if let Some((name, _)) = cert.critical_options.first() {
        return Err(GrantError::CriticalOption(name.clone()));
    }
    if let Some(p) = cert
        .principals
        .iter()
        .find(|p| p.contains(['*', '?', '!', ',']))
    {
        return Err(GrantError::PatternPrincipal(p.clone()));
    }
    let wanted = principal(policy.host, action);
    if !cert.principals.contains(&wanted) {
        if cert.principals.iter().any(|p| p == action) {
            return Err(GrantError::Unpinned(action.to_string()));
        }
        let elsewhere = cert
            .principals
            .iter()
            .find(|p| p.split_once(':').is_some_and(|(_, a)| a == action));
        if let Some(p) = elsewhere {
            return Err(GrantError::OtherHost(p.clone()));
        }
        return Err(GrantError::ActionNotGranted(action.to_string()));
    }
    if now < cert.valid_after {
        return Err(GrantError::NotYetValid);
    }
    if now >= cert.valid_before {
        return Err(GrantError::Expired);
    }
    let span = cert.valid_before - cert.valid_after;
    if span > policy.max_span_seconds {
        return Err(GrantError::SpanTooLong {
            span,
            max: policy.max_span_seconds,
        });
    }
    Ok(Grant {
        key_id: cert.key_id,
        serial: cert.serial,
        principals: cert.principals,
        valid_after: cert.valid_after,
        valid_before: cert.valid_before,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::Kit;

    const DAY: u64 = 86_400;

    fn policy(kit: &Kit) -> (Vec<Vec<u8>>, u64) {
        (vec![kit.ca_blob()], 30 * DAY)
    }

    fn check(kit: &Kit, sig: &Sshsig, action: &str, now: u64) -> Result<Grant, GrantError> {
        let (cas, max) = policy(kit);
        check_grant(
            sig,
            action,
            now,
            &GrantPolicy {
                host: crate::testkit::HOST,
                ca_blobs: &cas,
                max_span_seconds: max,
            },
        )
    }

    #[test]
    fn a_grant_naming_the_action_passes_and_is_read() {
        let kit = Kit::new();
        let cert = kit.grant("alice", &["restic-snapshots", "circus-status"], "+1h", &[]);
        let sig = kit.sign(&cert, b"m");
        let g = check(&kit, &sig, "circus-status", crate::util::now()).unwrap();
        assert_eq!(g.key_id, "alice");
        assert_eq!(g.principals, ["h1:restic-snapshots", "h1:circus-status"]);
    }

    #[test]
    fn a_grant_for_another_host_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["h2:a"], "+1h", &[]), b"m");
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::OtherHost("h2:a".into()))
        );
    }

    #[test]
    fn an_unpinned_grant_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["a"], "+1h", &[]), b"m");
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::Unpinned("a".into()))
        );
    }

    #[test]
    fn a_grant_for_several_hosts_works_on_each_named_one() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["h2:a", "h1:a"], "+1h", &[]), b"m");
        assert!(check(&kit, &sig, "a", crate::util::now()).is_ok());
    }

    #[test]
    fn an_action_the_grant_does_not_name_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["restic-snapshots"], "+1h", &[]), b"m");
        assert_eq!(
            check(&kit, &sig, "restic", crate::util::now()),
            Err(GrantError::ActionNotGranted("restic".into()))
        );
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "20200101:20200102", &[]), b"m");
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::Expired)
        );
    }

    #[test]
    fn a_future_grant_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1d:+2d", &[]), b"m");
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::NotYetValid)
        );
    }

    #[test]
    fn a_wildcard_principal_is_refused_not_honoured() {
        let kit = Kit::new();
        for p in ["*", "restic-*", "a?", "!a"] {
            let sig = kit.sign(&kit.cert("alice", &[p], "+1h", &[]), b"m");
            assert_eq!(
                check(&kit, &sig, "a", crate::util::now()),
                Err(GrantError::PatternPrincipal(p.into())),
                "{p}"
            );
        }
    }

    #[test]
    fn a_critical_option_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(
            &kit.grant("alice", &["a"], "+1h", &["-O", "force-command=/bin/true"]),
            b"m",
        );
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::CriticalOption("force-command".into()))
        );
    }

    #[test]
    fn a_host_certificate_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &["-h"]), b"m");
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::NotAUserCertificate)
        );
    }

    #[test]
    fn another_ca_is_refused() {
        let kit = Kit::new();
        let other = Kit::new();
        let sig = other.sign(&other.grant("alice", &["a"], "+1h", &[]), b"m");
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::UnknownCa)
        );
    }

    #[test]
    fn a_span_over_the_maximum_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "-1d:+31d", &[]), b"m");
        assert!(matches!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::SpanTooLong { max, .. }) if max == 30 * DAY
        ));
    }

    #[test]
    fn a_span_of_exactly_the_maximum_passes_and_one_second_more_does_not() {
        let kit = Kit::new();
        let start = 1_577_836_800; // 2020-01-01T00:00:00Z
        let now = start + 15 * DAY;
        let exact = kit.sign(
            &kit.grant("alice", &["a"], "20200101000000Z:20200131000000Z", &[]),
            b"m",
        );
        assert!(
            check(&kit, &exact, "a", now).is_ok(),
            "{:?}",
            check(&kit, &exact, "a", now)
        );
        let over = kit.sign(
            &kit.grant("alice", &["a"], "20200101000000Z:20200131000001Z", &[]),
            b"m",
        );
        assert!(matches!(
            check(&kit, &over, "a", now),
            Err(GrantError::SpanTooLong { .. })
        ));
    }

    #[test]
    fn a_comma_in_a_principal_is_refused() {
        // ssh-keygen -n splits on commas, so patch one into the parsed
        // certificate: the check runs before any signature is believed.
        let kit = Kit::new();
        let mut sig = kit.sign(&kit.cert("alice", &["a.b"], "+1h", &[]), b"m");
        let at = sig.public_key.windows(3).position(|w| w == b"a.b").unwrap();
        sig.public_key[at + 1] = b',';
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::PatternPrincipal("a,b".into()))
        );
    }

    #[test]
    fn an_unknown_hash_is_refused() {
        let kit = Kit::new();
        let mut sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        sig.hash_algorithm = "md5".into();
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::UnknownHash("md5".into()))
        );
    }

    #[test]
    fn a_plain_key_signature_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign_plain(b"m");
        assert!(matches!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::Wire(WireError::NotACertificate(_)))
        ));
    }

    #[test]
    fn another_namespace_is_refused() {
        let kit = Kit::new();
        let mut sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        sig.namespace = "file".into();
        assert_eq!(
            check(&kit, &sig, "a", crate::util::now()),
            Err(GrantError::WrongNamespace("file".into()))
        );
    }
}
