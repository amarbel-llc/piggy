//! `hogtie exec RESPONSE ACTION [ARGS]`: decide, in this order, failing
//! closed at the first refusal:
//!
//! 1. the response parses (else nothing is touched);
//! 2. the nonce is claimed from the caller's account directory: from here
//!    on it is burnt, whatever follows;
//! 3. the nonce has not expired;
//! 4. the configuration is root-owned, unwritable by others, and parses;
//! 5. the action is declared;
//! 6. the message rebuilt from (host, nonce, caller uid, action, args)
//!    encodes;
//! 7. the grant passes hogtie's own checks (`grant.rs`);
//! 8. ssh-keygen and the action's program are root-owned files writable by
//!    no one else;
//! 9. ssh-keygen verifies the signature over the message, for the action;
//! 10. the arguments fit the action's typed parameters.
//!
//! The decision and its audit record are returned; `main` appends the
//! record and only then executes.

use crate::audit::Record;
use crate::config::Config;
use crate::grant::{GrantPolicy, check_grant};
use crate::message::{MAX_ARG_LEN, MAX_ARGS, Request, principal};
use crate::nonce::NonceStore;
use crate::paths::Paths;
use crate::response::{Response, nonce_hex};
use crate::sshwire::Sshsig;
use crate::util::Clock;
use crate::verify::{Verifier, VerifyError};
use std::path::PathBuf;

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub program: PathBuf,
    /// argv, program first.
    pub argv: Vec<String>,
    /// The whole environment.
    pub env: Vec<(String, String)>,
}

/// Why nothing runs. `internal` marks hogtie's own failure (its
/// configuration, its store, its scratch directory, running ssh-keygen):
/// exit 3 and outcome `error`, not the caller's refusal (exit 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub internal: bool,
}

fn refused(reason: impl ToString) -> Refusal {
    Refusal {
        reason: reason.to_string(),
        internal: false,
    }
}

fn broken(reason: impl ToString) -> Refusal {
    Refusal {
        reason: reason.to_string(),
        internal: true,
    }
}

#[derive(Debug)]
pub struct Decision {
    pub run: Result<Run, Refusal>,
    pub record: Record,
}

pub fn decide(
    paths: &Paths,
    caller_uid: u32,
    response: &str,
    action: &str,
    args: &[String],
    clock: Clock,
) -> Decision {
    // Anyone the sudo rule admits can call this with no grant at all: the
    // record is bounded where it is written (Record::to_json, LINE_MAX).
    let mut record = Record {
        time: clock.wall,
        outcome: "refused",
        caller_uid: Some(caller_uid),
        action: Some(action.to_string()),
        args: args.to_vec(),
        ..Default::default()
    };
    // The action must be a config key's shape before anything else, and is
    // never echoed when it is not (review N1).
    let run = if !crate::message::is_action_name(action) {
        Err(refused(
            "the action given is not an action name ([a-z0-9][a-z0-9-]{0,62})",
        ))
    } else if args.len() > MAX_ARGS || args.iter().any(|a| a.len() > MAX_ARG_LEN) {
        Err(refused(format!(
            "at most {MAX_ARGS} arguments of at most {MAX_ARG_LEN} bytes each"
        )))
    } else {
        steps(
            paths,
            caller_uid,
            response,
            action,
            args,
            clock,
            &mut record,
        )
    };
    match &run {
        Ok(r) => {
            record.outcome = "started";
            record.argv = r.argv.clone();
        }
        Err(e) => {
            if e.internal {
                record.outcome = "error";
            }
            record.reason = Some(e.reason.clone());
        }
    }
    Decision { run, record }
}

fn steps(
    paths: &Paths,
    caller_uid: u32,
    response: &str,
    action: &str,
    args: &[String],
    clock: Clock,
    record: &mut Record,
) -> Result<Run, Refusal> {
    use crate::nonce::ClaimError;
    let now = clock.wall;
    let response = Response::parse(response).map_err(refused)?;
    record.nonce = Some(nonce_hex(&response.nonce));
    // The store exec reads is checked as the socket checks it (review note).
    crate::paths::check_dir(&paths.run, 0o711).map_err(broken)?;
    crate::paths::check_dir(&paths.nonces(), 0o700).map_err(broken)?;
    // A nonce's life is on the boot clock, which nobody can set back.
    let entry = NonceStore::new(paths.nonces())
        .claim(caller_uid, &response.nonce, clock.boot)
        .map_err(|e| match &e {
            ClaimError::Expired(en) => {
                record.asked_by = Some(en.clone());
                refused(&e)
            }
            ClaimError::Unknown => refused(&e),
            ClaimError::Corrupt | ClaimError::Io(_) => broken(&e),
        })?;
    record.asked_by = Some(entry);
    let config =
        Config::parse(&paths.read_trusted(&paths.config).map_err(broken)?).map_err(broken)?;
    let declared = config
        .actions
        .get(action)
        .ok_or_else(|| refused(format!("action {action:?} is not declared on this host")))?;
    let message = Request {
        host: config.host.clone(),
        nonce: response.nonce,
        uid: caller_uid,
        action: action.to_string(),
        args: args.to_vec(),
    }
    .encode()
    .map_err(refused)?;
    let sig = Sshsig::parse(&response.sshsig).map_err(|e| refused(format!("signature: {e}")))?;
    let ca_blobs: Vec<Vec<u8>> = config.cas.iter().map(|c| c.blob.clone()).collect();
    let grant = check_grant(
        &sig,
        action,
        now,
        &GrantPolicy {
            host: &config.host,
            ca_blobs: &ca_blobs,
            max_span_seconds: config.max_grant_seconds,
        },
    )
    .map_err(refused)?;
    paths
        .check_trusted_program(&config.ssh_keygen)
        .map_err(broken)?;
    paths
        .check_trusted_program(&declared.program)
        .map_err(broken)?;
    Paths::ensure_private_dir(&paths.scratch())
        .map_err(|e| broken(format!("scratch directory: {e}")))?;
    Verifier {
        ssh_keygen: &config.ssh_keygen,
        cas: &config.cas,
        scratch: &paths.scratch(),
        timeout: crate::verify::VERIFY_TIMEOUT,
    }
    .verify(&message, &sig, &principal(&config.host, action))
    .map_err(|e| match e {
        VerifyError::Io(_) => broken(&e),
        VerifyError::Refused(_) => refused(&e),
    })?;
    // Only a grant whose key made this signature is recorded as used: a
    // copied certificate in a forged sshsig is not logged as its owner's.
    record.grant = Some(grant);
    let argv = declared.build(args).map_err(refused)?;
    Ok(Run {
        program: declared.program.clone(),
        argv,
        env: declared.env.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::Asker;
    use crate::testkit::Kit;
    use crate::util::PrivateDir;

    struct Host {
        kit: Kit,
        _root: PrivateDir,
        paths: Paths,
        uid: u32,
    }

    impl Host {
        fn new() -> Self {
            let kit = Kit::new();
            let root = PrivateDir::new(&std::env::temp_dir(), "hogtie-host").unwrap();
            // SAFETY: getuid cannot fail.
            let uid = unsafe { libc::getuid() };
            let paths = Paths::under(root.path(), uid);
            std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
            crate::paths::ensure_dir(&paths.run, 0o711).unwrap();
            Paths::ensure_private_dir(&paths.nonces()).unwrap();
            let config = format!(
                "host = \"{}\"\nssh_keygen = \"{}\"\nca_keys = [\"{}\"]\nmax_grant_seconds = 86400\n\
                 [action.say]\nprogram = \"{}\"\nargv = [\"{{word}}\"]\nenv = {{ LANG = \"C\" }}\n\
                 param = [{{ name = \"word\", kind = \"choice\", values = [\"hello\", \"bye\"] }}]\n",
                crate::testkit::HOST,
                kit.ssh_keygen.display(),
                kit.ca_line(),
                crate::testkit::trusted_copy(kit.dir(), "echo").display(),
            );
            crate::testkit::write_trusted(&paths.config, &config);
            Self {
                kit,
                _root: root,
                paths,
                uid,
            }
        }

        fn nonce_for(&self, uid: u32, now: u64) -> crate::message::Nonce {
            NonceStore::new(self.paths.nonces())
                .issue(
                    &Asker {
                        uid,
                        pid: 1,
                        cgroup: Some("/a/agent.scope".into()),
                    },
                    now,
                )
                .unwrap()
                .0
        }

        /// A response for (this host, nonce, uid, action, args) signed with
        /// `cert`.
        fn respond(
            &self,
            cert: &std::path::Path,
            nonce: crate::message::Nonce,
            uid: u32,
            action: &str,
            args: &[&str],
        ) -> String {
            self.respond_for(crate::testkit::HOST, cert, nonce, uid, action, args)
        }

        /// The same, with the message signed for `host`.
        fn respond_for(
            &self,
            host: &str,
            cert: &std::path::Path,
            nonce: crate::message::Nonce,
            uid: u32,
            action: &str,
            args: &[&str],
        ) -> String {
            let msg = Request {
                host: host.into(),
                nonce,
                uid,
                action: action.into(),
                args: args.iter().map(|s| s.to_string()).collect(),
            }
            .encode()
            .unwrap();
            Response {
                nonce,
                sshsig: self.kit.sign(cert, &msg).encode(),
            }
            .format()
        }

        /// `exec` with both clocks at `now`.
        fn exec(&self, response: &str, action: &str, args: &[&str], now: u64) -> Decision {
            self.exec_at(
                response,
                action,
                args,
                Clock {
                    wall: now,
                    boot: now,
                },
            )
        }

        fn exec_at(&self, response: &str, action: &str, args: &[&str], clock: Clock) -> Decision {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            decide(&self.paths, self.uid, response, action, &args, clock)
        }

        fn set_host(&self, host: &str) {
            let old = std::fs::read_to_string(&self.paths.config).unwrap();
            let new = old.replacen(
                &format!("host = \"{}\"", crate::testkit::HOST),
                &format!("host = \"{host}\""),
                1,
            );
            assert_ne!(old, new);
            crate::testkit::write_trusted(&self.paths.config, &new);
        }
    }

    #[test]
    fn a_grant_for_this_host_is_refused_on_another() {
        let h = Host::new();
        h.set_host("h2");
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond_for(
            "h2",
            &cert,
            h.nonce_for(h.uid, now),
            h.uid,
            "say",
            &["hello"],
        );
        assert_eq!(
            refusal(&h.exec(&r, "say", &["hello"], now)),
            "grant names \"h1:say\", for another host"
        );
    }

    #[test]
    fn a_message_signed_for_another_host_is_refused() {
        // A grant for both hosts; the caller signed for h2 and replays on h1.
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["h1:say", "h2:say"], "+1h", &[]);
        let r = h.respond_for(
            "h2",
            &cert,
            h.nonce_for(h.uid, now),
            h.uid,
            "say",
            &["hello"],
        );
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("signature refused"));
    }

    #[test]
    fn a_message_signed_for_the_wrong_host_is_refused_with_a_grant_for_this_one() {
        // This host is h2 and the grant names h2:say, but the caller signed a
        // message for h1: hogtie rebuilds the message with its own host.
        let h = Host::new();
        h.set_host("h2");
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["h2:say"], "+1h", &[]);
        let r = h.respond_for(
            "h1",
            &cert,
            h.nonce_for(h.uid, now),
            h.uid,
            "say",
            &["hello"],
        );
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("signature refused"));
    }

    #[test]
    fn an_unpinned_grant_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("with no host"));
    }

    #[test]
    fn a_bad_action_name_is_refused_first_and_not_echoed() {
        let h = Host::new();
        let now = crate::util::now();
        let action = "\u{1}".repeat(128 * 1024);
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        let d = h.exec(&r, &action, &[], now);
        let reason = refusal(&d).to_string();
        assert!(
            reason.len() < 200,
            "the reason echoes the caller: {} bytes",
            reason.len()
        );
        assert!(reason.contains("not an action name"), "{reason}");
        // Refused before the nonce is claimed: it is still usable.
        assert!(h.exec(&r, "say", &["hello"], now).run.is_ok());
    }

    #[test]
    fn every_refusal_line_fits_the_cap() {
        // Caller bytes reach reasons through a forged certificate too: a
        // pattern principal is echoed. The line still fits.
        let h = Host::new();
        let now = crate::util::now();
        let long = format!("*{}", "x".repeat(8000));
        let cert = h.kit.cert("a", &[&long], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        let d = h.exec(&r, "say", &["hello"], now);
        assert!(refusal(&d).contains("pattern character"), "{}", refusal(&d));
        let line = d.record.to_json();
        assert!(line.len() <= crate::audit::LINE_MAX, "{} bytes", line.len());
    }

    #[test]
    fn exec_checks_the_nonce_store_it_reads() {
        use std::os::unix::fs::PermissionsExt as _;
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        std::fs::set_permissions(h.paths.nonces(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let d = h.exec(&r, "say", &["hello"], now);
        assert!(d.run.as_ref().is_err_and(|e| e.internal), "{:?}", d.run);
        assert!(
            refusal(&d).contains("no permission beyond"),
            "{}",
            refusal(&d)
        );
    }

    #[test]
    fn a_huge_refused_request_is_recorded_bounded() {
        let h = Host::new();
        let big = "x".repeat(1 << 20);
        let many: Vec<&str> = std::iter::repeat_n(big.as_str(), 64).collect();
        let d = h.exec("garbage", &"a".repeat(1 << 20), &many, crate::util::now());
        assert!(d.run.is_err());
        let line = d.record.to_json();
        assert!(line.len() < 64 * 1024, "the line is {} bytes", line.len());
    }

    #[test]
    fn a_nonce_lives_on_the_boot_clock_not_the_wall_clock() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let n = h.nonce_for(h.uid, 1_000);
        let r = h.respond(&cert, n, h.uid, "say", &["hello"]);
        // The wall clock is fine (now) but 31 boot seconds have passed.
        let d = h.exec_at(
            &r,
            "say",
            &["hello"],
            Clock {
                wall: now,
                boot: 1_031,
            },
        );
        assert_eq!(refusal(&d), "nonce has expired");
    }

    fn refusal(d: &Decision) -> &str {
        d.run
            .as_ref()
            .err()
            .map(|r| r.reason.as_str())
            .unwrap_or("ran")
    }

    #[test]
    fn a_forged_signature_is_not_recorded_as_the_copied_grant() {
        let h = Host::new();
        let now = crate::util::now();
        let alice = h.kit.grant("alice", &["say"], "+1h", &[]);
        let n = h.nonce_for(h.uid, now);
        let mut sig = h.kit.sign_plain(b"anything");
        sig.public_key = h.kit.sign(&alice, b"anything").public_key;
        let r = Response {
            nonce: n,
            sshsig: sig.encode(),
        }
        .format();
        let d = h.exec(&r, "say", &["hello"], now);
        assert!(refusal(&d).contains("signature refused"), "{}", refusal(&d));
        assert_eq!(d.record.grant, None);
    }

    #[test]
    fn hogtie_own_failures_are_marked_internal_not_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        std::fs::remove_file(&h.paths.config).unwrap();
        let d = h.exec(&r, "say", &["hello"], now);
        assert!(d.run.as_ref().unwrap_err().internal);
        assert_eq!(d.record.outcome, "error");
        let replay = h.exec(&r, "say", &["hello"], now);
        assert!(
            !replay.run.unwrap_err().internal,
            "a replay is the caller's"
        );
        assert_eq!(replay.record.outcome, "refused");
    }

    #[test]
    fn a_granted_action_runs_and_is_recorded() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("agent-1", &["say"], "+1h", &[]);
        let n = h.nonce_for(h.uid, now);
        let d = h.exec(
            &h.respond(&cert, n, h.uid, "say", &["hello"]),
            "say",
            &["hello"],
            now,
        );
        let run = d.run.unwrap();
        assert_eq!(run.argv[1..], ["hello"]);
        assert_eq!(run.env, [("LANG".to_string(), "C".to_string())]);
        assert_eq!(d.record.outcome, "started");
        assert_eq!(d.record.grant.unwrap().key_id, "agent-1");
        assert_eq!(d.record.asked_by.unwrap().asker.unit(), Some("agent.scope"));
    }

    #[test]
    fn a_replayed_response_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(h.exec(&r, "say", &["hello"], now).run.is_ok());
        let again = h.exec(&r, "say", &["hello"], now);
        assert!(
            refusal(&again).contains("unknown nonce"),
            "{}",
            refusal(&again)
        );
    }

    #[test]
    fn a_refused_attempt_burns_the_nonce() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(
            h.exec(&r, "say", &["bye"], now).run.is_err(),
            "signed for hello, asked for bye"
        );
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("unknown nonce"));
    }

    #[test]
    fn arguments_other_than_the_signed_ones_are_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["bye"], now)).contains("signature refused"));
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "20200101:20200102", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert_eq!(
            refusal(&h.exec(&r, "say", &["hello"], now)),
            "grant has expired"
        );
    }

    #[test]
    fn an_expired_nonce_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(
            &cert,
            h.nonce_for(h.uid, now - 31),
            h.uid,
            "say",
            &["hello"],
        );
        assert_eq!(
            refusal(&h.exec(&r, "say", &["hello"], now)),
            "nonce has expired"
        );
    }

    #[test]
    fn an_action_the_grant_does_not_name_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["other"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert_eq!(
            refusal(&h.exec(&r, "say", &["hello"], now)),
            "grant does not name action \"say\""
        );
    }

    #[test]
    fn an_undeclared_action_is_refused_even_when_granted() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["shutdown"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "shutdown", &[]);
        assert!(refusal(&h.exec(&r, "shutdown", &[], now)).contains("not declared"));
    }

    #[test]
    fn a_nonce_asked_by_another_account_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let other = h.uid + 1;
        let n = h.nonce_for(other, now);
        // Signed honestly for this account, and for the other: both refused.
        for uid in [h.uid, other] {
            let r = h.respond(&cert, n, uid, "say", &["hello"]);
            assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("unknown nonce"));
        }
    }

    #[test]
    fn a_signature_naming_another_account_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid + 1, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("signature refused"));
    }

    #[test]
    fn a_copied_grant_used_with_another_key_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let alice = h.kit.grant("alice", &["say"], "+1h", &[]);
        let mallory = h.kit.grant("mallory", &["other"], "+1h", &[]);
        let n = h.nonce_for(h.uid, now);
        let msg = Request {
            host: crate::testkit::HOST.into(),
            nonce: n,
            uid: h.uid,
            action: "say".into(),
            args: vec!["hello".into()],
        }
        .encode()
        .unwrap();
        let mut sig = h.kit.sign(&mallory, &msg);
        sig.public_key = h.kit.sign(&alice, b"anything").public_key;
        let r = Response {
            nonce: n,
            sshsig: sig.encode(),
        }
        .format();
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("signature refused"));
    }

    #[test]
    fn malformed_everything_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let n = h.nonce_for(h.uid, now);
        assert!(refusal(&h.exec("garbage", "say", &["hello"], now)).contains("not v1"));
        let junk = Response {
            nonce: n,
            sshsig: b"not an sshsig".to_vec(),
        }
        .format();
        assert!(refusal(&h.exec(&junk, "say", &["hello"], now)).contains("SSHSIG"));
        let n = h.nonce_for(h.uid, now);
        let r = Response {
            nonce: n,
            sshsig: vec![],
        }
        .format();
        assert!(refusal(&h.exec(&r, "Bad Action", &[], now)).contains("not an action name"));
    }

    #[test]
    fn a_program_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let h = Host::new();
        let prog = crate::testkit::trusted_copy(h.paths.config.parent().unwrap(), "echo");
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o757)).unwrap();
        let echo = crate::testkit::trusted_copy(h.kit.dir(), "echo");
        let old = std::fs::read_to_string(&h.paths.config).unwrap();
        let text = old.replace(
            &format!("program = \"{}\"", echo.display()),
            &format!("program = \"{}\"", prog.display()),
        );
        assert_ne!(text, old, "the program line was replaced");
        crate::testkit::write_trusted(&h.paths.config, &text);
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        let d = h.exec(&r, "say", &["hello"], now);
        assert_eq!(
            refusal(&d),
            format!(
                "{} must be a file owned by root and writable by no one else",
                prog.display()
            )
        );
    }

    #[test]
    fn a_config_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let h = Host::new();
        std::fs::set_permissions(&h.paths.config, std::fs::Permissions::from_mode(0o666)).unwrap();
        let now = crate::util::now();
        let cert = h.kit.grant("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("writable by no one else"));
    }
}
