//! `hogtie exec RESPONSE ACTION [ARGS]`: decide, in this order, failing
//! closed at the first refusal:
//!
//! 1. the response parses (else nothing is touched);
//! 2. the nonce is claimed from the caller's account directory: from here
//!    on it is burnt, whatever follows;
//! 3. the nonce has not expired;
//! 4. the configuration is root-owned, unwritable by others, and parses;
//! 5. the action is declared;
//! 6. the message rebuilt from (nonce, caller uid, action, args) encodes;
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
use crate::message::Request;
use crate::nonce::NonceStore;
use crate::paths::Paths;
use crate::response::{Response, nonce_hex};
use crate::sshwire::Sshsig;
use crate::verify::Verifier;
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

#[derive(Debug)]
pub struct Decision {
    pub run: Result<Run, String>,
    pub record: Record,
}

pub fn decide(
    paths: &Paths,
    caller_uid: u32,
    response: &str,
    action: &str,
    args: &[String],
    now: u64,
) -> Decision {
    let mut record = Record {
        time: now,
        outcome: "refused",
        caller_uid: Some(caller_uid),
        action: Some(action.to_string()),
        args: args.to_vec(),
        ..Default::default()
    };
    let run = steps(paths, caller_uid, response, action, args, now, &mut record);
    match &run {
        Ok(r) => {
            record.outcome = "ran";
            record.argv = r.argv.clone();
        }
        Err(e) => record.reason = Some(e.clone()),
    }
    Decision { run, record }
}

fn steps(
    paths: &Paths,
    caller_uid: u32,
    response: &str,
    action: &str,
    args: &[String],
    now: u64,
    record: &mut Record,
) -> Result<Run, String> {
    let response = Response::parse(response).map_err(|e| e.to_string())?;
    record.nonce = Some(nonce_hex(&response.nonce));
    let entry = NonceStore::new(paths.nonces())
        .claim(caller_uid, &response.nonce, now)
        .map_err(|e| {
            if let crate::nonce::ClaimError::Expired(en) = &e {
                record.asked_by = Some(en.clone());
            }
            e.to_string()
        })?;
    record.asked_by = Some(entry);
    let config = Config::parse(&paths.read_trusted(&paths.config)?).map_err(|e| e.to_string())?;
    let declared = config
        .actions
        .get(action)
        .ok_or_else(|| format!("action {action:?} is not declared on this host"))?;
    let message = Request {
        nonce: response.nonce,
        uid: caller_uid,
        action: action.to_string(),
        args: args.to_vec(),
    }
    .encode()
    .map_err(|e| e.to_string())?;
    let sig = Sshsig::parse(&response.sshsig).map_err(|e| format!("signature: {e}"))?;
    let ca_blobs: Vec<Vec<u8>> = config.cas.iter().map(|c| c.blob.clone()).collect();
    let grant = check_grant(
        &sig,
        action,
        now,
        &GrantPolicy {
            ca_blobs: &ca_blobs,
            max_span_seconds: config.max_grant_seconds,
        },
    )
    .map_err(|e| e.to_string())?;
    record.grant = Some(grant);
    paths.check_trusted_program(&config.ssh_keygen)?;
    paths.check_trusted_program(&declared.program)?;
    Paths::ensure_private_dir(&paths.scratch()).map_err(|e| format!("scratch directory: {e}"))?;
    Verifier {
        ssh_keygen: &config.ssh_keygen,
        cas: &config.cas,
        scratch: &paths.scratch(),
    }
    .verify(&message, &sig, action)
    .map_err(|e| e.to_string())?;
    let argv = declared.build(args)?;
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

    fn on_path(name: &str) -> String {
        let path = std::env::var_os("PATH").unwrap();
        std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    impl Host {
        fn new() -> Self {
            let kit = Kit::new();
            let root = PrivateDir::new(&std::env::temp_dir(), "hogtie-host").unwrap();
            // SAFETY: getuid cannot fail.
            let uid = unsafe { libc::getuid() };
            let paths = Paths::under(root.path(), uid);
            std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
            Paths::ensure_private_dir(&paths.nonces()).unwrap();
            let config = format!(
                "ssh_keygen = \"{}\"\nca_keys = [\"{}\"]\nmax_grant_seconds = 86400\n\
                 [action.say]\nprogram = \"{}\"\nargv = [\"{{word}}\"]\nenv = {{ LANG = \"C\" }}\n\
                 param = [{{ name = \"word\", kind = \"choice\", values = [\"hello\", \"bye\"] }}]\n",
                kit.ssh_keygen.display(),
                kit.ca_line(),
                on_path("echo"),
            );
            std::fs::write(&paths.config, config).unwrap();
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

        /// A response for (nonce, uid, action, args) signed with `cert`.
        fn respond(
            &self,
            cert: &std::path::Path,
            nonce: crate::message::Nonce,
            uid: u32,
            action: &str,
            args: &[&str],
        ) -> String {
            let msg = Request {
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

        fn exec(&self, response: &str, action: &str, args: &[&str], now: u64) -> Decision {
            let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            decide(&self.paths, self.uid, response, action, &args, now)
        }
    }

    fn refusal(d: &Decision) -> &str {
        d.run.as_ref().err().map(String::as_str).unwrap_or("ran")
    }

    #[test]
    fn a_granted_action_runs_and_is_recorded() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.cert("agent-1", &["say"], "+1h", &[]);
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
        assert_eq!(d.record.outcome, "ran");
        assert_eq!(d.record.grant.unwrap().key_id, "agent-1");
        assert_eq!(d.record.asked_by.unwrap().asker.unit(), Some("agent.scope"));
    }

    #[test]
    fn a_replayed_response_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
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
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
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
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["bye"], now)).contains("signature refused"));
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["say"], "20200101:20200102", &[]);
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
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
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
        let cert = h.kit.cert("a", &["other"], "+1h", &[]);
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
        let cert = h.kit.cert("a", &["shutdown"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "shutdown", &[]);
        assert!(refusal(&h.exec(&r, "shutdown", &[], now)).contains("not declared"));
    }

    #[test]
    fn a_nonce_asked_by_another_account_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
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
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid + 1, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("signature refused"));
    }

    #[test]
    fn a_copied_grant_used_with_another_key_is_refused() {
        let h = Host::new();
        let now = crate::util::now();
        let alice = h.kit.cert("alice", &["say"], "+1h", &[]);
        let mallory = h.kit.cert("mallory", &["other"], "+1h", &[]);
        let n = h.nonce_for(h.uid, now);
        let msg = Request {
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
        assert!(refusal(&h.exec(&r, "Bad Action", &[], now)).contains("not declared"));
    }

    #[test]
    fn a_program_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let h = Host::new();
        let prog = h.paths.config.parent().unwrap().join("prog");
        std::fs::copy(on_path("echo"), &prog).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o757)).unwrap();
        let text = std::fs::read_to_string(&h.paths.config).unwrap();
        let text = text.replace(
            &format!("program = \"{}\"", on_path("echo")),
            &format!("program = \"{}\"", prog.display()),
        );
        std::fs::write(&h.paths.config, text).unwrap();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        let d = h.exec(&r, "say", &["hello"], now);
        assert!(
            refusal(&d).contains("writable by no one else"),
            "{}",
            refusal(&d)
        );
    }

    #[test]
    fn a_config_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let h = Host::new();
        std::fs::set_permissions(&h.paths.config, std::fs::Permissions::from_mode(0o666)).unwrap();
        let now = crate::util::now();
        let cert = h.kit.cert("a", &["say"], "+1h", &[]);
        let r = h.respond(&cert, h.nonce_for(h.uid, now), h.uid, "say", &["hello"]);
        assert!(refusal(&h.exec(&r, "say", &["hello"], now)).contains("writable by no one else"));
    }
}
