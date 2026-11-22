//! The signature check, by ssh-keygen: `ssh-keygen -Y verify` against an
//! allowed-signers file hogtie writes from its configuration, one line per
//! CA: `* cert-authority,namespaces="hogtie-v1" <CA key>`. ssh-keygen runs
//! by its absolute configured path, with an empty environment, in a fresh
//! 0700 directory under hogtie's own runtime directory, with no `-O`
//! option (a `verify-time` would defeat expiry). It is asked for the action
//! as the principal (`-I`), so it checks the certificate names it too.

use crate::message::NAMESPACE;
use crate::sshwire::{Reader, Sshsig};
use crate::util::{PrivateDir, write_new};
use std::fmt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A configured CA public key, `TYPE BASE64 [comment]` as in a `.pub` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaKey {
    pub key_type: String,
    pub base64: String,
    pub blob: Vec<u8>,
}

impl CaKey {
    pub fn parse(line: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let mut parts = line.split_ascii_whitespace();
        let key_type = parts.next().ok_or("empty CA key")?.to_string();
        let b64 = parts
            .next()
            .ok_or("CA key has no base64 field")?
            .to_string();
        if !key_type
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"@.-".contains(&c))
        {
            return Err(format!(
                "CA key type {key_type:?} has unexpected characters"
            ));
        }
        let blob = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|_| "CA key base64 does not decode".to_string())?;
        let inner = Reader(&blob)
            .text()
            .map_err(|_| "CA key blob does not start with its type".to_string())?;
        if inner != key_type {
            return Err(format!(
                "CA key says {key_type:?} but its blob is {inner:?}"
            ));
        }
        if key_type.contains("-cert-") {
            return Err("a CA key must be a plain key, not a certificate".into());
        }
        // ssh-rsa may verify with SHA-1 and DSA is broken: pin the CA to EC
        // types (the card's slot is P-256; tests use ecdsa too).
        const CA_TYPES: [&str; 4] = [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ];
        if !CA_TYPES.contains(&key_type.as_str()) {
            return Err(format!(
                "CA key type {key_type:?}: must be ssh-ed25519 or ecdsa-sha2-nistp256/384/521"
            ));
        }
        Ok(Self {
            key_type,
            base64: b64,
            blob,
        })
    }

    fn allowed_signers_line(&self) -> String {
        format!(
            "* cert-authority,namespaces=\"{NAMESPACE}\" {} {}\n",
            self.key_type, self.base64
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// hogtie could not run the check (its own fault, not the caller's).
    Io(String),
    /// ssh-keygen refused; its first line of output.
    Refused(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Io(e) => write!(f, "cannot run the signature check: {e}"),
            VerifyError::Refused(e) => write!(f, "signature refused: {e}"),
        }
    }
}

/// How long ssh-keygen may take before it is killed (review finding 8).
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// A verify directory older than this is a leftover of a killed `exec`
/// (review finding 6); the socket's sweep removes it.
pub const SCRATCH_MAX_AGE: Duration = Duration::from_secs(300);

pub struct Verifier<'a> {
    pub ssh_keygen: &'a Path,
    pub cas: &'a [CaKey],
    /// Where the private working directory is made (root-only in production).
    pub scratch: &'a Path,
    pub timeout: Duration,
}

/// Remove `verify-*` directories under `scratch` older than `max_age`.
pub fn sweep_scratch(scratch: &Path, max_age: Duration) -> std::io::Result<()> {
    let now = std::time::SystemTime::now();
    for e in std::fs::read_dir(scratch)? {
        let Ok(e) = e else { continue };
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > max_age);
        if old && e.file_name().to_string_lossy().starts_with("verify-") {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    Ok(())
}

impl Verifier<'_> {
    /// Verify `sig` over `message` for `principal` (`<host>:<action>`).
    pub fn verify(&self, message: &[u8], sig: &Sshsig, principal: &str) -> Result<(), VerifyError> {
        let io = |e: std::io::Error| VerifyError::Io(e.to_string());
        if self.cas.is_empty() {
            return Err(VerifyError::Io("no CA is configured".into()));
        }
        let dir = PrivateDir::new(self.scratch, "verify").map_err(io)?;
        let allowed: String = self.cas.iter().map(CaKey::allowed_signers_line).collect();
        write_new(&dir.path().join("allowed_signers"), allowed.as_bytes()).map_err(io)?;
        write_new(&dir.path().join("sig"), sig.armor().as_bytes()).map_err(io)?;
        // Files, not pipes: nothing to block on, so the deadline below is
        // the only wait.
        write_new(&dir.path().join("msg"), message).map_err(io)?;
        let file = |name: &str, create: bool| {
            let p = dir.path().join(name);
            if create {
                std::fs::File::create(p)
            } else {
                std::fs::File::open(p)
            }
            .map_err(io)
        };
        let mut child = Command::new(self.ssh_keygen)
            .env_clear()
            .current_dir(dir.path())
            .args([
                "-Y",
                "verify",
                "-f",
                "allowed_signers",
                "-I",
                principal,
                "-n",
                NAMESPACE,
                "-s",
                "sig",
            ])
            .stdin(Stdio::from(file("msg", false)?))
            .stdout(Stdio::from(file("out", true)?))
            .stderr(Stdio::from(file("err", true)?))
            .spawn()
            .map_err(|e| VerifyError::Io(format!("{}: {e}", self.ssh_keygen.display())))?;
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(st) = child.try_wait().map_err(io)? {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(VerifyError::Io(format!(
                    "ssh-keygen timed out after {:?}",
                    self.timeout
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let read = |name: &str| std::fs::read(dir.path().join(name)).unwrap_or_default();
        let (out, err) = (read("out"), read("err"));
        let stdout = String::from_utf8_lossy(&out);
        let good = format!("Good \"{NAMESPACE}\" signature for {principal} with ");
        if status.success() && stdout.starts_with(&good) {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&err);
        let first = stderr
            .lines()
            .chain(stdout.lines())
            .find(|l| !l.trim().is_empty())
            .unwrap_or("no output")
            .to_string();
        Err(VerifyError::Refused(first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::Kit;

    fn verify(kit: &Kit, msg: &[u8], sig: &Sshsig, action: &str) -> Result<(), VerifyError> {
        let cas = [CaKey::parse(&kit.ca_line()).unwrap()];
        Verifier {
            ssh_keygen: &kit.ssh_keygen,
            cas: &cas,
            scratch: kit.dir(),
            timeout: VERIFY_TIMEOUT,
        }
        .verify(msg, sig, action)
    }

    #[test]
    fn a_good_signature_by_a_granted_key_passes() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"the message");
        assert_eq!(verify(&kit, b"the message", &sig, "h1:a"), Ok(()));
    }

    #[test]
    fn another_message_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"the message");
        assert!(matches!(
            verify(&kit, b"another message", &sig, "h1:a"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn an_expired_grant_is_refused_by_ssh_keygen_too() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "20200101:20200102", &[]), b"m");
        match verify(&kit, b"m", &sig, "h1:a") {
            Err(VerifyError::Refused(e)) => assert!(e.contains("expired"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_action_the_grant_does_not_name_is_refused_by_ssh_keygen_too() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        assert!(matches!(
            verify(&kit, b"m", &sig, "h1:b"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn a_grant_for_this_host_is_refused_by_ssh_keygen_for_another() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        assert!(matches!(
            verify(&kit, b"m", &sig, "h2:a"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn a_copied_grant_used_with_another_key_is_refused() {
        // Bob signs with his own granted key, then swaps Alice's certificate
        // into the sshsig: the signature no longer matches the certified key.
        let kit = Kit::new();
        let alice = kit.grant("alice", &["a"], "+1h", &[]);
        let bob = kit.grant("bob", &["a"], "+1h", &[]);
        let mut sig = kit.sign(&bob, b"m");
        sig.public_key = kit.sign(&alice, b"m").public_key;
        assert!(matches!(
            verify(&kit, b"m", &sig, "h1:a"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn another_ca_is_refused_by_ssh_keygen_too() {
        let kit = Kit::new();
        let other = Kit::new();
        let sig = other.sign(&other.grant("alice", &["a"], "+1h", &[]), b"m");
        assert!(matches!(
            verify(&kit, b"m", &sig, "h1:a"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn ssh_keygen_runs_with_an_empty_environment_and_exactly_these_arguments() {
        let kit = Kit::new();
        let spy = kit.dir().join("spy-keygen");
        let script = format!(
            "#!/bin/sh\n{} > \"$0.env\"\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$0.args\"\nexit 1\n",
            crate::testkit::on_path("env")
        );
        crate::testkit::write_script(&spy, &script);
        // SAFETY: a variable no other test reads; set before the spawn.
        unsafe { std::env::set_var("HOGTIE_SPY_SENTINEL", "leaked") };
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        let cas = [CaKey::parse(&kit.ca_line()).unwrap()];
        let r = Verifier {
            ssh_keygen: &spy,
            cas: &cas,
            scratch: kit.dir(),
            timeout: VERIFY_TIMEOUT,
        }
        .verify(b"m", &sig, "h1:a");
        assert!(matches!(r, Err(VerifyError::Refused(_))), "{r:?}");
        let env = std::fs::read_to_string(kit.dir().join("spy-keygen.env")).unwrap();
        assert!(
            !env.contains("HOGTIE_SPY_SENTINEL"),
            "the environment leaked: {env}"
        );
        assert!(!env.contains("PATH="), "the environment leaked: {env}");
        let args = std::fs::read_to_string(kit.dir().join("spy-keygen.args")).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            [
                "-Y",
                "verify",
                "-f",
                "allowed_signers",
                "-I",
                "h1:a",
                "-n",
                "hogtie-v1",
                "-s",
                "sig"
            ],
            "no -O option, nothing else"
        );
    }

    #[test]
    fn a_hung_ssh_keygen_is_killed_and_reported_as_hogtie_own_failure() {
        let kit = Kit::new();
        let spy = kit.dir().join("slow-keygen");
        let sleep = crate::testkit::on_path("sleep");
        crate::testkit::write_script(&spy, &format!("#!/bin/sh\nexec {sleep} 30\n"));
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        let cas = [CaKey::parse(&kit.ca_line()).unwrap()];
        let start = std::time::Instant::now();
        let r = Verifier {
            ssh_keygen: &spy,
            cas: &cas,
            scratch: kit.dir(),
            timeout: std::time::Duration::from_millis(500),
        }
        .verify(b"m", &sig, "h1:a");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "it waited {:?}",
            start.elapsed()
        );
        assert!(
            matches!(&r, Err(VerifyError::Io(e)) if e.contains("timed out")),
            "{r:?}"
        );
    }

    #[test]
    fn the_scratch_sweep_removes_only_old_verify_directories() {
        let kit = Kit::new();
        let scratch = kit.dir().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        for name in ["verify-old", "verify-new", "other-old"] {
            std::fs::create_dir(scratch.join(name)).unwrap();
        }
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(3600);
        for name in ["verify-old", "other-old"] {
            std::fs::File::open(scratch.join(name))
                .unwrap()
                .set_modified(long_ago)
                .unwrap();
        }
        sweep_scratch(&scratch, SCRATCH_MAX_AGE).unwrap();
        assert!(!scratch.join("verify-old").exists());
        assert!(
            scratch.join("verify-new").exists(),
            "a verify in flight is kept"
        );
        assert!(
            scratch.join("other-old").exists(),
            "only verify directories"
        );
    }

    #[test]
    fn a_zero_exit_without_the_good_line_is_refused() {
        let kit = Kit::new();
        let spy = kit.dir().join("quiet-keygen");
        crate::testkit::write_script(
            &spy,
            "#!/bin/sh\necho 'Good \"hogtie-v1\" signature for other with x'\nexit 0\n",
        );
        let sig = kit.sign(&kit.grant("alice", &["a"], "+1h", &[]), b"m");
        let cas = [CaKey::parse(&kit.ca_line()).unwrap()];
        let r = Verifier {
            ssh_keygen: &spy,
            cas: &cas,
            scratch: kit.dir(),
            timeout: VERIFY_TIMEOUT,
        }
        .verify(b"m", &sig, "h1:a");
        assert!(matches!(r, Err(VerifyError::Refused(_))), "{r:?}");
    }

    #[test]
    fn a_ca_key_line_is_checked() {
        let kit = Kit::new();
        assert!(CaKey::parse(&kit.ca_line()).is_ok());
        assert!(CaKey::parse("").is_err());
        assert!(CaKey::parse("ssh-ed25519").is_err());
        assert!(CaKey::parse("ssh-ed25519 !!!").is_err());
        let (_, b64) = kit
            .ca_line()
            .split_once(' ')
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap();
        assert!(
            CaKey::parse(&format!("ssh-ed25519 {b64}")).is_err(),
            "type must match the blob"
        );
        assert!(CaKey::parse(&format!("cert-authority,x {b64}")).is_err());
    }
}
