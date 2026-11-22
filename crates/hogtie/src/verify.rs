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
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

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

pub struct Verifier<'a> {
    pub ssh_keygen: &'a Path,
    pub cas: &'a [CaKey],
    /// Where the private working directory is made (root-only in production).
    pub scratch: &'a Path,
}

impl Verifier<'_> {
    pub fn verify(&self, message: &[u8], sig: &Sshsig, action: &str) -> Result<(), VerifyError> {
        let io = |e: std::io::Error| VerifyError::Io(e.to_string());
        if self.cas.is_empty() {
            return Err(VerifyError::Io("no CA is configured".into()));
        }
        let dir = PrivateDir::new(self.scratch, "verify").map_err(io)?;
        let allowed: String = self.cas.iter().map(CaKey::allowed_signers_line).collect();
        write_new(&dir.path().join("allowed_signers"), allowed.as_bytes()).map_err(io)?;
        write_new(&dir.path().join("sig"), sig.armor().as_bytes()).map_err(io)?;
        let mut child = Command::new(self.ssh_keygen)
            .env_clear()
            .current_dir(dir.path())
            .args([
                "-Y",
                "verify",
                "-f",
                "allowed_signers",
                "-I",
                action,
                "-n",
                NAMESPACE,
                "-s",
                "sig",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VerifyError::Io(format!("{}: {e}", self.ssh_keygen.display())))?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(message)
            .map_err(io)?;
        let out = child.wait_with_output().map_err(io)?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let good = format!("Good \"{NAMESPACE}\" signature for {action} with ");
        if out.status.success() && stdout.starts_with(&good) {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
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
        }
        .verify(msg, sig, action)
    }

    #[test]
    fn a_good_signature_by_a_granted_key_passes() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["a"], "+1h", &[]), b"the message");
        assert_eq!(verify(&kit, b"the message", &sig, "a"), Ok(()));
    }

    #[test]
    fn another_message_is_refused() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["a"], "+1h", &[]), b"the message");
        assert!(matches!(
            verify(&kit, b"another message", &sig, "a"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn an_expired_grant_is_refused_by_ssh_keygen_too() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["a"], "20200101:20200102", &[]), b"m");
        match verify(&kit, b"m", &sig, "a") {
            Err(VerifyError::Refused(e)) => assert!(e.contains("expired"), "{e}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_action_the_grant_does_not_name_is_refused_by_ssh_keygen_too() {
        let kit = Kit::new();
        let sig = kit.sign(&kit.cert("alice", &["a"], "+1h", &[]), b"m");
        assert!(matches!(
            verify(&kit, b"m", &sig, "b"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn a_copied_grant_used_with_another_key_is_refused() {
        // Bob signs with his own granted key, then swaps Alice's certificate
        // into the sshsig: the signature no longer matches the certified key.
        let kit = Kit::new();
        let alice = kit.cert("alice", &["a"], "+1h", &[]);
        let bob = kit.cert("bob", &["a"], "+1h", &[]);
        let mut sig = kit.sign(&bob, b"m");
        sig.public_key = kit.sign(&alice, b"m").public_key;
        assert!(matches!(
            verify(&kit, b"m", &sig, "a"),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn another_ca_is_refused_by_ssh_keygen_too() {
        let kit = Kit::new();
        let other = Kit::new();
        let sig = other.sign(&other.cert("alice", &["a"], "+1h", &[]), b"m");
        assert!(matches!(
            verify(&kit, b"m", &sig, "a"),
            Err(VerifyError::Refused(_))
        ));
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
