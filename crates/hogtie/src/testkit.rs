//! A software CA and granted keys made with stock ssh-keygen, for tests.
//! Built for unit tests and for the `test-harness` feature (the binary
//! tests use it); never in the shipped binary.

use crate::message::NAMESPACE;
use crate::sshwire::{Sshsig, dearmor};
use crate::util::PrivateDir;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Kit {
    dir: PrivateDir,
    pub ssh_keygen: PathBuf,
    counter: Cell<u32>,
}

/// `ssh-keygen` from PATH.
pub fn find_ssh_keygen() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|d| d.join("ssh-keygen"))
        .find(|p| p.is_file())
        .expect("ssh-keygen on PATH (openssh)")
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("run ssh-keygen");
    assert!(
        out.status.success(),
        "{cmd:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

impl Kit {
    pub fn new() -> Self {
        let dir = PrivateDir::new(&std::env::temp_dir(), "hogtie-kit").expect("kit dir");
        let kit = Self {
            dir,
            ssh_keygen: find_ssh_keygen(),
            counter: Cell::new(0),
        };
        kit.keygen(&["-t", "ecdsa", "-b", "256", "-f", "ca", "-C", "ca"]);
        kit.keygen(&["-t", "ed25519", "-f", "plain", "-C", "plain"]);
        kit
    }

    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    fn keygen(&self, args: &[&str]) {
        run(Command::new(&self.ssh_keygen)
            .current_dir(self.dir())
            .args(["-q", "-N", ""])
            .args(args));
    }

    /// `TYPE BASE64` of the CA's public key.
    pub fn ca_line(&self) -> String {
        let text = std::fs::read_to_string(self.dir().join("ca.pub")).unwrap();
        text.split_ascii_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn ca_blob(&self) -> Vec<u8> {
        use base64::Engine as _;
        let line = self.ca_line();
        let b64 = line.split_once(' ').unwrap().1;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    }

    /// A fresh ed25519 key and a certificate for it signed by this kit's CA.
    /// `validity` is ssh-keygen's `-V`; `extra` goes before the key path
    /// (`-h` for a host certificate, `-O ...`). Returns the `-cert.pub` path.
    pub fn cert(
        &self,
        key_id: &str,
        principals: &[&str],
        validity: &str,
        extra: &[&str],
    ) -> PathBuf {
        let n = self.counter.get() + 1;
        self.counter.set(n);
        let key = format!("k{n}");
        self.keygen(&["-t", "ed25519", "-f", &key, "-C", &key]);
        let principals = principals.join(",");
        let mut cmd = Command::new(&self.ssh_keygen);
        cmd.current_dir(self.dir())
            .args([
                "-q",
                "-s",
                "ca",
                "-I",
                key_id,
                "-n",
                &principals,
                "-V",
                validity,
            ])
            .args(extra)
            .arg(format!("{key}.pub"));
        run(&mut cmd);
        self.dir().join(format!("{key}-cert.pub"))
    }

    /// `ssh-keygen -Y sign -f CERT -n hogtie-v1` over `msg`.
    pub fn sign(&self, cert: &Path, msg: &[u8]) -> Sshsig {
        self.sign_with(cert, msg)
    }

    /// A signature by a plain key with no certificate.
    pub fn sign_plain(&self, msg: &[u8]) -> Sshsig {
        self.sign_with(&self.dir().join("plain"), msg)
    }

    fn sign_with(&self, key: &Path, msg: &[u8]) -> Sshsig {
        let n = self.counter.get() + 1;
        self.counter.set(n);
        let file = self.dir().join(format!("msg{n}"));
        std::fs::write(&file, msg).unwrap();
        run(Command::new(&self.ssh_keygen)
            .current_dir(self.dir())
            .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
            .arg(key)
            .arg(&file));
        let armored = std::fs::read_to_string(file.with_file_name(format!("msg{n}.sig"))).unwrap();
        Sshsig::parse(&dearmor(&armored).expect("armored sshsig")).expect("sshsig")
    }
}

impl Default for Kit {
    fn default() -> Self {
        Self::new()
    }
}
