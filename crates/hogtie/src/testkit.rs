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

/// The absolute path of `name` on PATH.
pub fn on_path(name: &str) -> String {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("{name} on PATH"))
        .to_string_lossy()
        .into_owned()
}

/// Write a configuration file mode 0644 whatever the umask, so hogtie's
/// "writable by no one else" check sees what production would.
pub fn write_trusted(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
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

/// A copy of `name` from PATH in `dir`, mode 0755, owned by the test: what
/// hogtie's "owned by root" check accepts under the test harness however a
/// build sandbox maps the store's owner (piggy-rs shows it as not root).
///
/// The copy is written by a `cp` child, not by this process: a file this
/// multi-threaded test process held open for writing could be inherited by
/// another thread's fork, and exec of the copy would fail with ETXTBSY.
pub fn trusted_copy(dir: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    // Kept under its own name: coreutils is one binary that dispatches on
    // argv[0], so `bin-echo` would not be echo.
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let to = bin.join(name);
    if !to.exists() {
        let tmp = bin.join(format!(".{name}.{}", std::process::id()));
        let st = Command::new(on_path("cp"))
            .arg(on_path(name))
            .arg(&tmp)
            .status()
            .expect("run cp");
        assert!(st.success(), "cp {name}");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp, &to).unwrap();
    }
    to
}

impl Kit {
    pub fn new() -> Self {
        let dir = PrivateDir::new(&std::env::temp_dir(), "hogtie-kit").expect("kit dir");
        let ssh_keygen = trusted_copy(dir.path(), "ssh-keygen");
        let kit = Self {
            dir,
            ssh_keygen,
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

    /// A signature by a plain key with no certificate.
    pub fn sign_plain(&self, msg: &[u8]) -> Sshsig {
        self.sign(&self.dir().join("plain"), msg)
    }

    /// `ssh-keygen -Y sign -f KEY -n hogtie-v1` over `msg`; `key` is a
    /// `-cert.pub` (the sshsig embeds the certificate) or a private key.
    pub fn sign(&self, key: &Path, msg: &[u8]) -> Sshsig {
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
