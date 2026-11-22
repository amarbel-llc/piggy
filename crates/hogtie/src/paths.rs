//! Where hogtie keeps things. The shipped binary has them compiled in; no
//! flag or environment variable a sudo caller could set moves them. Only a
//! binary built with the `test-harness` feature reads `HOGTIE_TEST_ROOT`.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    /// The configuration file (root-owned).
    pub config: PathBuf,
    /// The runtime directory (root-only, in memory): nonces, scratch, socket.
    pub run: PathBuf,
    /// The log directory (root-only): the audit log.
    pub log: PathBuf,
    /// The uid that must own the configuration and run `exec` and `serve`:
    /// 0, except under the test harness, where it is the test's own.
    pub root_uid: u32,
}

impl Paths {
    pub fn production() -> Self {
        Self {
            config: PathBuf::from("/etc/hogtie/hogtie.toml"),
            run: PathBuf::from("/run/hogtie"),
            log: PathBuf::from("/var/log/hogtie"),
            root_uid: 0,
        }
    }

    /// Everything under `root`, owned by `root_uid`.
    pub fn under(root: &Path, root_uid: u32) -> Self {
        Self {
            config: root.join("etc/hogtie.toml"),
            run: root.join("run"),
            log: root.join("log"),
            root_uid,
        }
    }

    /// The paths this binary uses.
    pub fn for_this_binary() -> Self {
        #[cfg(feature = "test-harness")]
        if let Some(root) = std::env::var_os("HOGTIE_TEST_ROOT") {
            // SAFETY: geteuid cannot fail.
            return Self::under(Path::new(&root), unsafe { libc::geteuid() });
        }
        Self::production()
    }

    pub fn nonces(&self) -> PathBuf {
        self.run.join("nonces")
    }

    pub fn scratch(&self) -> PathBuf {
        self.run.join("scratch")
    }

    pub fn socket(&self) -> PathBuf {
        self.run.join("nonce.sock")
    }

    pub fn audit_log(&self) -> PathBuf {
        self.log.join("audit.log")
    }

    /// Refuse unless this process runs as `root_uid`.
    pub fn check_running_as_root(&self) -> Result<(), String> {
        // SAFETY: geteuid cannot fail.
        let euid = unsafe { libc::geteuid() };
        if euid != self.root_uid {
            return Err(format!(
                "must run as uid {} (through sudo), not {euid}",
                self.root_uid
            ));
        }
        Ok(())
    }

    /// Read a file only if it (after symlinks: on NixOS /etc points into
    /// the store) is owned by `root_uid` and writable by no one else.
    pub fn read_trusted(&self, path: &Path) -> Result<String, String> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.uid() != self.root_uid || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} must be owned by uid {} and writable by no one else",
                path.display(),
                self.root_uid
            ));
        }
        std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Refuse a program to be run as root (an action's, or ssh-keygen)
    /// unless it (after symlinks) is owned by root (or, in tests, by
    /// `root_uid`) and writable by no one else. Its directories are not
    /// checked; in production they are the store's.
    pub fn check_trusted_program(&self, path: &Path) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let owner_ok = meta.uid() == 0 || meta.uid() == self.root_uid;
        if !meta.is_file() || !owner_ok || meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} must be a file owned by root and writable by no one else",
                path.display()
            ));
        }
        Ok(())
    }

    /// Create a root-only directory if it is missing.
    pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt as _;
        match std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(path)
        {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }
}
