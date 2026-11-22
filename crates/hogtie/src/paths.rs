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

    /// Each account's refusal budget (audit::admit_refusal).
    pub fn refusals(&self) -> PathBuf {
        self.run.join("refusals")
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

    /// A root-only directory (mode 0700), made if missing, checked if not.
    pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
        ensure_dir(path, 0o700)
    }
}

/// Make `path` a directory with exactly `mode`, or, if something is already
/// there, check it rather than trust it (review finding 7): a real directory
/// (not a symlink), owned by this process's euid (root in production), and
/// granting no permission beyond `mode`.
pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => return std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    check_dir(path, mode)
}

/// Refuse unless `path` is on a tmpfs (emptied by a reboot).
pub fn check_tmpfs(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{}: a NUL in the path", path.display()))?;
    // SAFETY: statfs writes one struct into `st`.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(format!(
            "{}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    if st.f_type as i64 != TMPFS_MAGIC {
        return Err(format!(
            "{} is not on a tmpfs: nonces must not survive a reboot",
            path.display()
        ));
    }
    Ok(())
}

/// Check, without making it, that `path` is what [`ensure_dir`] makes.
pub fn check_dir(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o777 & !mode != 0 {
        return Err(io::Error::other(format!(
            "{} must be a directory owned by uid {euid} with no permission beyond {mode:o}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PrivateDir;

    #[test]
    fn an_existing_directory_is_checked_not_trusted() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-dirs").unwrap();
        let fresh = d.path().join("fresh");
        assert!(ensure_dir(&fresh, 0o700).is_ok());
        assert!(ensure_dir(&fresh, 0o700).is_ok(), "existing and right");
        let open = d.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_dir(&open, 0o700).is_err(), "open to others");
        assert!(ensure_dir(&open, 0o711).is_err(), "writable by others");
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&fresh, &link).unwrap();
        assert!(ensure_dir(&link, 0o700).is_err(), "a symlink");
        let file = d.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(ensure_dir(&file, 0o700).is_err(), "a file");
    }

    fn me() -> u32 {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Paths whose "root" is someone other than this test (and not 0).
    fn someone_else(dir: &Path) -> Paths {
        Paths::under(dir, me() + 1)
    }

    #[test]
    fn a_file_owned_by_someone_other_than_root_is_not_trusted() {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-paths").unwrap();
        let f = d.path().join("hogtie.toml");
        crate::testkit::write_trusted(&f, "x");
        assert!(Paths::under(d.path(), me()).read_trusted(&f).is_ok());
        assert!(
            someone_else(d.path())
                .read_trusted(&f)
                .unwrap_err()
                .contains("owned by uid")
        );
    }

    #[test]
    fn a_program_owned_by_someone_other_than_root_or_a_directory_is_not_trusted() {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-paths").unwrap();
        let f = d.path().join("prog");
        crate::testkit::write_trusted(&f, "x");
        assert!(
            Paths::under(d.path(), me())
                .check_trusted_program(&f)
                .is_ok()
        );
        assert!(someone_else(d.path()).check_trusted_program(&f).is_err());
        assert!(
            Paths::under(d.path(), me())
                .check_trusted_program(d.path())
                .is_err(),
            "a directory"
        );
        let store = std::path::PathBuf::from(crate::testkit::on_path("sh"));
        if std::fs::metadata(&store)
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
            .ok()
            == Some(0)
        {
            assert!(
                someone_else(d.path()).check_trusted_program(&store).is_ok(),
                "root's own program"
            );
        }
    }

    #[test]
    fn running_as_another_uid_is_refused() {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-paths").unwrap();
        assert!(Paths::under(d.path(), me()).check_running_as_root().is_ok());
        assert!(
            someone_else(d.path())
                .check_running_as_root()
                .unwrap_err()
                .contains("must run as uid")
        );
    }
}
