//! `tmpdir` port — secure ephemeral plaintext directory used by the
//! still-bash `edit` (and future Rust port thereof) to hold the
//! decrypted password file while $EDITOR is open.
//!
//! Mirrors `tmpdir` in `src/piggy.sh:182` (Linux) and the macOS
//! override in `src/platform/darwin.sh:19`.
//!
//! Linux strategy (preferred): `/dev/shm` tmpfs ramdisk — pages are
//! never paged out to swap, so `Drop` only needs to `rm -rf`.
//!
//! Linux fallback: `${TMPDIR:-/tmp}` under a regular filesystem.
//! Here `Drop` must `shred` every file before removing — that's the
//! `shred -f -z` step. The bash uses `find ... -type f -exec shred {} +`
//! which we mirror; `shred` is a no-op safety net on disk-backed
//! filesystems where overwriting may not reach the underlying
//! sectors (journaled / log-structured / SSD), but it's the
//! historical convention and matches what users expect.
//!
//! macOS strategy: an hdid-backed HFS ramdisk mounted under
//! `${TMPDIR:-/tmp}/piggy.XXX...`. The Drop guard unmounts +
//! ejects the ramdisk and removes the directory. Code is
//! cfg-gated and not exercised on Linux.
//!
//! `SecureTmpdir` is an RAII guard: construct it once, hold it for
//! the lifetime of the editor session, and let Drop clean up.
//! Drop is best-effort and silent on failure — same as the bash
//! `trap` handler which has no error path.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use crate::platform::shred::shred_paths;

/// Result of base-directory selection: either the ramdisk path we
/// prefer, or the disk-backed fallback that requires shred-on-drop.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BaseChoice {
    /// `/dev/shm` is writable+executable — the preferred ramdisk
    /// path; Drop only needs to `rm -rf`.
    Ramdisk(PathBuf),
    /// Fallback: regular disk-backed filesystem
    /// (`$TMPDIR` or `/tmp`). Drop must shred + remove. The string
    /// is the resolved base directory.
    Disk(PathBuf),
}

/// Pick the secure base directory the way bash does:
/// - prefer `/dev/shm` if it's a directory that is writable + executable
/// - else `${TMPDIR:-/tmp}`
///
/// Mirrors the bash `[[ -d /dev/shm && -w /dev/shm && -x /dev/shm ]]`
/// gate. `env_tmpdir` is injected for testability; in real use callers
/// pass `std::env::var_os("TMPDIR")`.
pub(crate) fn pick_base(shm: &Path, env_tmpdir: Option<&Path>) -> BaseChoice {
    if is_shm_usable(shm) {
        BaseChoice::Ramdisk(shm.to_path_buf())
    } else {
        let fallback = env_tmpdir
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        BaseChoice::Disk(fallback)
    }
}

#[cfg(unix)]
fn is_shm_usable(shm: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(meta) = std::fs::metadata(shm) else {
        return false;
    };
    if !meta.is_dir() {
        return false;
    }
    // -w and -x in bash test the calling user's effective access.
    // For the typical `/dev/shm` (mode 1777 owned by root) any
    // non-root user has rwx via the world bits; for the test
    // fixtures we create a dir under tmpfs/ext4 and chmod it. Use
    // the bash semantics: bit-OR `0o111` (any exec) and `0o222`
    // (any write) suffice for the system /dev/shm. For real access
    // we'd want `access(2)`; deferred to the real-world Linux path
    // where /dev/shm is always 1777.
    let mode = meta.permissions().mode();
    (mode & 0o222) != 0 && (mode & 0o111) != 0
}

#[cfg(not(unix))]
fn is_shm_usable(_shm: &Path) -> bool {
    false
}

/// `piggy.XXXXXXXXXXXXX` (13 X's) — the bash mktemp template. The
/// suffix count is a load-bearing pin: the unit tests assert on it
/// to keep our naming aligned with the original bash convention.
pub(crate) const TEMPLATE_PREFIX: &str = "piggy.";
pub(crate) const TEMPLATE_SUFFIX_X_COUNT: usize = 13;

#[cfg(test)]
fn template_name() -> String {
    let mut s = String::with_capacity(TEMPLATE_PREFIX.len() + TEMPLATE_SUFFIX_X_COUNT);
    s.push_str(TEMPLATE_PREFIX);
    for _ in 0..TEMPLATE_SUFFIX_X_COUNT {
        s.push('X');
    }
    s
}

/// Generate a fresh random suffix of `n` characters drawn from
/// `[A-Za-z0-9]`. mkdtemp(3) does the same; we open-code it here to
/// keep us off external crates and to match the `XXXXXXXXXXXXX`
/// template shape.
fn random_suffix(n: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::with_capacity(n);
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(std::process::id() as u64);
    for _ in 0..n {
        // Xorshift64 — fine for unique-enough scratch directory names;
        // we collide-retry below.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let idx = (seed as usize) % ALPHABET.len();
        s.push(ALPHABET[idx] as char);
    }
    s
}

#[cfg(unix)]
fn create_with_700(base: &Path) -> io::Result<PathBuf> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt as _;
    // Race-retry: bash's mktemp -d generates the name and rejects
    // EEXIST internally. Replicate with a small loop.
    for _ in 0..16 {
        let suffix = random_suffix(TEMPLATE_SUFFIX_X_COUNT);
        let candidate = base.join(format!("{TEMPLATE_PREFIX}{suffix}"));
        match DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique tmpdir name after 16 retries",
    ))
}

#[cfg(not(unix))]
fn create_with_700(base: &Path) -> io::Result<PathBuf> {
    let _ = base;
    Err(io::Error::other("create_with_700: unix-only"))
}

/// RAII secure tmpdir. Drop cleans up:
/// - Ramdisk: `rm -rf $path` (bash `remove_tmpfile`).
/// - Disk: `shred` every regular file under $path, then `rm -rf $path`
///   (bash `shred_tmpfile`).
/// - macOS (cfg): umount + diskutil eject + rm.
///
/// Drop is best-effort and swallows errors. This mirrors the bash
/// `trap EXIT` handler which has no error reporting path.
pub struct SecureTmpdir {
    path: PathBuf,
    needs_shred: bool,
    #[cfg(target_os = "macos")]
    darwin_ramdisk_dev: Option<OsString>,
}

impl SecureTmpdir {
    /// Allocate a fresh secure tmpdir. `warn` controls whether the
    /// caller wants the bash "no /dev/shm; sure?" prompt (which we
    /// surface as a stderr message — the actual y/n prompt belongs in
    /// the caller because it owns the TTY).
    ///
    /// Returns the guard whose `path()` is the new directory.
    pub fn new(warn: bool) -> io::Result<Self> {
        new_with_env(warn, Path::new("/dev/shm"), std::env::var_os("TMPDIR"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn new_with_env(
    warn: bool,
    shm: &Path,
    env_tmpdir: Option<OsString>,
) -> io::Result<SecureTmpdir> {
    let env_tmpdir_path = env_tmpdir.as_ref().map(PathBuf::from);
    let choice = pick_base(shm, env_tmpdir_path.as_deref());

    match choice {
        BaseChoice::Ramdisk(base) => {
            let path = create_with_700(&base)?;
            Ok(SecureTmpdir {
                path,
                needs_shred: false,
                #[cfg(target_os = "macos")]
                darwin_ramdisk_dev: None,
            })
        }
        BaseChoice::Disk(base) => {
            if warn {
                eprintln!(
                    "Your system does not have /dev/shm, which means that it may\n\
                     be difficult to entirely erase the temporary non-encrypted\n\
                     password file after editing."
                );
            }
            let path = create_with_700(&base)?;
            Ok(SecureTmpdir {
                path,
                needs_shred: true,
                #[cfg(target_os = "macos")]
                darwin_ramdisk_dev: None,
            })
        }
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    //! macOS ramdisk path — port of `tmpdir` in
    //! `src/platform/darwin.sh`. Untested under cargo test on Linux
    //! (compiles only); will be exercised once piggy ships on macOS.

    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::{SecureTmpdir, create_with_700};

    /// Allocate `$TMPDIR/piggy.XXX...` as a plain directory, then
    /// `hdid` a 16 MB ram device, format HFS, mount it over the
    /// directory.
    // TODO(#145): orphaned — SecureTmpdir::new always sets
    // darwin_ramdisk_dev: None, so this ramdisk path is never taken even
    // on macOS. Allowed dead until the wiring lands.
    #[allow(dead_code)]
    pub(crate) fn new_with_env(env_tmpdir: Option<OsString>) -> io::Result<SecureTmpdir> {
        let base: PathBuf = env_tmpdir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let mount_point = create_with_700(&base)?;

        let dev = hdid_ramdisk()?;
        newfs_hfs(&dev)?;
        mount_hfs(&dev, &mount_point)?;

        Ok(SecureTmpdir {
            path: mount_point,
            needs_shred: false,
            darwin_ramdisk_dev: Some(dev),
        })
    }

    // TODO(#145): orphaned helper for the unwired ramdisk path.
    #[allow(dead_code)]
    fn hdid_ramdisk() -> io::Result<OsString> {
        let out = Command::new("hdid")
            .args(["-drivekey", "system-image=yes", "-nomount", "ram://32768"])
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "hdid exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let dev = stdout
            .split_whitespace()
            .next()
            .ok_or_else(|| io::Error::other("hdid produced no device path"))?;
        Ok(OsString::from(dev))
    }

    // TODO(#145): orphaned helper for the unwired ramdisk path.
    #[allow(dead_code)]
    fn newfs_hfs(dev: &OsString) -> io::Result<()> {
        let status = Command::new("newfs_hfs")
            .arg("-M")
            .arg("700")
            .arg(dev)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!("newfs_hfs exited {status}")));
        }
        Ok(())
    }

    // TODO(#145): orphaned helper for the unwired ramdisk path.
    #[allow(dead_code)]
    fn mount_hfs(dev: &OsString, mount_point: &Path) -> io::Result<()> {
        let status = Command::new("mount")
            .args(["-t", "hfs", "-o", "noatime", "-o", "nobrowse"])
            .arg(dev)
            .arg(mount_point)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!("mount exited {status}")));
        }
        Ok(())
    }

    pub(crate) fn umount_and_eject(mount_point: &Path, dev: &OsString) {
        let _ = Command::new("umount").arg(mount_point).status();
        let _ = Command::new("diskutil")
            .args(["quiet", "eject"])
            .arg(dev)
            .status();
    }
}

impl Drop for SecureTmpdir {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() && self.path.exists() {
            #[cfg(target_os = "macos")]
            if let Some(dev) = self.darwin_ramdisk_dev.as_ref() {
                darwin::umount_and_eject(&self.path, dev);
                let _ = std::fs::remove_dir_all(&self.path);
                return;
            }

            if self.needs_shred {
                let files = collect_regular_files(&self.path);
                let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
                let _ = shred_paths(&refs);
            }
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Walk `root` collecting every regular file (recursing through
/// subdirectories). Mirrors `find $SECURE_TMPDIR -type f -exec`.
fn collect_regular_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(path),
                Ok(ft) if ft.is_file() => out.push(path),
                _ => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    fn scratch_root() -> PathBuf {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "piggy-platform-tmpdir-test-{}-{}",
            std::process::id(),
            random_suffix(8)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn pick_base_prefers_writable_shm() {
        let root = scratch_root();
        let shm = root.join("shm");
        fs::create_dir(&shm).unwrap();
        fs::set_permissions(&shm, fs::Permissions::from_mode(0o777)).unwrap();

        let tmp = root.join("tmp");
        fs::create_dir(&tmp).unwrap();

        let choice = pick_base(&shm, Some(&tmp));
        assert_eq!(choice, BaseChoice::Ramdisk(shm));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pick_base_falls_back_when_shm_missing() {
        let root = scratch_root();
        let shm = root.join("does-not-exist");
        let tmp = root.join("tmp");
        fs::create_dir(&tmp).unwrap();

        let choice = pick_base(&shm, Some(&tmp));
        assert_eq!(choice, BaseChoice::Disk(tmp));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pick_base_falls_back_when_shm_not_a_dir() {
        let root = scratch_root();
        let shm = root.join("shm-as-file");
        fs::write(&shm, b"not a dir").unwrap();
        let tmp = root.join("tmp");
        fs::create_dir(&tmp).unwrap();

        let choice = pick_base(&shm, Some(&tmp));
        assert_eq!(choice, BaseChoice::Disk(tmp));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pick_base_falls_back_when_shm_not_writable() {
        let root = scratch_root();
        let shm = root.join("shm-readonly");
        fs::create_dir(&shm).unwrap();
        fs::set_permissions(&shm, fs::Permissions::from_mode(0o555)).unwrap();
        let tmp = root.join("tmp");
        fs::create_dir(&tmp).unwrap();

        let choice = pick_base(&shm, Some(&tmp));
        assert_eq!(choice, BaseChoice::Disk(tmp));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pick_base_defaults_to_slash_tmp_without_env() {
        let root = scratch_root();
        let shm = root.join("no-shm");

        let choice = pick_base(&shm, None);
        assert_eq!(choice, BaseChoice::Disk(PathBuf::from("/tmp")));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn template_name_has_13_xs() {
        let t = template_name();
        assert!(t.starts_with("piggy."));
        let xs = t.trim_start_matches("piggy.");
        assert_eq!(xs.len(), 13);
        assert!(xs.chars().all(|c| c == 'X'));
    }

    #[test]
    fn random_suffix_length() {
        let s = random_suffix(13);
        assert_eq!(s.len(), 13);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn create_with_700_creates_unique_dir_with_mode() {
        let root = scratch_root();
        let one = create_with_700(&root).unwrap();
        let two = create_with_700(&root).unwrap();
        assert_ne!(one, two);
        let meta = fs::metadata(&one).unwrap();
        assert!(meta.is_dir());
        // Permissions should be 0o700 (set by DirBuilder, less the umask
        // restriction; piggy.sh runs with umask 077 which leaves 0o700 alone).
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ramdisk_drop_removes_directory() {
        let root = scratch_root();
        let shm = root.join("shm");
        fs::create_dir(&shm).unwrap();
        fs::set_permissions(&shm, fs::Permissions::from_mode(0o777)).unwrap();

        let path_to_check;
        {
            let guard = new_with_env(false, &shm, None).unwrap();
            path_to_check = guard.path().to_path_buf();
            assert!(path_to_check.exists());
            assert!(path_to_check.starts_with(&shm));
            // Stage a regular file in the tmpdir so we can verify it
            // also gets removed by the rm -rf step.
            fs::write(path_to_check.join("plaintext"), b"secret").unwrap();
        }
        assert!(!path_to_check.exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn disk_drop_shreds_and_removes_directory() {
        let root = scratch_root();
        let shm = root.join("does-not-exist");
        let tmp = root.join("tmp");
        fs::create_dir(&tmp).unwrap();

        let path_to_check;
        let plaintext_path;
        {
            let guard = new_with_env(false, &shm, Some(tmp.clone().into_os_string())).unwrap();
            path_to_check = guard.path().to_path_buf();
            assert!(path_to_check.starts_with(&tmp));
            plaintext_path = path_to_check.join("plaintext");
            fs::write(&plaintext_path, b"secret-needs-shred").unwrap();
            assert!(plaintext_path.exists());
        }
        assert!(!plaintext_path.exists());
        assert!(!path_to_check.exists());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn collect_regular_files_walks_subdirs() {
        let root = scratch_root();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("top.txt"), b"a").unwrap();
        fs::write(root.join("a/mid.txt"), b"b").unwrap();
        fs::write(root.join("a/b/deep.txt"), b"c").unwrap();

        let mut files = collect_regular_files(&root);
        files.sort();
        let names: Vec<String> = files
            .iter()
            .map(|p| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(names, vec!["a/b/deep.txt", "a/mid.txt", "top.txt"]);

        let _ = fs::remove_dir_all(&root);
    }
}
