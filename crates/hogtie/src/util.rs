//! Small system helpers shared by the modules.

use std::io;
use std::path::{Path, PathBuf};

/// `n` bytes from the kernel's CSPRNG (getrandom(2), blocking until the
/// pool is initialised).
pub fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    let mut filled = 0;
    while filled < N {
        // SAFETY: the pointer and length describe the unfilled tail of `out`.
        let n = unsafe { libc::getrandom(out[filled..].as_mut_ptr().cast(), N - filled, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        filled += n as usize;
    }
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seconds since boot, CLOCK_BOOTTIME: it counts suspend and cannot be
/// set, so a clock set backwards does not lengthen a nonce's life. The
/// nonce store is in /run, which a reboot empties, so boot seconds never
/// cross a boot. An error if the clock cannot be read: a zero here would
/// make every nonce look fresh (review N5).
pub fn boot_now() -> io::Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec into `ts`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64)
}

/// The two clocks a decision reads: wall time for grants (a certificate's
/// validity is wall time by definition) and boot time for nonce life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    pub wall: u64,
    pub boot: u64,
}

impl Clock {
    pub fn now() -> io::Result<Self> {
        Ok(Self {
            wall: now(),
            boot: boot_now()?,
        })
    }
}

/// A fresh directory, mode 0700, under `parent`, removed when dropped.
pub struct PrivateDir(PathBuf);

impl PrivateDir {
    pub fn new(parent: &Path, prefix: &str) -> io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt as _;
        let name = format!("{prefix}-{}", hex(&random_bytes::<8>()?));
        let path = parent.join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write a new file (it must not exist) with mode 0600.
pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
