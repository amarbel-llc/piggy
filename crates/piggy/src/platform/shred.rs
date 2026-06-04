//! `shred` port — overwrite-and-remove a regular file.
//!
//! Bash defaults (`src/piggy.sh:213`):
//! ```sh
//! SHRED="shred -f -z"        # Linux: POSIX shred
//! ```
//!
//! macOS override (`src/platform/darwin.sh:59`):
//! ```sh
//! SHRED="srm -f -z"          # macOS: legacy srm
//! ```
//!
//! `shred -f` forces a chmod when needed; `-z` final-overwrites with
//! zeros so a curious bystander only sees a zero-block file before
//! `rm` unlinks it. `srm -f` corresponds. Neither `-z` nor `srm -f`
//! has a perfectly faithful no-op fallback on systems that lack the
//! binary, so we treat absence of the tool as "warn and fall through
//! to plain remove" — same shape as the bash, which would silently
//! fail the `shred` invocation and rely on the subsequent `rm -rf`.

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::process::Command;

/// Name + initial-args the bash uses. Returned as a slice so the
/// caller can extend with paths.
pub(crate) fn shred_argv() -> (&'static str, &'static [&'static str]) {
    #[cfg(target_os = "macos")]
    {
        ("srm", &["-f", "-z"])
    }
    #[cfg(not(target_os = "macos"))]
    {
        ("shred", &["-f", "-z"])
    }
}

/// Run `shred -f -z $paths...` (or the macOS `srm` equivalent).
///
/// Errors propagate from spawning the shred binary. A non-zero exit
/// from shred itself is reported as `io::Error::other`. Callers in
/// `Drop` paths should ignore the result and continue with the
/// `rm -rf`.
pub(crate) fn shred_paths(paths: &[&Path]) -> io::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let (bin, args) = shred_argv();
    let mut cmd = Command::new(bin);
    for a in args {
        cmd.arg(OsStr::new(a));
    }
    for p in paths {
        cmd.arg(p);
    }
    let status = cmd.status()?;
    if !status.success() {
        return Err(io::Error::other(format!("{bin} exited {status}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Used only by the non-macOS shred-on-disk test and its helpers.
    #[cfg(not(target_os = "macos"))]
    use std::fs;
    #[cfg(not(target_os = "macos"))]
    use std::path::PathBuf;

    // Only consumed by the non-macOS shred test below.
    #[cfg(not(target_os = "macos"))]
    fn scratch_root() -> PathBuf {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "piggy-platform-shred-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn shred_argv_matches_platform_default() {
        let (bin, args) = shred_argv();
        if cfg!(target_os = "macos") {
            assert_eq!(bin, "srm");
        } else {
            assert_eq!(bin, "shred");
        }
        assert_eq!(args, ["-f", "-z"]);
    }

    #[test]
    fn shred_paths_empty_is_ok() {
        assert!(shred_paths(&[]).is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn shred_paths_zeroes_and_succeeds_on_regular_file() {
        if which("shred").is_none() {
            eprintln!("skipping: shred(1) not on PATH");
            return;
        }
        let root = scratch_root();
        let file = root.join("victim");
        fs::write(&file, b"plaintext-secret").unwrap();

        shred_paths(&[file.as_path()]).expect("shred -f -z");

        // shred -z leaves the file present, all-zeros, same size.
        // (shred does NOT unlink; the caller follows up with rm -rf.)
        let after = fs::read(&file).unwrap();
        assert!(
            after.iter().all(|b| *b == 0),
            "shred -z should leave only zero bytes, got {after:?}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    // Only consumed by the non-macOS shred test above.
    #[cfg(not(target_os = "macos"))]
    fn which(name: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
