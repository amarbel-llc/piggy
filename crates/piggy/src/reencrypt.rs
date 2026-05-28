//! `reencrypt_path` port — walk every `*.ebox` under a target
//! directory, decrypt with `pivy-box stream decrypt`, re-encrypt with
//! `piggy-ids encrypt $piggy_ids`, and atomic-rename over the
//! original.
//!
//! Mirrors `reencrypt_path` in `src/piggy.sh:88`. Each file picks up
//! the **nearest** `piggy-ids` (walking up from the file's directory
//! toward the store root), matching the bash `find_piggy_ids
//! "$passfile_dir"` call inside the loop.
//!
//! Symlinks are skipped (bash uses `[[ -L $passfile ]] && continue`).
//! Per-file failures are non-fatal: the temp file is removed and the
//! walk continues. This matches the bash, which uses
//! `(pipeline && mv) || rm` so a failed pipeline doesn't abort the
//! whole pass.
//!
//! The Rust port spawns the decrypt and encrypt processes connected
//! by an OS pipe (no buffering plaintext in our address space) — same
//! risk profile as the bash pipeline.
//!
//! This module is reachable two ways:
//!
//! 1. From Rust callers (future `mv`/`cp`/`recipients add/remove/sync`
//!    ports), via `reencrypt::run`.
//! 2. From the existing bash callers (today's `mv`/`cp`/recipients
//!    flows), via the hidden top-level `piggy internal-reencrypt-path
//!    <dir>` subcommand, which `piggy.sh::reencrypt_path` exec's into.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::store::{collect_eboxes, find_piggy_ids, store_root};

/// Exit code conventions:
/// - 0: walk completed (zero or more files reencrypted)
/// - 1: usage / IO error preventing any walk
///
/// Per-file failures emit a stderr line and continue the walk; they do
/// not change the exit code, matching the bash behavior.
pub fn run(target: &Path) -> i32 {
    let store = store_root();
    let target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        store.join(target)
    };

    if !target.exists() {
        eprintln!(
            "piggy reencrypt: target does not exist: {}",
            target.display()
        );
        return 1;
    }

    let entries = match collect_eboxes_no_symlinks(&target) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("piggy reencrypt: walk {}: {}", target.display(), err);
            return 1;
        }
    };

    for path in entries {
        // Compute the relative display name (drop store root prefix
        // and `.ebox` suffix). Matches bash $passfile_display.
        let display = display_name(&path, &store);

        // Find the nearest piggy-ids for this file's directory.
        let passfile_dir = match path.parent() {
            Some(p) => p,
            None => continue,
        };
        let subfolder = passfile_dir
            .strip_prefix(&store)
            .unwrap_or(passfile_dir)
            .to_string_lossy()
            .into_owned();
        let piggy_ids = match find_piggy_ids(&store, &subfolder) {
            Ok(p) => p,
            Err(err) => {
                eprintln!("piggy reencrypt: {display}: {err}");
                continue;
            }
        };

        eprintln_safe(&format!("{display}: reencrypting"));

        if let Err(err) = reencrypt_one(&path, &piggy_ids) {
            eprintln!("piggy reencrypt: {display}: {err}");
            // Bash silently continues on failure. We mirror that and
            // do not change the exit code.
        }
    }

    0
}

/// `eprintln!` to stderr, but ignore I/O errors (matches the bash
/// `echo` which prints to stdout via `>&2` redirection inheritance
/// from callers). The bash actually `echo`s to stdout, so we route to
/// stdout to stay byte-compatible.
fn eprintln_safe(message: &str) {
    // The bash `echo "$passfile_display: reencrypting"` writes to
    // stdout (no redirect). Keep the same channel so callers that
    // grep / tee on stdout still see it.
    let _ = std::io::Write::write_all(&mut std::io::stdout().lock(), message.as_bytes());
    let _ = std::io::Write::write_all(&mut std::io::stdout().lock(), b"\n");
}

/// Walk like `collect_eboxes`, but skip symlinks at the file level so
/// we never try to re-encrypt through a link.
fn collect_eboxes_no_symlinks(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut entries = collect_eboxes(root)?;
    entries.retain(|p| match std::fs::symlink_metadata(p) {
        Ok(m) => !m.file_type().is_symlink(),
        Err(_) => false,
    });
    Ok(entries)
}

fn display_name(path: &Path, store: &Path) -> String {
    let rel = path.strip_prefix(store).unwrap_or(path);
    let rel_str = rel.to_string_lossy();
    rel_str
        .strip_suffix(".ebox")
        .unwrap_or(&rel_str)
        .to_string()
}

/// Run `pivy-box stream decrypt < passfile | piggy-ids encrypt $piggy_ids > tmp`
/// connected by an OS pipe, then atomic-rename tmp over passfile.
fn reencrypt_one(passfile: &Path, piggy_ids: &Path) -> Result<(), String> {
    let tmp = make_tmp_path(passfile);

    let pipeline_result = (|| -> Result<(), String> {
        let input = std::fs::File::open(passfile).map_err(|e| format!("open passfile: {e}"))?;

        let mut decrypt_cmd = Command::new("pivy-box");
        decrypt_cmd
            .arg("stream")
            .arg("decrypt")
            .stdin(input)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // Prefer piggy's own agent socket over the ambient SSH_AUTH_SOCK
        // (commonly an ssh-agent-mux that may not advertise ecdh@joyent.com).
        // The binary and library crates are disjoint, so this mirrors
        // piggy::agent_client::piggy_auth_sock_override rather than calling
        // it. See #123.
        if let Some(sock) = std::env::var_os("PIGGY_AUTH_SOCK").filter(|s| !s.is_empty()) {
            decrypt_cmd.env("SSH_AUTH_SOCK", sock);
        }
        let mut decrypt = decrypt_cmd
            .spawn()
            .map_err(|e| format!("spawn pivy-box: {e}"))?;

        let decrypt_stdout = decrypt
            .stdout
            .take()
            .ok_or_else(|| "pivy-box stdout unavailable".to_string())?;

        let piggy_ids_bin: OsString =
            std::env::var_os("PIGGY_IDS_PATH").unwrap_or_else(|| OsString::from("piggy-ids"));

        let tmp_file = std::fs::File::create(&tmp)
            .map_err(|e| format!("create tmp {}: {}", tmp.display(), e))?;

        let mut encrypt = Command::new(&piggy_ids_bin)
            .arg("encrypt")
            .arg(piggy_ids)
            .stdin(decrypt_stdout)
            .stdout(tmp_file)
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawn piggy-ids: {e}"))?;

        let decrypt_status = decrypt.wait().map_err(|e| format!("wait pivy-box: {e}"))?;
        let encrypt_status = encrypt.wait().map_err(|e| format!("wait piggy-ids: {e}"))?;

        if !decrypt_status.success() {
            return Err(format!("pivy-box exited {decrypt_status}"));
        }
        if !encrypt_status.success() {
            return Err(format!("piggy-ids encrypt exited {encrypt_status}"));
        }
        Ok(())
    })();

    match pipeline_result {
        Ok(()) => std::fs::rename(&tmp, passfile).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("rename {} -> {}: {}", tmp.display(), passfile.display(), e)
        }),
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            Err(err)
        }
    }
}

/// `${passfile}.tmp.<RANDOM>.<RANDOM>.<RANDOM>.<RANDOM>.--` to match
/// the bash naming pattern (informational; the file is always
/// renamed or removed).
fn make_tmp_path(passfile: &Path) -> PathBuf {
    let parent = passfile.parent().unwrap_or_else(|| Path::new("."));
    let name = passfile
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ebox".to_string());
    let suffix = format!(
        "{}.tmp.{}.{}.{}.{}.--",
        name,
        pseudo_random(),
        pseudo_random(),
        pseudo_random(),
        pseudo_random(),
    );
    parent.join(suffix)
}

fn pseudo_random() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    nanos
        .wrapping_mul(2654435761)
        .wrapping_add(pid.wrapping_mul(0x9E37))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_strips_store_root_and_ebox() {
        let store = Path::new("/store");
        let path = Path::new("/store/folder/cred1.ebox");
        assert_eq!(display_name(path, store), "folder/cred1");
    }

    #[test]
    fn display_name_top_level() {
        let store = Path::new("/store");
        let path = Path::new("/store/cred1.ebox");
        assert_eq!(display_name(path, store), "cred1");
    }

    #[test]
    fn tmp_path_uses_passfile_dir() {
        let p = Path::new("/store/folder/cred1.ebox");
        let tmp = make_tmp_path(p);
        assert_eq!(tmp.parent(), Some(Path::new("/store/folder")));
        assert!(
            tmp.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("cred1.ebox.tmp.") && s.ends_with(".--")),
            "unexpected tmp name: {:?}",
            tmp.file_name()
        );
    }
}
