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
//! Symlinked eboxes are **resolved and their real target rewritten**,
//! leaving the link in place. The bash original (and earlier Rust)
//! skipped symlinks outright (`[[ -L $passfile ]] && continue`), which
//! makes `recipients sync` a permanent no-op on a symlink-farm store
//! (e.g. a store whose entries all symlink into an rcm checkout). We
//! follow the link, decrypt+re-encrypt the canonical target file, and
//! atomic-rename over *that* path so the store's symlink keeps pointing
//! at a freshly-rewritten file. Targets are deduplicated by canonical
//! path so two links to the same file (or a link beside its own target)
//! are processed exactly once. A rewritten target may live outside the
//! store (in rcm); the caller's git-commit step is store-scoped and
//! simply finds nothing to stage for those — re-encryption still
//! happens, the rcm working tree is left dirty for the user's own rcm
//! workflow to commit.
//!
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
//! 1. From Rust callers (`init`, `mv`, `cp`, `recipients
//!    add/remove/sync`) via `reencrypt::run`.
//! 2. From the hidden top-level `piggy internal-reencrypt-path
//!    <dir>` subcommand, kept for backward compat with out-of-tree
//!    integrations that historically invoked the bash
//!    `reencrypt_path` shim.

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

    let entries = match collect_eboxes_dedup_targets(&target) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("piggy reencrypt: walk {}: {}", target.display(), err);
            return 1;
        }
    };

    for (path, real) in entries {
        // Compute the relative display name (drop store root prefix
        // and `.ebox` suffix). Matches bash $passfile_display. Uses the
        // store-side `path`, not the resolved target.
        let display = display_name(&path, &store);

        // Find the nearest piggy-ids for this file's directory. This
        // walks up from the STORE-SIDE path, so a symlink picks up the
        // piggy-ids governing its store location (the rcm-farm case has
        // a single store-side piggy-ids governing everything).
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

        // `real` is the canonical (symlink-resolved) target, already
        // computed during the dedup walk — pass it straight through so
        // reencrypt_one doesn't re-`canonicalize`.
        if let Err(err) = reencrypt_one(&real, &piggy_ids) {
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

/// Walk like `collect_eboxes`, following symlinks, but deduplicate
/// entries by their canonical (symlink-resolved) target so a file
/// reachable by more than one path — a symlink beside its own target,
/// or two symlinks into the same rcm file — is re-encrypted exactly
/// once.
///
/// Returns `(store_side, canonical_real)` pairs, one per distinct
/// target, keyed on the first store-side path seen (sorted order). The
/// caller uses `store_side` for `display_name` and the nearest-
/// `piggy-ids` walk (both want the store's view), and `canonical_real`
/// as the file to rewrite — resolving the symlink exactly once here so
/// `reencrypt_one` doesn't `canonicalize` a second time.
fn collect_eboxes_dedup_targets(root: &Path) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    let entries = collect_eboxes(root)?;
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for path in entries {
        // Canonicalize to collapse symlinks; on failure (dangling link,
        // race) fall back to the path itself so we still attempt it
        // once and surface the real error at reencrypt time.
        let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.insert(real.clone()) {
            out.push((path, real));
        }
    }
    Ok(out)
}

fn display_name(path: &Path, store: &Path) -> String {
    let rel = path.strip_prefix(store).unwrap_or(path);
    let rel_str = rel.to_string_lossy();
    rel_str
        .strip_suffix(".ebox")
        .unwrap_or(&rel_str)
        .to_string()
}

/// Run `pivy-box stream decrypt < real | piggy-ids encrypt $piggy_ids > tmp`
/// connected by an OS pipe, then atomic-rename tmp over `real`.
///
/// `real` is the canonical (symlink-resolved) target, resolved once by
/// [`collect_eboxes_dedup_targets`]. When the store-side entry was a
/// symlink (e.g. into an rcm checkout), `real` is the file the link
/// points at: the tmp is created as a sibling of `real` and
/// atomic-renamed over it, so the store's symlink is left untouched and
/// keeps pointing at a freshly-rewritten file. Renaming over the link
/// directly would replace the link with a regular file and orphan the
/// real target — the hazard the old skip-symlinks behavior avoided by
/// refusing to act at all.
fn reencrypt_one(real: &Path, piggy_ids: &Path) -> Result<(), String> {
    let tmp = make_tmp_path(real);

    let pipeline_result = (|| -> Result<(), String> {
        let input = std::fs::File::open(real).map_err(|e| format!("open passfile: {e}"))?;

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
        // Rename over the resolved real target, not the store-side
        // symlink, so the link stays a link pointing at the rewritten
        // file.
        Ok(()) => std::fs::rename(&tmp, real).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("rename {} -> {}: {}", tmp.display(), real.display(), e)
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

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-reencrypt-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A symlinked ebox is now collected (not skipped). The walk follows
    /// the link, so the entry shows up exactly once.
    #[test]
    fn collect_follows_symlinked_ebox() {
        let dir = tempdir();
        let real = dir.join("real.ebox");
        std::fs::write(&real, b"ciphertext").unwrap();
        let link = dir.join("link.ebox");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Drop the real file from the walk root so only the link is
        // present under `root`, proving the link itself is collected.
        let root = tempdir();
        let root_link = root.join("link.ebox");
        std::os::unix::fs::symlink(&real, &root_link).unwrap();

        let got = collect_eboxes_dedup_targets(&root).unwrap();
        assert_eq!(got.len(), 1, "expected the single link, got: {got:?}");
        let (store_side, resolved) = &got[0];
        assert_eq!(store_side, &root_link, "store-side path must be the link");
        assert_eq!(
            resolved,
            &std::fs::canonicalize(&real).unwrap(),
            "resolved target must be the real file"
        );
    }

    /// A symlink sitting beside its own target (both under the walk
    /// root, both resolving to the same file) is collected exactly once
    /// — we must not decrypt+re-encrypt the same file twice in one pass.
    #[test]
    fn collect_dedups_link_beside_its_target() {
        let root = tempdir();
        let real = root.join("real.ebox");
        std::fs::write(&real, b"ciphertext").unwrap();
        let link = root.join("link.ebox");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let got = collect_eboxes_dedup_targets(&root).unwrap();
        assert_eq!(
            got.len(),
            1,
            "link + its target must collapse to one entry, got: {got:?}"
        );
        // The surviving entry's resolved target is the real file
        // (whichever store-side path sorted first is kept).
        let (_, resolved) = &got[0];
        assert_eq!(resolved, &std::fs::canonicalize(&real).unwrap());
    }

    /// Two distinct symlinks pointing at the same out-of-root target
    /// collapse to a single entry.
    #[test]
    fn collect_dedups_two_links_to_same_target() {
        let target_dir = tempdir();
        let real = target_dir.join("shared.ebox");
        std::fs::write(&real, b"ciphertext").unwrap();

        let root = tempdir();
        let a = root.join("a.ebox");
        let b = root.join("b.ebox");
        std::os::unix::fs::symlink(&real, &a).unwrap();
        std::os::unix::fs::symlink(&real, &b).unwrap();

        let got = collect_eboxes_dedup_targets(&root).unwrap();
        assert_eq!(
            got.len(),
            1,
            "two links to one target must collapse to one entry, got: {got:?}"
        );
        let (_, resolved) = &got[0];
        assert_eq!(resolved, &std::fs::canonicalize(&real).unwrap());
    }
}
