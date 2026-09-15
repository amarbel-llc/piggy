//! `piggy_encrypt` / `piggy_decrypt` Rust shims.
//!
//! Mirrors the bash helpers of the same names in `src/piggy.sh`. These
//! are the only two crypto-shaped operations on the user-facing `show`
//! and `insert` dispatch paths (and, after Split B, `edit` and
//! `generate`).
//!
//! - [`encrypt`] shells to the **`piggy-ids`** binary (via
//!   `PIGGY_IDS_PATH`, same lookup as `reencrypt.rs` and `recipients`),
//!   piping plaintext on stdin and writing the ebox to a file. Mirrors
//!   bash `piggy_encrypt() { "${PIGGY_IDS_PATH:-piggy-ids}" encrypt
//!   "$piggy_ids" >"$outfile" || die "Encryption aborted."; }`.
//! - [`decrypt`] runs **in process** through the Rust ebox unlock
//!   (`piggy::cmd::pivy_box::Decryptor`, piggy#164/#154): agent oracle
//!   from `PIGGY_AUTH_SOCK` (preferred, #123) else `SSH_AUTH_SOCK`, and
//!   the direct-PCSC card oracle with the askpass PIN. The C `pivy-box`
//!   subprocess the bash `piggy_decrypt` spawned is gone.
//!
//! Plaintext never crosses argv; stderr is inherited so user-facing
//! piggy-ids diagnostics still surface.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Encrypt `plaintext` to `outfile` using the recipients in
/// `piggy_ids`. Spawns `piggy-ids encrypt <piggy_ids>`, pipes
/// `plaintext` on stdin, and writes the child's stdout straight to
/// `outfile`.
///
/// Returns `Ok(())` on success; `Err(message)` on spawn / wait / I/O /
/// non-zero exit failures. Callers print the message to stderr and
/// translate to the bash-equivalent `"Encryption aborted."` die line.
pub(crate) fn encrypt(
    piggy_ids: &Path,
    outfile: &Path,
    mut plaintext: impl Read,
) -> Result<(), String> {
    let binary: OsString =
        std::env::var_os("PIGGY_IDS_PATH").unwrap_or_else(|| OsString::from("piggy-ids"));

    let out = std::fs::File::create(outfile)
        .map_err(|err| format!("create {}: {err}", outfile.display()))?;

    let mut child = Command::new(&binary)
        .arg("encrypt")
        .arg(piggy_ids)
        .stdin(Stdio::piped())
        .stdout(out)
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| format!("spawn piggy-ids: {err}"))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "piggy-ids stdin unavailable".to_string())?;
        std::io::copy(&mut plaintext, &mut stdin)
            .map_err(|err| format!("write plaintext to piggy-ids: {err}"))?;
        stdin
            .flush()
            .map_err(|err| format!("flush piggy-ids stdin: {err}"))?;
    }

    let status = child
        .wait()
        .map_err(|err| format!("wait piggy-ids: {err}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(outfile);
        return Err(format!("piggy-ids encrypt exited {status}"));
    }
    Ok(())
}

/// Decrypt `infile` and return the plaintext bytes, in process
/// (piggy#164/#154): the ebox stream is unlocked through the agent named
/// by `PIGGY_AUTH_SOCK` / `SSH_AUTH_SOCK` (#123) or directly against a
/// local card with the askpass PIN, then its chunks are decrypted. No C
/// `pivy-box` subprocess is involved; see [`piggy::cmd::pivy_box::Decryptor`].
pub(crate) fn decrypt(infile: &Path) -> Result<Vec<u8>, String> {
    let input = std::fs::read(infile).map_err(|err| format!("open {}: {err}", infile.display()))?;
    piggy::cmd::pivy_box::Decryptor::from_env().decrypt(&input)
}

/// Decrypt the store entry `pass_name` and return its first line without
/// the trailing newline — the bytes `piggy pass show <name> | head -n1 |
/// tr -d '\n'` yields, i.e. what a passphrase-shaped consumer
/// (`cryptsetup --key-file -`, `zfs load-key`) wants on stdin. Shared by
/// `piggy luks` and `piggy zfs`.
///
/// Errors on a sneaky path, a missing entry, a decrypt failure, or an
/// empty first line (an empty passphrase is never what the caller meant).
pub(crate) fn decrypt_first_line(pass_name: &str) -> Result<Vec<u8>, String> {
    let name = pass_name.trim_end_matches('/');
    if let Some(reason) = crate::store::sneaky_path_reason(name) {
        return Err(format!(
            "sneaky path ({reason}) in secret name {pass_name:?}"
        ));
    }
    let passfile = crate::store::store_root().join(format!("{name}.ebox"));
    if !passfile.is_file() {
        return Err(format!("{name} is not in the password store"));
    }
    let plaintext = decrypt(&passfile)?;
    let end = plaintext
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(plaintext.len());
    let line = plaintext[..end].to_vec();
    if line.is_empty() {
        return Err(format!("{name}: first line is empty"));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Mutex-protected env mutation helper. Same pattern as
    /// `card_oracle.rs`'s `env_lock` — tests run on multiple threads by
    /// default, and `PIGGY_IDS_PATH` is process-global. Without this,
    /// the two tests below that both `set_var("PIGGY_IDS_PATH", ...)`
    /// race: A sets the fake-script path, B sets the
    /// definitely-doesn't-exist path, A's `encrypt()` then reads env
    /// and finds B's value. See #132.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // Poison-tolerant: the guarded region only mutates env, so a panic in
        // one test leaves no invariant broken — recover the guard rather than
        // cascade a PoisonError into every sibling test sharing this lock.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Tempdir helper modeled after the one in `rm.rs` / `store.rs`.
    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "piggy-crypt-test-{}",
            std::process::id().wrapping_mul(0x9E37)
                ^ (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u32)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Force the encrypt shim down a fake-piggy-ids path that ignores
    /// its argv and streams stdin to stdout. We can't use `cat` because
    /// `cat encrypt <path>` treats `encrypt` and the file as files-to-
    /// concat. Use a tiny `sh`-wrapper script instead, written to the
    /// tempdir and chmod +x'd.
    #[test]
    fn encrypt_writes_stdin_to_outfile_via_fake_binary() {
        use std::os::unix::fs::PermissionsExt as _;
        let _guard = env_lock();
        let dir = tempdir();
        let piggy_ids = dir.join("piggy-ids");
        std::fs::write(&piggy_ids, b"fixture").unwrap();
        let out = dir.join("c.ebox");
        let fake = dir.join("fake-piggy-ids");
        std::fs::write(&fake, b"#!/bin/sh\nexec cat\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let saved = std::env::var_os("PIGGY_IDS_PATH");
        std::env::set_var("PIGGY_IDS_PATH", &fake);
        let result = encrypt(&piggy_ids, &out, Cursor::new(b"hello world\n"));
        match saved {
            Some(v) => std::env::set_var("PIGGY_IDS_PATH", v),
            None => std::env::remove_var("PIGGY_IDS_PATH"),
        }

        assert!(result.is_ok(), "encrypt unexpectedly failed: {result:?}");
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(
            bytes, b"hello world\n",
            "expected stdin to pass through to outfile, got: {bytes:?}"
        );
    }

    #[test]
    fn encrypt_reports_spawn_failure() {
        let _guard = env_lock();
        let dir = tempdir();
        let piggy_ids = dir.join("piggy-ids");
        std::fs::write(&piggy_ids, b"x").unwrap();
        let out = dir.join("c.ebox");

        let saved = std::env::var_os("PIGGY_IDS_PATH");
        std::env::set_var(
            "PIGGY_IDS_PATH",
            "/this/path/definitely/does/not/exist/piggy-ids",
        );
        let result = encrypt(&piggy_ids, &out, Cursor::new(b"x"));
        match saved {
            Some(v) => std::env::set_var("PIGGY_IDS_PATH", v),
            None => std::env::remove_var("PIGGY_IDS_PATH"),
        }

        assert!(result.is_err(), "expected spawn failure");
    }
}
