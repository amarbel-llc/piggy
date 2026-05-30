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
//! - [`decrypt`] shells to **`pivy-box stream decrypt`** directly (NOT
//!   through piggy-ids — same as the bash) with the ebox piped on stdin
//!   and stdout captured into a Vec<u8>. Honors `PIGGY_AUTH_SOCK` per
//!   #123: when set and non-empty, the child sees `SSH_AUTH_SOCK =
//!   PIGGY_AUTH_SOCK`, so piggy's decrypts always go through piggy's
//!   own agent (which advertises `ecdh@joyent.com`) rather than through
//!   a mux that may not. The canonical resolver lives in the lib crate
//!   at `piggy::agent_client::piggy_auth_sock_override`.
//!
//! Plaintext never crosses argv; stderr is inherited so user-facing
//! pivy-box / piggy-ids diagnostics still surface.

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

/// Decrypt `infile` and return the plaintext bytes. Spawns
/// `pivy-box stream decrypt` with the ebox file piped on stdin and
/// captures stdout.
///
/// PIGGY_AUTH_SOCK (#123): if set and non-empty, override
/// `SSH_AUTH_SOCK` for the child so piggy's decrypts hit piggy-agent
/// (which advertises `ecdh@joyent.com`) rather than an ssh-agent-mux
/// that may not.
pub(crate) fn decrypt(infile: &Path) -> Result<Vec<u8>, String> {
    let input =
        std::fs::File::open(infile).map_err(|err| format!("open {}: {err}", infile.display()))?;

    let mut cmd = Command::new("pivy-box");
    cmd.arg("stream")
        .arg("decrypt")
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    if let Some(sock) = piggy::agent_client::piggy_auth_sock_override() {
        cmd.env("SSH_AUTH_SOCK", sock);
    }

    let mut child = cmd
        .spawn()
        .map_err(|err| format!("spawn pivy-box: {err}"))?;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "pivy-box stdout unavailable".to_string())?;

    let mut out = Vec::new();
    std::io::copy(&mut stdout, &mut out).map_err(|err| format!("read pivy-box stdout: {err}"))?;

    let status = child
        .wait()
        .map_err(|err| format!("wait pivy-box: {err}"))?;
    if !status.success() {
        return Err(format!("pivy-box stream decrypt exited {status}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
