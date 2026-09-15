//! `piggy zfs` — ZFS native-encryption datasets keyed by a piggy store
//! secret.
//!
//! Phase 3b.2 of the C-pivy retirement plan (piggy#279), the sibling of
//! [`crate::luks`]: a new piggy command, not a port of C `pivy-zfs` and
//! its key-ebox format. The store entry's first line is the dataset's
//! passphrase, fed to `zfs … -o keylocation=prompt` / `zfs load-key -L
//! prompt` on stdin, exactly what `nix/vm-tests/zfs.nix` scripted by hand
//! before this module existed. The decrypt goes through
//! [`crate::crypt::decrypt_first_line`], so it reaches the card the same
//! way `pass show` does; one card ECDH per invocation.
//!
//! Everything after `--` is forwarded to `zfs` verbatim, before the
//! dataset: `piggy zfs create pool/enc --secret zfs/x -- -o mountpoint=/mnt`
//! runs `zfs create -o encryption=aes-256-gcm -o keyformat=passphrase -o
//! keylocation=prompt -o mountpoint=/mnt pool/enc`. piggy interprets none
//! of them.

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::crypt;

/// Which `zfs` action to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `zfs create -o encryption=aes-256-gcm -o keyformat=passphrase
    /// -o keylocation=prompt [extra…] <dataset>`.
    Create { dataset: String },
    /// `zfs load-key -L prompt [extra…] <dataset>`.
    LoadKey { dataset: String },
}

/// Build the zfs argv for `action`, splicing `extra` (the forwarded
/// `-- …` arguments) between the fixed options and the dataset.
pub fn plan(action: &Action, extra: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();
    match action {
        Action::Create { dataset } => {
            argv.extend(
                [
                    "create",
                    "-o",
                    "encryption=aes-256-gcm",
                    "-o",
                    "keyformat=passphrase",
                    "-o",
                    "keylocation=prompt",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
            argv.extend(extra.iter().cloned());
            argv.push(dataset.clone());
        }
        Action::LoadKey { dataset } => {
            argv.extend(["load-key", "-L", "prompt"].iter().map(|s| s.to_string()));
            argv.extend(extra.iter().cloned());
            argv.push(dataset.clone());
        }
    }
    argv
}

/// Entry point. `secret` is the store entry whose first line is the
/// passphrase. Returns `zfs`'s exit code, or 1 on a piggy-side failure.
pub fn run(action: Action, secret: &str, extra: &[String]) -> i32 {
    match run_inner(action, secret, extra) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piggy zfs: {e}");
            1
        }
    }
}

fn run_inner(action: Action, secret: &str, extra: &[String]) -> Result<i32, String> {
    let argv = plan(&action, extra);
    let passphrase = crypt::decrypt_first_line(secret)?;

    let mut child = Command::new("zfs")
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn zfs: {e} (is zfs on PATH?)"))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "zfs stdin unavailable".to_string())?;
        // zfs reads the passphrase as one line from a non-tty stdin.
        stdin
            .write_all(&passphrase)
            .and_then(|()| stdin.write_all(b"\n"))
            .map_err(|e| format!("write passphrase to zfs: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("wait zfs: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn create_fixes_the_encryption_options_and_puts_extra_before_dataset() {
        let argv = plan(
            &Action::Create {
                dataset: "pigpool/enc".into(),
            },
            &s(&["-o", "mountpoint=/mnt/enc"]),
        );
        assert_eq!(
            argv,
            s(&[
                "create",
                "-o",
                "encryption=aes-256-gcm",
                "-o",
                "keyformat=passphrase",
                "-o",
                "keylocation=prompt",
                "-o",
                "mountpoint=/mnt/enc",
                "pigpool/enc"
            ])
        );
    }

    #[test]
    fn load_key_prompts_from_stdin() {
        let argv = plan(
            &Action::LoadKey {
                dataset: "pigpool/enc".into(),
            },
            &[],
        );
        assert_eq!(argv, s(&["load-key", "-L", "prompt", "pigpool/enc"]));
    }

    #[test]
    fn missing_entry_is_a_piggy_side_error() {
        // No store entry: fails before zfs is spawned.
        let code = run(
            Action::LoadKey {
                dataset: "x/y".into(),
            },
            "definitely/not/here",
            &[],
        );
        assert_eq!(code, 1);
    }
}
