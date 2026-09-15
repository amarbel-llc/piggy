//! `piggy luks` — LUKS2 volumes keyed by a piggy store secret.
//!
//! Phase 3b.1 of the C-pivy retirement plan (piggy#277): a new piggy
//! command, not a port of C `pivy-luks` and its key-ebox format. The key
//! material is an ordinary store entry: the entry's first line is fed to
//! `cryptsetup … --key-file -` on stdin, exactly the shape
//! `nix/vm-tests/luks.nix` scripted by hand before this module existed
//! (`piggy pass show <name> | head -n1 | tr -d '\n' | cryptsetup …`).
//! Decrypting the entry goes through [`crate::crypt::decrypt`], so it
//! reaches the card the same way `pass show` does (agent, `PIGGY_AUTH_SOCK`,
//! askpass); one card ECDH per invocation.
//!
//! Primary configs only — there is no N-of-M / recovery shape here
//! (piggy#282 tracks that as a feature to design). A passphrase keyslot
//! beside the store-keyed one is `add-key`, which is what FDR 0004's
//! "token slot + passphrase" layout wants.
//!
//! Everything after `--` is forwarded to `cryptsetup` verbatim, before
//! the device: `piggy luks format /dev/vdb --secret luks/x -- -q --pbkdf
//! pbkdf2` runs `cryptsetup luksFormat --type luks2 --key-file - -q
//! --pbkdf pbkdf2 /dev/vdb`. piggy interprets none of them.

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::crypt;

/// Which `cryptsetup` action to run and where the passphrase goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `cryptsetup luksFormat --type luks2 --key-file - [extra…] <dev>`.
    Format { device: String },
    /// `cryptsetup open --key-file - [extra…] <dev> <name>`.
    Open { device: String, name: String },
    /// `cryptsetup luksAddKey --key-file - [extra…] <dev> <new-key-file>`:
    /// the store secret authorises, the file's contents become the new
    /// keyslot.
    AddKey {
        device: String,
        new_key_file: String,
    },
    /// `cryptsetup close [extra…] <name>`; no secret involved.
    Close { name: String },
}

/// The fully-resolved invocation: argv for `cryptsetup` and whether the
/// store secret is written to its stdin.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub argv: Vec<String>,
    pub needs_secret: bool,
}

/// Build the cryptsetup argv for `action`, splicing `extra` (the
/// forwarded `-- …` arguments) between the fixed flags and the
/// positional device/name.
pub fn plan(action: &Action, extra: &[String]) -> Plan {
    let mut argv: Vec<String> = Vec::new();
    let needs_secret = match action {
        Action::Format { device } => {
            argv.extend(
                ["luksFormat", "--type", "luks2", "--key-file", "-"]
                    .iter()
                    .map(|s| s.to_string()),
            );
            argv.extend(extra.iter().cloned());
            argv.push(device.clone());
            true
        }
        Action::Open { device, name } => {
            argv.extend(["open", "--key-file", "-"].iter().map(|s| s.to_string()));
            argv.extend(extra.iter().cloned());
            argv.push(device.clone());
            argv.push(name.clone());
            true
        }
        Action::AddKey {
            device,
            new_key_file,
        } => {
            argv.extend(
                ["luksAddKey", "--key-file", "-"]
                    .iter()
                    .map(|s| s.to_string()),
            );
            argv.extend(extra.iter().cloned());
            argv.push(device.clone());
            argv.push(new_key_file.clone());
            true
        }
        Action::Close { name } => {
            argv.push("close".to_string());
            argv.extend(extra.iter().cloned());
            argv.push(name.clone());
            false
        }
    };
    Plan { argv, needs_secret }
}

/// Entry point. `secret` is the store entry whose first line is the
/// passphrase (required for every action but `close`). Returns
/// `cryptsetup`'s exit code, or 1 on a piggy-side failure (missing
/// `--secret`, decrypt error, spawn error).
pub fn run(action: Action, secret: Option<&str>, extra: &[String]) -> i32 {
    match run_inner(action, secret, extra) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piggy luks: {e}");
            1
        }
    }
}

fn run_inner(action: Action, secret: Option<&str>, extra: &[String]) -> Result<i32, String> {
    let plan = plan(&action, extra);
    let passphrase = if plan.needs_secret {
        let name = secret.ok_or("--secret <pass-name> is required for this action")?;
        Some(crypt::decrypt_first_line(name)?)
    } else {
        None
    };

    let mut cmd = Command::new("cryptsetup");
    cmd.args(&plan.argv)
        .stdin(if passphrase.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn cryptsetup: {e} (is cryptsetup on PATH?)"))?;
    if let Some(bytes) = passphrase {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "cryptsetup stdin unavailable".to_string())?;
        stdin
            .write_all(&bytes)
            .map_err(|e| format!("write passphrase to cryptsetup: {e}"))?;
        // Drop closes the pipe; cryptsetup reads the key file to EOF.
    }
    let status = child.wait().map_err(|e| format!("wait cryptsetup: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn format_puts_extra_before_device() {
        let p = plan(
            &Action::Format {
                device: "/dev/vdb".into(),
            },
            &s(&["-q", "--pbkdf", "pbkdf2"]),
        );
        assert_eq!(
            p.argv,
            s(&[
                "luksFormat",
                "--type",
                "luks2",
                "--key-file",
                "-",
                "-q",
                "--pbkdf",
                "pbkdf2",
                "/dev/vdb"
            ])
        );
        assert!(p.needs_secret);
    }

    #[test]
    fn open_orders_device_then_name() {
        let p = plan(
            &Action::Open {
                device: "/dev/vdb".into(),
                name: "pigcrypt".into(),
            },
            &[],
        );
        assert_eq!(
            p.argv,
            s(&["open", "--key-file", "-", "/dev/vdb", "pigcrypt"])
        );
        assert!(p.needs_secret);
    }

    #[test]
    fn add_key_takes_new_key_file_last() {
        let p = plan(
            &Action::AddKey {
                device: "/dev/vdb".into(),
                new_key_file: "/root/pw2".into(),
            },
            &s(&["-q"]),
        );
        assert_eq!(
            p.argv,
            s(&[
                "luksAddKey",
                "--key-file",
                "-",
                "-q",
                "/dev/vdb",
                "/root/pw2"
            ])
        );
        assert!(p.needs_secret);
    }

    #[test]
    fn close_needs_no_secret() {
        let p = plan(
            &Action::Close {
                name: "pigcrypt".into(),
            },
            &[],
        );
        assert_eq!(p.argv, s(&["close", "pigcrypt"]));
        assert!(!p.needs_secret);
    }

    #[test]
    fn missing_secret_is_a_piggy_side_error() {
        // No store, no cryptsetup needed: the check runs before either.
        let code = run(
            Action::Open {
                device: "/dev/null".into(),
                name: "x".into(),
            },
            None,
            &[],
        );
        assert_eq!(code, 1);
    }
}
