//! `piggy ssh-copy-id` — authorize a whole recipient set for SSH login.
//!
//! Reads the SSH-authentication keys (PIV slot 9A, `piggy-piv_auth-v1`
//! with an `ssh_*_pub` format: ECDSA P-256/P-384 or Ed25519) declared in
//! a `piggy-ids` file, renders each as an OpenSSH `authorized_keys`
//! line, and hands the lot to the system `ssh-copy-id` so every listed
//! identity is authorized on the remote host in a single invocation.
//!
//! This is the SSH-auth sibling of the encryption-recipient set: a
//! `piggy-ids` file may carry both 9D ECDH recipients (who can *decrypt*
//! the store) and 9A SSH-auth keys (who may *log in*). `ssh-copy-id`
//! consumes only the latter — the 9D recipients are not SSH keys and are
//! ignored here (mirroring how the encrypt pipeline ignores the 9A keys).
//!
//! The rendering is fully offline: each 9A markl ID already carries its
//! key payload (compressed EC point or raw Ed25519 key), so no card or
//! PCSC access is needed.
//! Reuses the same `piggy_ids::openssh_authorized_key` renderer behind
//! `piggy list --format=ssh`, so the emitted line is byte-identical to
//! that of a live-card enumeration of the same key.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use piggy_ids::{RecipientFile, openssh_authorized_key};

use crate::store::{find_piggy_ids, store_root};

/// Entry point for `piggy ssh-copy-id`. `args` is the raw trailing argv
/// after the subcommand name. Returns a process exit code: the
/// `ssh-copy-id` child's status on a successful spawn, or non-zero on a
/// piggy-side error (bad `piggy-ids`, no SSH keys, missing host).
pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("piggy ssh-copy-id: {e}");
            1
        }
    }
}

const USAGE: &str =
    "Usage: piggy ssh-copy-id [--ids <piggy-ids>] [ssh-copy-id options] [user@]host";

fn run_inner(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(format!("missing [user@]host\n{USAGE}"));
    }

    let (ids_override, passthrough) = split_args(args)?;
    if passthrough.is_empty() {
        return Err(format!("missing [user@]host\n{USAGE}"));
    }

    let ids_path = match ids_override {
        Some(p) => PathBuf::from(p),
        None => {
            let store = store_root();
            find_piggy_ids(&store, "")?
        }
    };

    let lines = authorized_key_lines(&ids_path)?;
    if lines.is_empty() {
        return Err(format!(
            "no SSH-auth (slot 9A) keys in {}\n\
             A piggy-ids file carries SSH-login keys as \
             `piggy-piv_auth-v1@ssh_*_pub` lines. Discover them \
             with `piggy list --format=human` and add them with \
             `piggy pass recipients add <markl-id>`.",
            ids_path.display(),
        ));
    }

    let tmp = write_pubkey_file(&lines)?;
    let status = run_ssh_copy_id(&tmp, &passthrough);
    // Public keys, no secrecy concern — but don't litter $TMPDIR.
    let _ = std::fs::remove_file(&tmp);

    status
}

/// Pull the piggy-only `--ids <path>` / `--ids=<path>` flag out of the
/// argv, returning `(ids_override, passthrough)`. Every other argument —
/// including the `[user@]host` and any `ssh-copy-id` options (`-p`, `-o`,
/// …) — is forwarded verbatim to `ssh-copy-id`.
fn split_args(args: &[String]) -> Result<(Option<String>, Vec<String>), String> {
    let mut ids_override = None;
    let mut passthrough = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--ids" {
            let path = it
                .next()
                .ok_or_else(|| format!("--ids requires a path argument\n{USAGE}"))?;
            ids_override = Some(path.clone());
        } else if let Some(path) = arg.strip_prefix("--ids=") {
            ids_override = Some(path.to_string());
        } else {
            passthrough.push(arg.clone());
        }
    }
    Ok((ids_override, passthrough))
}

/// Parse the `piggy-ids` file and render each slot-9A SSH-auth recipient
/// as a `<keytype> <b64> <comment>` `authorized_keys` line, in file
/// order. The trailing comment is the recipient's inline `# …` note
/// when present, else its markl ID (so an installed key is traceable back
/// to the source line).
fn authorized_key_lines(ids_path: &std::path::Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(ids_path)
        .map_err(|e| format!("reading {}: {e}", ids_path.display()))?;
    let file =
        RecipientFile::parse(&text).map_err(|e| format!("parsing {}: {e}", ids_path.display()))?;

    let mut lines = Vec::new();
    for r in file.ssh_auth_recipients() {
        let prefix = openssh_authorized_key(r.id())
            .map_err(|e| format!("rendering SSH key for {}: {e}", r.id().to_wire()))?;
        let comment = r
            .comment()
            .map(str::to_string)
            .unwrap_or_else(|| r.id().to_wire());
        lines.push(format!("{prefix} {comment}"));
    }
    Ok(lines)
}

/// Write the rendered `authorized_keys` lines to a temp file and return
/// its path. The `.pub` suffix makes `ssh-copy-id -i <file>` read it
/// directly rather than appending `.pub`.
fn write_pubkey_file(lines: &[String]) -> Result<PathBuf, String> {
    let mut path = std::env::temp_dir();
    path.push(format!("piggy-ssh-copy-id.{}.pub", std::process::id()));
    let mut f =
        std::fs::File::create(&path).map_err(|e| format!("creating {}: {e}", path.display()))?;
    for line in lines {
        writeln!(f, "{line}").map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    Ok(path)
}

/// Spawn `ssh-copy-id -f -i <tmp> <passthrough…>`, inheriting stdio, and
/// return its exit code. `-f` skips ssh-copy-id's "is this key already
/// installed" probe (which queries the *local* agent) — appropriate here
/// because the keys come from a file of recipients, not our own agent.
fn run_ssh_copy_id(tmp: &std::path::Path, passthrough: &[String]) -> Result<i32, String> {
    let status = Command::new("ssh-copy-id")
        .arg("-f")
        .arg("-i")
        .arg(tmp)
        .args(passthrough)
        .status()
        .map_err(|e| format!("running ssh-copy-id: {e} (is openssh installed and on PATH?)"))?;
    Ok(status.code().unwrap_or(1))
}
