//! `piggy internal-clipboard-restore` — hidden, never user-facing.
//!
//! Implements the deferred-restore half of `cmd_show -c`. The
//! [`show::spawn_clipboard_restore_worker`] in the parent process
//! spawns this subcommand with:
//!   - argv0 set to `plan.sleep_argv0` (the bash `exec -a "$sleep_argv0"
//!     bash ...` equivalent) so subsequent `clip` calls can `pkill -f
//!     "^<argv0>"` it,
//!   - the serialized [`ClipPlan`] piped on stdin,
//!   - no wait on the child handle (Linux reparents to PID 1 and
//!     reaps; no zombie).
//!
//! This subcommand:
//!   1. Reads the serialized plan from stdin.
//!   2. Sleeps `clip_time`.
//!   3. Reads the current clipboard via `plan.paste`.
//!   4. If the current clipboard equals `plan.pushed_bytes`, writes
//!      `plan.restore_bytes` back via `plan.copy`. Otherwise, leaves it
//!      alone — the user pasted something else, restoring would clobber.
//!   5. Best-effort `qdbus org.kde.klipper /klipper
//!      org.kde.klipper.klipper.clearClipboardHistory` to clear KDE's
//!      clipboard manager history. Ignore failure: this is the same
//!      best-effort posture as bash, which catches every clipboard
//!      manager that doesn't ship qdbus support as a silent no-op.
//!
//! ## Serialization format
//!
//! Length-prefixed framing: every field is `<u32-be length><bytes>` so
//! arbitrary binary payloads (NUL, newlines, non-UTF-8) round-trip
//! without escape. Fields in declared order:
//!
//! 1. `copy.program` (OsString as raw bytes)
//! 2. `copy.args` — `<u32-be count>` then `<u32-be length><bytes>` per
//!    arg
//! 3. `paste.program`
//! 4. `paste.args` (same shape as copy.args)
//! 5. `sleep_argv0` (UTF-8 String)
//! 6. `clip_time_secs` as a single `u64-be`
//! 7. `pushed_bytes`
//! 8. `restore_bytes`
//!
//! `user_message` is not serialized — it's only used by the parent's
//! "Copied X to clipboard. Will clear in N seconds." line.
//!
//! No serde here: the platform-clipboard `ClipPlan` uses `OsString`
//! for cross-OS argv accuracy, which serde_json can't round-trip
//! losslessly on non-UTF-8 platforms. The hand-rolled framing is 60
//! lines, exhaustively unit-tested, and keeps the wire shape
//! self-documenting for any future reader.

use std::ffi::OsString;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::platform::clipboard::{ClipPlan, CopyInvocation, PasteInvocation};

/// Exit code conventions:
///   - 0: planned worker finished (whether or not it actually restored)
///   - 1: malformed plan on stdin / spawn failure for the paste tool
pub fn run() -> i32 {
    let mut bytes = Vec::new();
    if let Err(err) = std::io::stdin().lock().read_to_end(&mut bytes) {
        eprintln!("internal-clipboard-restore: read stdin: {err}");
        return 1;
    }
    let plan = match deserialize_plan(&bytes) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("internal-clipboard-restore: {msg}");
            return 1;
        }
    };

    std::thread::sleep(plan.clip_time);

    let current = match run_paste(&plan.paste) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("internal-clipboard-restore: paste: {err}");
            // The plan never reached the user's clipboard? Nothing
            // to do — bash's `qdbus &>/dev/null` swallows this too.
            return 1;
        }
    };

    if current == plan.pushed_bytes {
        if let Err(err) = run_copy(&plan.copy, &plan.restore_bytes) {
            eprintln!("internal-clipboard-restore: restore: {err}");
        }
    }

    // klipper-clear is best-effort by design. qdbus may not exist;
    // klipper may not be running. Bash hides any output via
    // `&>/dev/null`.
    let _ = Command::new("qdbus")
        .arg("org.kde.klipper")
        .arg("/klipper")
        .arg("org.kde.klipper.klipper.clearClipboardHistory")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    0
}

fn run_paste(invocation: &PasteInvocation) -> std::io::Result<Vec<u8>> {
    let out = Command::new(&invocation.program)
        .args(&invocation.args)
        .output()?;
    Ok(out.stdout)
}

fn run_copy(invocation: &CopyInvocation, bytes: &[u8]) -> std::io::Result<()> {
    let mut child = Command::new(&invocation.program)
        .args(&invocation.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bytes)?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(std::io::Error::other(format!("copy exited {status}")));
    }
    Ok(())
}

/// Serialize a [`ClipPlan`] using the length-prefixed framing
/// described in the module docs. Pure function over the plan.
pub(crate) fn serialize_plan(plan: &ClipPlan) -> Vec<u8> {
    let mut buf = Vec::new();
    write_bytes(&mut buf, plan.copy.program.as_bytes());
    write_args(&mut buf, &plan.copy.args);
    write_bytes(&mut buf, plan.paste.program.as_bytes());
    write_args(&mut buf, &plan.paste.args);
    write_bytes(&mut buf, plan.sleep_argv0.as_bytes());
    buf.extend_from_slice(&plan.clip_time.as_secs().to_be_bytes());
    write_bytes(&mut buf, &plan.pushed_bytes);
    write_bytes(&mut buf, &plan.restore_bytes);
    buf
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn write_args(buf: &mut Vec<u8>, args: &[OsString]) {
    buf.extend_from_slice(&(args.len() as u32).to_be_bytes());
    for a in args {
        write_bytes(buf, a.as_bytes());
    }
}

fn deserialize_plan(bytes: &[u8]) -> Result<ClipPlan, String> {
    let mut r = Reader::new(bytes);
    let copy_program = OsString::from_vec(r.read_bytes()?);
    let copy_args = r.read_args()?;
    let paste_program = OsString::from_vec(r.read_bytes()?);
    let paste_args = r.read_args()?;
    let sleep_argv0 = String::from_utf8(r.read_bytes()?)
        .map_err(|err| format!("sleep_argv0 not UTF-8: {err}"))?;
    let clip_time_secs = r.read_u64_be()?;
    let pushed_bytes = r.read_bytes()?;
    let restore_bytes = r.read_bytes()?;
    if !r.is_empty() {
        return Err(format!("trailing {} byte(s) after plan", r.remaining()));
    }
    Ok(ClipPlan {
        copy: CopyInvocation {
            program: copy_program,
            args: copy_args,
        },
        paste: PasteInvocation {
            program: paste_program,
            args: paste_args,
        },
        sleep_argv0,
        clip_time: Duration::from_secs(clip_time_secs),
        pushed_bytes,
        restore_bytes,
        // user_message is recomputed if needed; the worker never prints
        // it, so leave it empty.
        user_message: String::new(),
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u32_be(&mut self) -> Result<u32, String> {
        if self.bytes.len() < self.pos + 4 {
            return Err("truncated u32 length prefix".into());
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&self.bytes[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(arr))
    }

    fn read_u64_be(&mut self) -> Result<u64, String> {
        if self.bytes.len() < self.pos + 8 {
            return Err("truncated u64 (clip_time)".into());
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(arr))
    }

    fn read_bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self.read_u32_be()? as usize;
        if self.bytes.len() < self.pos + len {
            return Err(format!(
                "truncated bytes field (claimed {len}, remaining {})",
                self.bytes.len() - self.pos
            ));
        }
        let out = self.bytes[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    fn read_args(&mut self) -> Result<Vec<OsString>, String> {
        let count = self.read_u32_be()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(OsString::from_vec(self.read_bytes()?));
        }
        Ok(out)
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_plan() -> ClipPlan {
        ClipPlan {
            copy: CopyInvocation {
                program: OsString::from("wl-copy"),
                args: vec![OsString::from("--primary")],
            },
            paste: PasteInvocation {
                program: OsString::from("wl-paste"),
                args: vec![OsString::from("-n"), OsString::from("--primary")],
            },
            sleep_argv0: "piggy sleep on display wayland-0".to_string(),
            clip_time: Duration::from_secs(45),
            pushed_bytes: b"new-secret".to_vec(),
            restore_bytes: b"old-clip".to_vec(),
            user_message: "Copied cred to clipboard. Will clear in 45 seconds.".to_string(),
        }
    }

    #[test]
    fn roundtrip_basic_plan() {
        let p = fixture_plan();
        let bytes = serialize_plan(&p);
        let q = deserialize_plan(&bytes).unwrap();
        assert_eq!(q.copy.program, p.copy.program);
        assert_eq!(q.copy.args, p.copy.args);
        assert_eq!(q.paste.program, p.paste.program);
        assert_eq!(q.paste.args, p.paste.args);
        assert_eq!(q.sleep_argv0, p.sleep_argv0);
        assert_eq!(q.clip_time, p.clip_time);
        assert_eq!(q.pushed_bytes, p.pushed_bytes);
        assert_eq!(q.restore_bytes, p.restore_bytes);
        // user_message is intentionally not transported across the
        // process boundary — the parent prints it before exit.
        assert_eq!(q.user_message, "");
    }

    #[test]
    fn roundtrip_binary_clipboard_payloads() {
        let mut p = fixture_plan();
        // Embedded NUL + non-UTF-8 bytes — the kind of thing serde_json
        // would mangle. Hand-rolled framing handles it transparently.
        p.pushed_bytes = vec![0x00, 0xFF, 0x01, b'\n', b'a', 0x00];
        p.restore_bytes = vec![0xFE, 0xFD, 0x00, 0x01, b'\n'];
        let bytes = serialize_plan(&p);
        let q = deserialize_plan(&bytes).unwrap();
        assert_eq!(q.pushed_bytes, p.pushed_bytes);
        assert_eq!(q.restore_bytes, p.restore_bytes);
    }

    #[test]
    fn roundtrip_zero_args() {
        let mut p = fixture_plan();
        p.copy.args.clear();
        p.paste.args.clear();
        let bytes = serialize_plan(&p);
        let q = deserialize_plan(&bytes).unwrap();
        assert!(q.copy.args.is_empty());
        assert!(q.paste.args.is_empty());
    }

    #[test]
    fn deserialize_rejects_truncated_input() {
        let p = fixture_plan();
        let bytes = serialize_plan(&p);
        for cut in 0..bytes.len() {
            let result = deserialize_plan(&bytes[..cut]);
            assert!(
                result.is_err(),
                "truncated at {cut} should fail, got {result:?}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_trailing_garbage() {
        let p = fixture_plan();
        let mut bytes = serialize_plan(&p);
        bytes.push(0xCC);
        let result = deserialize_plan(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("trailing"));
    }
}
