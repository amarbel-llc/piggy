//! The audit log: one JSON line per `hogtie exec`, run or refused, appended
//! to `/var/log/hogtie/audit.log` (root, 0600) and synced before anything
//! runs. A line that cannot be written refuses the action (fail closed).

use crate::grant::Grant;
use crate::nonce::Entry;
use std::io::{self, Write as _};
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    pub time: u64,
    /// `started` (written just before the exec), `refused` (the caller's
    /// request), `error` (hogtie's own failure), or `exec-failed` (a second
    /// line after a `started` one whose exec returned).
    pub outcome: &'static str,
    pub reason: Option<String>,
    pub caller_uid: Option<u32>,
    pub action: Option<String>,
    pub args: Vec<String>,
    pub nonce: Option<String>,
    pub asked_by: Option<Entry>,
    pub grant: Option<Grant>,
    /// The argv run (program first), when it ran.
    pub argv: Vec<String>,
    /// hogtie's own remark: the refusal budget's notes.
    pub note: Option<String>,
}

/// Refusals an account may have logged in full per [`REFUSAL_WINDOW`]
/// seconds (review finding 2): anyone the sudo rule admits can be refused
/// at will, so past the budget refusals are counted, and the next window's
/// first line says how many were not logged.
pub const REFUSAL_BUDGET: u64 = 20;
pub const REFUSAL_WINDOW: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Log it.
    Log,
    /// Log it, and say the rest of the window is not logged.
    LogLast,
    /// Log it, and say how many the last window did not log.
    LogWithSummary(u64),
    /// Count it; do not log it.
    Quiet,
}

impl Admit {
    pub fn note(self) -> Option<String> {
        match self {
            Admit::LogLast => Some(format!(
                "{REFUSAL_BUDGET} refusals of this account this minute; the rest are counted, not logged"
            )),
            Admit::LogWithSummary(n) => {
                Some(format!("{n} refusals of this account were not logged"))
            }
            Admit::Log | Admit::Quiet => None,
        }
    }
}

/// Decide whether this refusal by `uid` (`None`: no SUDO_UID) is logged,
/// at boot-clock second `now`, keeping each account's count in a root-only
/// file under `dir`, locked while it is read and written.
pub fn admit_refusal(dir: &Path, uid: Option<u32>, now: u64) -> io::Result<Admit> {
    use std::io::{Read as _, Seek as _};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let name = uid.map_or_else(|| "none".to_string(), |u| u.to_string());
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(name))?;
    // SAFETY: flock on a descriptor this function owns; released on close.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut text = String::new();
    f.read_to_string(&mut text)?;
    let mut fields = text
        .split_whitespace()
        .map(|s| s.parse::<u64>().unwrap_or(0));
    let (mut start, mut count, mut quiet) = (
        fields.next().unwrap_or(0),
        fields.next().unwrap_or(0),
        fields.next().unwrap_or(0),
    );
    let mut summary = None;
    if now >= start.saturating_add(REFUSAL_WINDOW) || now < start {
        if quiet > 0 {
            summary = Some(quiet);
        }
        (start, count, quiet) = (now, 0, 0);
    }
    count += 1;
    let admit = match (summary, count) {
        (Some(n), _) => Admit::LogWithSummary(n),
        (None, c) if c <= REFUSAL_BUDGET => Admit::Log,
        (None, c) if c == REFUSAL_BUDGET + 1 => Admit::LogLast,
        _ => {
            quiet += 1;
            Admit::Quiet
        }
    };
    f.set_len(0)?;
    f.rewind()?;
    f.write_all(format!("{start} {count} {quiet}\n").as_bytes())?;
    Ok(admit)
}

/// No audit line is longer than this, whatever the caller sends: a record
/// that would be is written as a short one marked `"truncated":true`.
pub const LINE_MAX: usize = 4096;

/// The most of any one caller-given string a line records.
pub const RECORD_STRING_MAX: usize = 256;
/// The most caller-given arguments a line records.
pub const RECORD_ARGS_MAX: usize = 32;

/// `s` cut to [`RECORD_STRING_MAX`] bytes (at a character boundary), with a
/// marker saying how long it was.
pub fn bounded(s: &str) -> String {
    if s.len() <= RECORD_STRING_MAX {
        return s.to_string();
    }
    let mut end = RECORD_STRING_MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[{} bytes]", &s[..end], s.len())
}

/// At most [`RECORD_ARGS_MAX`] arguments, each [`bounded`], and a marker
/// for the rest: a refusal by someone with no grant cannot fill the log.
pub fn bounded_args(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = args
        .iter()
        .take(RECORD_ARGS_MAX)
        .map(|a| bounded(a))
        .collect();
    if args.len() > RECORD_ARGS_MAX {
        out.push(format!(
            "...[{} more arguments]",
            args.len() - RECORD_ARGS_MAX
        ));
    }
    out
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn list(items: &[String]) -> String {
    format!(
        "[{}]",
        items.iter().map(|s| esc(s)).collect::<Vec<_>>().join(",")
    )
}

fn opt<T>(v: &Option<T>, f: impl Fn(&T) -> String) -> String {
    v.as_ref().map(f).unwrap_or_else(|| "null".into())
}

/// A bounded string, escaped.
fn bs(s: &str) -> String {
    esc(&bounded(s))
}

impl Record {
    /// The JSON line, at most [`LINE_MAX`] bytes: every caller-derived
    /// string is bounded, and a record still too long is written short.
    pub fn to_json(&self) -> String {
        let full = self.render_full();
        if full.len() <= LINE_MAX {
            return full;
        }
        self.render_short()
    }

    fn render_full(&self) -> String {
        let asked = opt(&self.asked_by, |e| {
            format!(
                "{{\"pid\":{},\"cgroup\":{},\"unit\":{},\"issued\":{}}}",
                e.asker.pid,
                opt(&e.asker.cgroup, |c| bs(c)),
                opt(&e.asker.unit().map(str::to_string), |u| bs(u)),
                e.issued
            )
        });
        let grant = opt(&self.grant, |g| {
            format!(
                "{{\"key_id\":{},\"serial\":{},\"principals\":{},\"valid_after\":{},\"valid_before\":{}}}",
                bs(&g.key_id),
                g.serial,
                list(&bounded_args(&g.principals)),
                g.valid_after,
                g.valid_before
            )
        });
        format!(
            "{{\"time\":{},\"outcome\":{},\"reason\":{},\"caller_uid\":{},\"action\":{},\"args\":{},\"nonce\":{},\"asked_by\":{},\"grant\":{},\"argv\":{},\"note\":{}}}",
            self.time,
            esc(self.outcome),
            opt(&self.reason, |r| bs(r)),
            opt(&self.caller_uid, |u| u.to_string()),
            opt(&self.action, |a| bs(a)),
            list(&bounded_args(&self.args)),
            opt(&self.nonce, |n| bs(n)),
            asked,
            grant,
            list(&bounded_args(&self.argv)),
            opt(&self.note, |n| bs(n)),
        )
    }

    /// The fields that identify the event, each cut short: at most about
    /// 6 x (64 + 64 + 64 + 256) escaped bytes plus the frame.
    fn render_short(&self) -> String {
        let cut = |s: &str, n: usize| {
            let mut end = s.len().min(n);
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            esc(&s[..end])
        };
        format!(
            "{{\"time\":{},\"outcome\":{},\"reason\":{},\"caller_uid\":{},\"action\":{},\"nonce\":{},\"key_id\":{},\"truncated\":true}}",
            self.time,
            esc(self.outcome),
            opt(&self.reason, |r| cut(r, 256)),
            opt(&self.caller_uid, |u| u.to_string()),
            opt(&self.action, |a| cut(a, 64)),
            opt(&self.nonce, |n| cut(n, 64)),
            opt(&self.grant, |g| cut(&g.key_id, 64)),
        )
    }
}

/// Append `record`'s line, locked against other writers. A short write (a
/// full disk, a file size limit) is cut back off, so the log never holds a
/// partial line, and is returned as an error: the caller refuses.
pub fn append(path: &Path, record: &Record) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut line = record.to_json();
    if line.len() > LINE_MAX {
        return Err(io::Error::other("an audit line over the cap"));
    }
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    // SAFETY: flock on a descriptor this function owns; released on close.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let before = f.metadata()?.len();
    if let Err(e) = f.write_all(line.as_bytes()).and_then(|()| f.sync_all()) {
        let _ = f.set_len(before);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record with every field as large as a caller can make it.
    fn worst_record() -> Record {
        let huge = "\u{1}".repeat(16 * 1024);
        Record {
            time: u64::MAX,
            outcome: "refused",
            reason: Some(format!(
                "grant principal {huge:?} holds a pattern character"
            )),
            caller_uid: Some(u32::MAX),
            action: Some(huge.clone()),
            args: vec![huge.clone(); 1000],
            nonce: Some(huge.clone()),
            asked_by: Some(Entry {
                asker: crate::nonce::Asker {
                    uid: u32::MAX,
                    pid: i32::MAX,
                    cgroup: Some(format!("/{huge}.scope")),
                },
                issued: u64::MAX,
                expires: u64::MAX,
            }),
            grant: Some(Grant {
                key_id: huge.clone(),
                serial: u64::MAX,
                principals: vec![huge.clone(); 1000],
                valid_after: u64::MAX,
                valid_before: u64::MAX,
            }),
            argv: vec![huge.clone(); 1000],
            note: Some(huge),
        }
    }

    #[test]
    fn refusals_beyond_the_budget_are_counted_not_logged() {
        let d = crate::util::PrivateDir::new(&std::env::temp_dir(), "hogtie-budget").unwrap();
        let mut got = Vec::new();
        for _ in 0..REFUSAL_BUDGET + 5 {
            got.push(admit_refusal(d.path(), Some(1000), 100).unwrap());
        }
        assert!(
            got[..REFUSAL_BUDGET as usize]
                .iter()
                .all(|a| *a == Admit::Log)
        );
        assert_eq!(got[REFUSAL_BUDGET as usize], Admit::LogLast);
        assert!(
            got[REFUSAL_BUDGET as usize + 1..]
                .iter()
                .all(|a| *a == Admit::Quiet)
        );
        assert_eq!(
            admit_refusal(d.path(), Some(1001), 100).unwrap(),
            Admit::Log,
            "per account"
        );
        assert_eq!(
            admit_refusal(d.path(), Some(1000), 100 + REFUSAL_WINDOW).unwrap(),
            Admit::LogWithSummary(4),
            "the next window says how many were not logged"
        );
    }

    #[test]
    fn no_line_exceeds_the_cap_whatever_the_caller_sends() {
        let line = worst_record().to_json();
        assert!(line.len() <= LINE_MAX, "the line is {} bytes", line.len());
        assert!(line.contains("\"truncated\":true"), "{line}");
    }

    #[test]
    fn caller_strings_are_bounded() {
        assert_eq!(bounded("short"), "short");
        let b = bounded(&"x".repeat(100_000));
        assert!(b.len() < RECORD_STRING_MAX + 32, "{}", b.len());
        assert!(b.ends_with("...[100000 bytes]"));
        let multibyte = "é".repeat(200); // 400 bytes, a boundary at 256
        assert!(bounded(&multibyte).starts_with(&"é".repeat(128)));
        let args = vec!["y".repeat(5000); 1000];
        let a = bounded_args(&args);
        assert_eq!(a.len(), RECORD_ARGS_MAX + 1);
        assert_eq!(a.last().unwrap(), "...[968 more arguments]");
    }

    #[test]
    fn strings_are_escaped() {
        assert_eq!(esc("a\"b\\c\nd\u{1}"), r#""a\"b\\c\nd\u0001""#);
    }

    #[test]
    fn a_refusal_line_is_one_json_object() {
        let r = Record {
            time: 5,
            outcome: "refused",
            reason: Some("x".into()),
            args: vec!["a\nb".into()],
            ..Default::default()
        };
        let j = r.to_json();
        assert!(!j.contains('\n'));
        assert!(
            j.starts_with(
                "{\"time\":5,\"outcome\":\"refused\",\"reason\":\"x\",\"caller_uid\":null"
            ),
            "{j}"
        );
        assert!(j.contains("\"args\":[\"a\\nb\"]"), "{j}");
    }

    #[test]
    fn lines_are_appended() {
        let d = crate::util::PrivateDir::new(&std::env::temp_dir(), "hogtie-audit").unwrap();
        let p = d.path().join("audit.log");
        let r = Record {
            time: 1,
            outcome: "started",
            ..Default::default()
        };
        append(&p, &r).unwrap();
        append(&p, &r).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap().lines().count(), 2);
    }
}
