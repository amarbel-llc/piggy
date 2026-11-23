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

/// How long hogtie waits for an account's budget file lock before it gives
/// up (review R2): the lock is per account, so a stopped holder can only
/// delay its own account, and not for long.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// One account's budget file, one fixed-width record (see
/// [`budget_record`]), locked while it is open. A file that exists but does
/// not hold exactly one record (cut by a kill mid-write, say) is `corrupt`:
/// it counts as over budget for one window, never as a fresh one (F2).
struct Budget {
    file: std::fs::File,
    start: u64,
    count: u64,
    quiet: u64,
    corrupt: bool,
}

/// The budget file's record: `<window start> <count> <quiet>`, each 20
/// digits, so a rewrite in place is always the same length.
pub fn budget_record(start: u64, count: u64, quiet: u64) -> String {
    format!("{start:020} {count:020} {quiet:020}\n")
}

fn parse_record(text: &str) -> Option<(u64, u64, u64)> {
    let line = text.strip_suffix('\n')?;
    let mut f = line.split(' ');
    let field = |s: Option<&str>| s.filter(|s| s.len() == 20)?.parse::<u64>().ok();
    let r = (field(f.next())?, field(f.next())?, field(f.next())?);
    f.next().is_none().then_some(r)
}

impl Budget {
    fn open(path: &Path) -> io::Result<Self> {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let open = |create_new: bool| {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(create_new)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
        };
        let (mut file, fresh) = match open(true) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (open(false)?, false),
            Err(e) => return Err(e),
        };
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        // SAFETY: flock on a descriptor this function owns; released on close.
        while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) || std::time::Instant::now() > deadline {
                return Err(e);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let (start, count, quiet, corrupt) = match parse_record(&text) {
            Some((s, c, q)) => (s, c, q, false),
            // Created just now (or by a racing exec that has not written
            // yet): a fresh account.
            None if fresh => (0, 0, 0, false),
            None => (0, 0, 0, true),
        };
        let mut b = Self {
            file,
            start,
            count,
            quiet,
            corrupt,
        };
        if fresh {
            // Written at once, so only a write cut short can leave it empty.
            b.save()?;
        }
        Ok(b)
    }

    fn window_closed(&self, now: u64) -> bool {
        now >= self.start.saturating_add(REFUSAL_WINDOW) || now < self.start
    }

    /// Rewrite the record in place: same length every time, so no moment
    /// leaves the file empty (F2).
    fn save(&mut self) -> io::Result<()> {
        use std::os::unix::fs::FileExt as _;
        let line = budget_record(self.start, self.count, self.quiet);
        self.file.write_all_at(line.as_bytes(), 0)?;
        self.file.set_len(line.len() as u64)
    }
}

/// The `n` unlogged refusals a `LogWithSummary(n)` line reported are now
/// in the log: stop owing them (F3). Called only after that line is written.
pub fn summary_written(dir: &Path, uid: Option<u32>, n: u64) -> io::Result<()> {
    let mut b = Budget::open(&budget_path(dir, uid))?;
    if b.corrupt {
        return Ok(());
    }
    b.quiet = b.quiet.saturating_sub(n);
    b.save()
}

fn budget_path(dir: &Path, uid: Option<u32>) -> std::path::PathBuf {
    dir.join(uid.map_or_else(|| "none".to_string(), |u| u.to_string()))
}

/// Decide whether this refusal by `uid` (`None`: no SUDO_UID) is logged,
/// at boot-clock second `now`, keeping each account's count in a root-only
/// file under `dir`, locked while it is read and written.
pub fn admit_refusal(dir: &Path, uid: Option<u32>, now: u64) -> io::Result<Admit> {
    let mut b = Budget::open(&budget_path(dir, uid))?;
    if b.corrupt {
        // over_budget runs first and repairs it; if it did not, log.
        return Ok(Admit::Log);
    }
    let (mut start, mut count, mut quiet) = (b.start, b.count, b.quiet);
    let mut summary = None;
    if b.window_closed(now) {
        if quiet > 0 {
            summary = Some(quiet);
        }
        // `quiet` stays owed until the line reporting it is written (F3).
        (start, count) = (now, 0);
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
    (b.start, b.count, b.quiet) = (start, count, quiet);
    b.save()?;
    Ok(admit)
}

/// Whether `uid` has spent its budget in the current window (review R3).
/// If it has, the request is not evaluated at all: it is counted here and
/// answered with one fixed refusal, so no answer can be told from another.
pub fn over_budget(dir: &Path, uid: Option<u32>, now: u64) -> io::Result<bool> {
    let mut b = Budget::open(&budget_path(dir, uid))?;
    if b.corrupt {
        // Over budget for one window, from now (F2).
        (b.start, b.count, b.quiet, b.corrupt) = (now, REFUSAL_BUDGET + 1, 1, false);
        b.save()?;
        return Ok(true);
    }
    if b.window_closed(now) || b.count <= REFUSAL_BUDGET {
        return Ok(false);
    }
    b.quiet += 1;
    b.save()?;
    Ok(true)
}

/// For every account whose window has closed with refusals not logged,
/// append one `summary` line saying how many, and clear the count, so the
/// counts reach the log even if that account never asks again (review R3).
/// The socket's periodic sweep calls this.
pub fn flush_summaries(dir: &Path, log: &Path, now: u64, wall: u64) -> io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let Ok(e) = e else { continue };
        let Ok(mut b) = Budget::open(&e.path()) else {
            continue;
        };
        if b.corrupt || b.quiet == 0 || !b.window_closed(now) {
            continue;
        }
        let caller_uid = e.file_name().to_str().and_then(|s| s.parse().ok());
        let record = Record {
            time: wall,
            outcome: "summary",
            caller_uid,
            note: Admit::LogWithSummary(b.quiet).note(),
            ..Default::default()
        };
        append(log, &record)?;
        b.quiet = 0;
        b.save()?;
    }
    Ok(())
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
    /// The JSON line, at most [`LINE_MAX`] bytes: whole if it fits; else
    /// with every caller-derived string bounded; else short, marked
    /// `"truncated":true`.
    pub fn to_json(&self) -> String {
        if self.fits_whole() {
            return self.render(false);
        }
        let full = self.render(true);
        if full.len() <= LINE_MAX {
            return full;
        }
        self.render_short()
    }

    /// Whether the line holds every field whole (review R4: a `started`
    /// line must, or the run is refused).
    pub fn fits_whole(&self) -> bool {
        // The caller's bytes alone, unescaped, are a lower bound on the
        // whole line: past the cap, do not render megabytes to find out.
        if self.raw_bytes() > LINE_MAX {
            return false;
        }
        self.render(false).len() <= LINE_MAX
    }

    fn raw_bytes(&self) -> usize {
        let strs = |v: &[String]| v.iter().map(String::len).sum::<usize>();
        let opt_len = |o: &Option<String>| o.as_ref().map_or(0, String::len);
        opt_len(&self.reason)
            + opt_len(&self.action)
            + opt_len(&self.nonce)
            + opt_len(&self.note)
            + strs(&self.args)
            + strs(&self.argv)
            + self
                .asked_by
                .as_ref()
                .map_or(0, |e| e.asker.cgroup.as_ref().map_or(0, String::len))
            + self
                .grant
                .as_ref()
                .map_or(0, |g| g.key_id.len() + strs(&g.principals))
    }

    fn render(&self, bound: bool) -> String {
        let s = |x: &str| if bound { bs(x) } else { esc(x) };
        let l = |x: &[String]| {
            if bound {
                list(&bounded_args(x))
            } else {
                list(x)
            }
        };
        let asked = opt(&self.asked_by, |e| {
            format!(
                "{{\"pid\":{},\"cgroup\":{},\"unit\":{},\"issued\":{}}}",
                e.asker.pid,
                opt(&e.asker.cgroup, |c| s(c)),
                opt(&e.asker.unit().map(str::to_string), |u| s(u)),
                e.issued
            )
        });
        let grant = opt(&self.grant, |g| {
            format!(
                "{{\"key_id\":{},\"serial\":{},\"principals\":{},\"valid_after\":{},\"valid_before\":{}}}",
                s(&g.key_id),
                g.serial,
                l(&g.principals),
                g.valid_after,
                g.valid_before
            )
        });
        format!(
            "{{\"time\":{},\"outcome\":{},\"reason\":{},\"caller_uid\":{},\"action\":{},\"args\":{},\"nonce\":{},\"asked_by\":{},\"grant\":{},\"argv\":{},\"note\":{}}}",
            self.time,
            esc(self.outcome),
            opt(&self.reason, |r| s(r)),
            opt(&self.caller_uid, |u| u.to_string()),
            opt(&self.action, |a| s(a)),
            l(&self.args),
            opt(&self.nonce, |n| s(n)),
            asked,
            grant,
            l(&self.argv),
            opt(&self.note, |n| s(n)),
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

/// Append `record`'s line with no lock (review R2: a stopped holder of a
/// lock would block every account): one `write` of the whole line, at most
/// [`LINE_MAX`] + 1 bytes, on a file opened `O_APPEND`. The guarantee relied
/// on is Linux's, not POSIX's: a write to a regular file holds the inode
/// lock for its whole length, so two hogtie lines never interleave (POSIX
/// promises only that each write starts at the end). A line the file size
/// limit would cut is refused before anything is written; a write that is
/// still short (a full disk) is ended with a newline if it can be, so the
/// next line starts clean, and refuses.
pub fn append(path: &Path, record: &Record) -> io::Result<()> {
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
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    // As root, shield_self raised the file size limit to infinity and this
    // never refuses; it matters where the limit could not be raised (a
    // non-root caller of hogtie, as in the test harness).
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let size = f.metadata()?.len();
    if lim.rlim_cur != libc::RLIM_INFINITY && size + line.len() as u64 > lim.rlim_cur {
        return Err(io::Error::other(
            "the audit line would pass the file size limit",
        ));
    }
    let n = f.write(line.as_bytes())?;
    if n != line.len() {
        let ended = matches!(f.write(b"\n"), Ok(1));
        let what = format!("short write to the audit log ({n} of {} bytes)", line.len());
        if ended {
            return Err(io::Error::other(what));
        }
        return Err(io::Error::other(PartialLine(what)));
    }
    f.sync_all()
}

/// A short write whose ending newline could not be written either (only a
/// full disk or an I/O error does that): the log now ends in a partial
/// line. `hogtie exec` exits 4 for it.
#[derive(Debug)]
pub struct PartialLine(pub String);

impl std::fmt::Display for PartialLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; the log ends in a partial line", self.0)
    }
}

impl std::error::Error for PartialLine {}

/// Whether `e` is a [`PartialLine`].
pub fn is_partial_line(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<PartialLine>())
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
    fn an_unwritten_summary_is_reported_again() {
        // F3: the count of unlogged refusals is cleared only once the line
        // that carries it has been written.
        let d = crate::util::PrivateDir::new(&std::env::temp_dir(), "hogtie-budget").unwrap();
        for _ in 0..=REFUSAL_BUDGET {
            admit_refusal(d.path(), Some(1000), 100).unwrap();
        }
        for _ in 0..3 {
            assert!(over_budget(d.path(), Some(1000), 100).unwrap());
        }
        let later = 100 + REFUSAL_WINDOW;
        assert_eq!(
            admit_refusal(d.path(), Some(1000), later).unwrap(),
            Admit::LogWithSummary(3)
        );
        // The line was not written (say hogtie was killed): still owed.
        let again = later + REFUSAL_WINDOW;
        assert_eq!(
            admit_refusal(d.path(), Some(1000), again).unwrap(),
            Admit::LogWithSummary(3)
        );
        summary_written(d.path(), Some(1000), 3).unwrap();
        let after = again + REFUSAL_WINDOW;
        assert_eq!(
            admit_refusal(d.path(), Some(1000), after).unwrap(),
            Admit::Log
        );
    }

    #[test]
    fn past_the_budget_an_account_is_over_until_the_window_closes() {
        let d = crate::util::PrivateDir::new(&std::env::temp_dir(), "hogtie-budget").unwrap();
        for _ in 0..=REFUSAL_BUDGET {
            assert!(!over_budget(d.path(), Some(1000), 100).unwrap());
            admit_refusal(d.path(), Some(1000), 100).unwrap();
        }
        assert!(over_budget(d.path(), Some(1000), 100).unwrap());
        assert!(
            !over_budget(d.path(), Some(1001), 100).unwrap(),
            "per account"
        );
        assert!(!over_budget(d.path(), Some(1000), 100 + REFUSAL_WINDOW).unwrap());
    }

    #[test]
    fn the_sweep_writes_the_count_of_unlogged_refusals_when_the_window_closes() {
        let d = crate::util::PrivateDir::new(&std::env::temp_dir(), "hogtie-budget").unwrap();
        let log = d.path().join("audit.log");
        let dir = d.path().join("refusals");
        std::fs::create_dir(&dir).unwrap();
        for _ in 0..=REFUSAL_BUDGET {
            admit_refusal(&dir, Some(1000), 100).unwrap();
        }
        for _ in 0..4 {
            assert!(over_budget(&dir, Some(1000), 100).unwrap());
        }
        flush_summaries(&dir, &log, 130, 5000).unwrap();
        assert!(!log.exists(), "the window is still open");
        flush_summaries(&dir, &log, 100 + REFUSAL_WINDOW, 5000).unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(
            text.contains("\"outcome\":\"summary\"") && text.contains("4 refusals"),
            "{text}"
        );
        assert!(text.contains("\"caller_uid\":1000"), "{text}");
        flush_summaries(&dir, &log, 100 + 2 * REFUSAL_WINDOW, 5000).unwrap();
        assert_eq!(
            std::fs::read_to_string(&log).unwrap().lines().count(),
            1,
            "written once"
        );
        assert_eq!(
            admit_refusal(&dir, Some(1000), 100 + 2 * REFUSAL_WINDOW).unwrap(),
            Admit::Log,
            "already reported"
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
