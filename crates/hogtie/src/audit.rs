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

impl Record {
    pub fn to_json(&self) -> String {
        let asked = opt(&self.asked_by, |e| {
            format!(
                "{{\"pid\":{},\"cgroup\":{},\"unit\":{},\"issued\":{}}}",
                e.asker.pid,
                opt(&e.asker.cgroup, |c| esc(c)),
                opt(&e.asker.unit().map(str::to_string), |u| esc(u)),
                e.issued
            )
        });
        let grant = opt(&self.grant, |g| {
            format!(
                "{{\"key_id\":{},\"serial\":{},\"principals\":{},\"valid_after\":{},\"valid_before\":{}}}",
                esc(&g.key_id),
                g.serial,
                list(&g.principals),
                g.valid_after,
                g.valid_before
            )
        });
        format!(
            "{{\"time\":{},\"outcome\":{},\"reason\":{},\"caller_uid\":{},\"action\":{},\"args\":{},\"nonce\":{},\"asked_by\":{},\"grant\":{},\"argv\":{}}}",
            self.time,
            esc(self.outcome),
            opt(&self.reason, |r| esc(r)),
            opt(&self.caller_uid, |u| u.to_string()),
            opt(&self.action, |a| esc(a)),
            list(&self.args),
            opt(&self.nonce, |n| esc(n)),
            asked,
            grant,
            list(&self.argv),
        )
    }
}

pub fn append(path: &Path, record: &Record) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut line = record.to_json();
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

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
