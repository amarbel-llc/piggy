//! `piggy pass find <term>...` — list entries whose names match any
//! of the given search terms.
//!
//! Mirrors the bash `cmd_find` in `src/piggy.sh:431`:
//!
//! ```text
//! tree -N -C -l --noreport -P "*foo*|*bar*" --prune --matchdirs \
//!      --ignore-case "$PIGGY_STORE_DIR"
//! | tail -n +2 | sed -E 's/\.ebox(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'
//! ```
//!
//! The first line of `tree`'s output is the root path; we drop it so
//! results display relative-style. The sed strips a `.ebox` suffix
//! while preserving the ANSI color reset and any trailing symlink
//! arrow.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use crate::store::store_root;

/// Exit code conventions:
/// - 0: tree printed (matches or not)
/// - 1: usage error or tree(1) failed
pub fn run(terms: &[String]) -> i32 {
    if terms.is_empty() {
        eprintln!("Usage: piggy pass find <pass-names>...");
        return 1;
    }

    println!("Search Terms: {}", terms.join(","));

    let glob = build_glob(terms);
    let root = store_root();

    let mut child = match Command::new("tree")
        .arg("-N")
        .arg("-C")
        .arg("-l")
        .arg("--noreport")
        .arg("-P")
        .arg(&glob)
        .arg("--prune")
        .arg("--matchdirs")
        .arg("--ignore-case")
        .arg(&root)
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!("piggy pass find: failed to spawn tree: {err}");
            return 1;
        }
    };

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            eprintln!("piggy pass find: tree stdout unavailable");
            let _ = child.wait();
            return 1;
        }
    };

    let reader = BufReader::new(stdout);
    let mut out = std::io::stdout().lock();
    for (i, line) in reader.lines().enumerate() {
        // Skip line 0 — it's the root path printed by tree(1).
        if i == 0 {
            continue;
        }
        let line = match line {
            Ok(s) => s,
            Err(err) => {
                eprintln!("piggy pass find: read tree output: {err}");
                let _ = child.wait();
                return 1;
            }
        };
        let stripped = strip_ebox_suffix(&line);
        let _ = writeln!(out, "{stripped}");
    }

    match child.wait() {
        Ok(status) if status.success() => 0,
        Ok(_status) => 1,
        Err(err) => {
            eprintln!("piggy pass find: wait tree: {err}");
            1
        }
    }
}

/// `["foo","bar"]` → `*foo*|*bar*`. The bash `IFS="," eval` echo with
/// a `*$(printf '%s*|*' "$@")` and `${terms%|*}` strip ends up
/// producing exactly this pattern.
fn build_glob(terms: &[String]) -> String {
    let mut out = String::new();
    for (i, t) in terms.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        out.push('*');
        out.push_str(t);
        out.push('*');
    }
    out
}

/// Strip `.ebox` immediately followed by either end-of-line or ` ->`,
/// preserving any ANSI reset code that tree(1) places between the
/// extension and the suffix.
///
/// Equivalent to the sed `s/\.ebox(\x1B\[[0-9]+m)?( ->|$)/\1\2/g`.
fn strip_ebox_suffix(line: &str) -> String {
    // Process iteratively: at each `.ebox` occurrence, check whether
    // the next byte run is `<ESC>[<digits>m` then either ` ->` or end.
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b".ebox") {
            let after = i + 5;
            // Optional ANSI: <ESC>[<digits>m
            let mut tail = after;
            if tail < bytes.len() && bytes[tail] == 0x1B {
                let ansi_end = scan_ansi(bytes, tail);
                if ansi_end > tail {
                    tail = ansi_end;
                }
            }
            let rest = &bytes[tail..];
            if rest.is_empty() || rest.starts_with(b" ->") {
                // Drop the `.ebox`; copy the ANSI (if any) verbatim,
                // then continue from `tail` (the byte after the ANSI
                // or after `.ebox` if no ANSI).
                out.push_str(std::str::from_utf8(&bytes[after..tail]).unwrap_or(""));
                i = tail;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// If `bytes[start]` begins an ANSI CSI like `<ESC>[12m`, return the
/// index *after* the trailing `m`. Otherwise return `start`.
fn scan_ansi(bytes: &[u8], start: usize) -> usize {
    if start + 1 >= bytes.len() || bytes[start] != 0x1B || bytes[start + 1] != b'[' {
        return start;
    }
    let mut j = start + 2;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    if j < bytes.len() && bytes[j] == b'm' {
        j + 1
    } else {
        start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_single_term() {
        assert_eq!(build_glob(&["foo".to_string()]), "*foo*");
    }

    #[test]
    fn glob_multiple_terms() {
        assert_eq!(
            build_glob(&["foo".to_string(), "bar".to_string()]),
            "*foo*|*bar*"
        );
    }

    #[test]
    fn glob_three_terms() {
        let v = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(build_glob(&v), "*a*|*b*|*c*");
    }

    #[test]
    fn strip_at_end_of_line() {
        assert_eq!(strip_ebox_suffix("foo.ebox"), "foo");
    }

    #[test]
    fn strip_before_symlink_arrow() {
        assert_eq!(
            strip_ebox_suffix("foo.ebox -> ../bar.ebox"),
            "foo -> ../bar"
        );
    }

    #[test]
    fn strip_preserves_ansi_reset_at_eol() {
        // tree -C emits e.g. "├── \x1b[01;32mfoo.ebox\x1b[0m"
        let line = "├── \x1b[01;32mfoo.ebox\x1b[0m";
        // We strip ".ebox" but keep the trailing ANSI reset.
        assert_eq!(strip_ebox_suffix(line), "├── \x1b[01;32mfoo\x1b[0m");
    }

    #[test]
    fn strip_preserves_ansi_then_arrow() {
        let line = "foo.ebox\x1b[0m -> bar.ebox";
        assert_eq!(strip_ebox_suffix(line), "foo\x1b[0m -> bar");
    }

    #[test]
    fn strip_leaves_unrelated_ebox_alone() {
        // ".eboxfoo" is not a `.ebox` suffix.
        assert_eq!(strip_ebox_suffix("foo.eboxfoo"), "foo.eboxfoo");
    }

    #[test]
    fn strip_empty() {
        assert_eq!(strip_ebox_suffix(""), "");
    }
}
