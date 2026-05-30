//! `piggy pass show [--qrcode[=N],-q[N]] [--clip[=N],-c[N]] [path]`
//! — native Rust port of `cmd_show` in `src/piggy.sh`.
//!
//! Three resolution paths, mirroring the bash:
//!
//! 1. `$PREFIX/$path.ebox` is a regular file → decrypt, print or
//!    clip/qr-code line N.
//! 2. `$PREFIX/$path` is a directory → print `Password Store`
//!    (root) or `${path%/}` plus `tree -N -C -l --noreport`'s output
//!    with the leaf-name `.ebox` suffix stripped (preserving ANSI
//!    color escapes).
//! 3. `$path` empty and store empty → "Error: password store is
//!    empty. Try \"piggy pass init\".".
//! 4. Otherwise → "Error: $path is not in the password store.".
//!
//! `--clip` and `--qrcode` are mutually exclusive; default selected
//! line is 1. The deferred-restore clipboard worker is spawned via
//! the hidden `piggy internal-clipboard-restore` subcommand (see
//! [`crate::internal_clipboard_restore`]) and the parent exits
//! immediately after writing the plan to the child's stdin — the same
//! `disown`-then-return shape the bash `clip` uses.

use std::io::Write as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::crypt;
use crate::platform::clipboard::{self, ClipPlan, Env as ClipEnv, ProcessRunner};
use crate::platform::qrcode::{self, Env as QrEnv, Plan as QrPlan};
use crate::store::store_root;

const DEFAULT_CLIP_TIME_SECS: u64 = 45;

/// Exit code conventions:
/// - 0: handled (file printed/clipped/qr'd, or directory listed)
/// - 1: usage / sneaky-path / not-in-store / decrypt failure
pub fn run(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{msg}");
            return 1;
        }
    };

    if let Some(reason) = sneaky_path_reason(&opts.path) {
        eprintln!("Error: You've attempted to pass a sneaky path to piggy ({reason}). Go home.");
        return 1;
    }

    let root = store_root();
    let passfile = root.join(format!("{}.ebox", opts.path));

    if passfile.is_file() {
        return handle_file(&opts, &passfile);
    }

    let dir_target = if opts.path.is_empty() {
        root.clone()
    } else {
        root.join(&opts.path)
    };

    if dir_target.is_dir() {
        return handle_dir(&opts.path, &dir_target);
    }

    if opts.path.is_empty() {
        eprintln!(r#"Error: password store is empty. Try "piggy pass init"."#);
    } else {
        eprintln!("Error: {} is not in the password store.", opts.path);
    }
    1
}

#[derive(Debug)]
struct Opts {
    mode: Mode,
    selected_line: usize,
    path: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Print,
    Clip,
    Qrcode,
}

/// Bash uses `getopt -o q::c:: -l qrcode::,clip::` — both options take
/// an optional value. With short flags the value must be glued
/// (`-c3`); with long flags it's `--clip=3`. Both default to "1" when
/// the value is absent. We mirror that shape.
fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut mode = Mode::Print;
    let mut selected_line: usize = 1;
    let mut positional: Vec<String> = Vec::new();
    let mut iter = args.iter();
    let usage = "Usage: piggy pass show [--clip[=line-number],-c[line-number]] [--qrcode[=line-number],-q[line-number]] [pass-name]";

    while let Some(arg) = iter.next() {
        let s = arg.as_str();
        if s == "--" {
            for rest in iter.by_ref() {
                positional.push(rest.clone());
            }
            break;
        } else if s == "-c" || s == "--clip" {
            set_mode(&mut mode, Mode::Clip, usage)?;
        } else if s == "-q" || s == "--qrcode" {
            set_mode(&mut mode, Mode::Qrcode, usage)?;
        } else if let Some(value) = s.strip_prefix("--clip=") {
            set_mode(&mut mode, Mode::Clip, usage)?;
            selected_line = parse_line(value)?;
        } else if let Some(value) = s.strip_prefix("--qrcode=") {
            set_mode(&mut mode, Mode::Qrcode, usage)?;
            selected_line = parse_line(value)?;
        } else if let Some(value) = s.strip_prefix("-c") {
            set_mode(&mut mode, Mode::Clip, usage)?;
            selected_line = parse_line(value)?;
        } else if let Some(value) = s.strip_prefix("-q") {
            set_mode(&mut mode, Mode::Qrcode, usage)?;
            selected_line = parse_line(value)?;
        } else if s.starts_with('-') {
            return Err(usage.into());
        } else {
            positional.push(arg.clone());
        }
    }

    if positional.len() > 1 {
        return Err(usage.into());
    }
    let path = positional
        .into_iter()
        .next()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    Ok(Opts {
        mode,
        selected_line,
        path,
    })
}

fn set_mode(current: &mut Mode, requested: Mode, usage: &str) -> Result<(), String> {
    if *current != Mode::Print && *current != requested {
        return Err(usage.into());
    }
    *current = requested;
    Ok(())
}

fn parse_line(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("Clip location '{value}' is not a number."))
}

fn handle_file(opts: &Opts, passfile: &Path) -> i32 {
    let plaintext = match crypt::decrypt(passfile) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("piggy pass show: {err}");
            return 1;
        }
    };

    match opts.mode {
        Mode::Print => {
            let mut stdout = std::io::stdout().lock();
            if let Err(err) = stdout.write_all(&plaintext) {
                eprintln!("piggy pass show: write stdout: {err}");
                return 1;
            }
            0
        }
        Mode::Clip => {
            let Some(line) = nth_line(&plaintext, opts.selected_line) else {
                eprintln!(
                    "There is no password to put on the clipboard at line {}.",
                    opts.selected_line
                );
                return 1;
            };
            clip_line(&line, &opts.path)
        }
        Mode::Qrcode => {
            let Some(line) = nth_line(&plaintext, opts.selected_line) else {
                eprintln!(
                    "There is no password to put on the clipboard at line {}.",
                    opts.selected_line
                );
                return 1;
            };
            qrcode_line(&line, &opts.path)
        }
    }
}

/// `tail -n +N | head -n 1` — return the bytes of line N (1-indexed),
/// without the trailing newline. None if N exceeds the number of lines
/// OR the resulting line is empty (mirrors the bash `[[ -n $pass ]]`
/// guard).
fn nth_line(bytes: &[u8], n: usize) -> Option<Vec<u8>> {
    if n == 0 {
        return None;
    }
    let mut idx = 0usize;
    let mut current = 1usize;
    while idx < bytes.len() {
        let end = bytes[idx..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|p| idx + p)
            .unwrap_or(bytes.len());
        if current == n {
            let line = bytes[idx..end].to_vec();
            return (!line.is_empty()).then_some(line);
        }
        idx = end + 1;
        current += 1;
    }
    None
}

fn clip_line(line: &[u8], name: &str) -> i32 {
    let env = ClipEnv::from_process();
    let clip_time = std::time::Duration::from_secs(clip_time_seconds());
    let plan = match clipboard::copy_with_clear(&env, line, name, clip_time, &ProcessRunner) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{err}");
            return 1;
        }
    };
    if let Err(err) = spawn_clipboard_restore_worker(&plan) {
        // Restore-worker spawn failure is non-fatal — the clipboard is
        // already populated, we just won't auto-clear. Match the bash
        // best-effort posture (the bash `disown` masks any worker error
        // too).
        eprintln!("piggy pass show: spawn restore worker: {err}");
    }
    println!("{}", plan.user_message);
    0
}

fn qrcode_line(line: &[u8], name: &str) -> i32 {
    let env = QrEnv::from_process();
    let plan = qrcode::render_plan(&env, name);
    render_qrcode(&plan, line)
}

fn render_qrcode(plan: &QrPlan, line: &[u8]) -> i32 {
    match plan {
        QrPlan::Gui {
            viewer,
            viewer_args,
        } => spawn_qrcode_gui(viewer, viewer_args, line),
        QrPlan::Stdout => spawn_qrcode_stdout(line),
    }
}

/// Pipe the line through `qrencode --size 10 -o -` to `<viewer> <args>`,
/// the bash one-liner shape.
fn spawn_qrcode_gui(viewer: &str, args: &[std::ffi::OsString], line: &[u8]) -> i32 {
    let mut qrencode = match Command::new("qrencode")
        .arg("--size")
        .arg("10")
        .arg("-o")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!("piggy pass show: spawn qrencode: {err}");
            return 1;
        }
    };
    if let Some(mut stdin) = qrencode.stdin.take() {
        if let Err(err) = stdin.write_all(line) {
            eprintln!("piggy pass show: write to qrencode: {err}");
            return 1;
        }
    }
    let qr_stdout = match qrencode.stdout.take() {
        Some(s) => s,
        None => {
            eprintln!("piggy pass show: qrencode stdout unavailable");
            return 1;
        }
    };
    let viewer_status = Command::new(viewer).args(args).stdin(qr_stdout).status();
    let _ = qrencode.wait();
    match viewer_status {
        Ok(s) if s.success() => 0,
        Ok(s) => s.code().unwrap_or(1),
        Err(err) => {
            eprintln!("piggy pass show: spawn {viewer}: {err}");
            1
        }
    }
}

fn spawn_qrcode_stdout(line: &[u8]) -> i32 {
    let mut child = match Command::new("qrencode")
        .arg("-t")
        .arg("utf8")
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!("piggy pass show: spawn qrencode: {err}");
            return 1;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(err) = stdin.write_all(line) {
            eprintln!("piggy pass show: write to qrencode: {err}");
            return 1;
        }
    }
    match child.wait() {
        Ok(s) if s.success() => 0,
        Ok(s) => s.code().unwrap_or(1),
        Err(err) => {
            eprintln!("piggy pass show: wait qrencode: {err}");
            1
        }
    }
}

/// Spawn the deferred-restore worker via `piggy
/// internal-clipboard-restore`, with argv0 set to
/// `plan.sleep_argv0`. The plan is serialized to the child's stdin so
/// it doesn't appear in argv. The parent does NOT wait — closing the
/// stdin pipe is the only synchronization point. This mirrors bash's
/// `(...) & disown`.
///
/// The argv0 rename matches bash `exec -a "$sleep_argv0" bash ...` so
/// subsequent `clip` calls can `pkill -f "^$sleep_argv0"` the stale
/// worker.
fn spawn_clipboard_restore_worker(plan: &ClipPlan) -> std::io::Result<()> {
    let piggy_bin = std::env::current_exe().or_else(|_| {
        std::env::var_os("PIGGY_BIN")
            .map(std::path::PathBuf::from)
            .ok_or_else(|| std::io::Error::other("current_exe unavailable and PIGGY_BIN unset"))
    })?;
    let mut cmd = Command::new(&piggy_bin);
    cmd.arg("internal-clipboard-restore");
    cmd.arg0(&plan.sleep_argv0);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    let mut child = cmd.spawn()?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("restore worker stdin unavailable"))?;
        let bytes = crate::internal_clipboard_restore::serialize_plan(plan);
        stdin.write_all(&bytes)?;
    }
    // Drop the Child handle without wait — Tokio-less detach. Linux
    // reparents the orphan to PID 1 and reaps it; no zombie.
    std::mem::drop(child);
    Ok(())
}

fn clip_time_seconds() -> u64 {
    std::env::var("PIGGY_CLIP_TIME")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CLIP_TIME_SECS)
}

fn handle_dir(path: &str, dir_target: &Path) -> i32 {
    if path.is_empty() {
        println!("Password Store");
    } else {
        println!("{}", path.trim_end_matches('/'));
    }
    print_tree(dir_target)
}

/// Shell to `tree -N -C -l --noreport <dir> | tail -n +1 (drop first
/// line) | sed -E 's/\.ebox(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'`.
///
/// The bash form pipes through `tail -n +2` and `sed` directly; we
/// post-process in Rust to avoid pulling sed/tail into the child
/// graph, but the regex semantics are preserved exactly (the
/// `(\x1B\[[0-9]+m)?` group preserves any ANSI color reset that `tree
/// -C` emits after the leaf name). The first line of `tree`'s output
/// is the input directory's own banner — bash strips it with `tail -n
/// +2` so the printed name comes from our own `println!` above.
fn print_tree(dir_target: &Path) -> i32 {
    let output = Command::new("tree")
        .arg("-N")
        .arg("-C")
        .arg("-l")
        .arg("--noreport")
        .arg(dir_target)
        .stderr(Stdio::inherit())
        .output();
    let out = match output {
        Ok(o) if o.status.success() => o,
        Ok(o) => return o.status.code().unwrap_or(1),
        Err(err) => {
            eprintln!("piggy pass show: spawn tree: {err}");
            return 1;
        }
    };

    let trimmed = strip_first_line(&out.stdout);
    let cleaned = strip_ebox_extension(trimmed);
    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_all(&cleaned) {
        eprintln!("piggy pass show: write stdout: {err}");
        return 1;
    }
    0
}

fn strip_first_line(input: &[u8]) -> &[u8] {
    match input.iter().position(|b| *b == b'\n') {
        Some(idx) => &input[idx + 1..],
        None => &[],
    }
}

/// Implements the bash `sed -E 's/\.ebox(\x1B\[[0-9]+m)?( ->|$)/\1\2/g'`:
/// drop the literal `.ebox` whenever it's directly followed by an
/// optional ANSI color-reset sequence and then either the symlink-target
/// marker ` ->` or end-of-line. The two captured groups (the optional
/// escape + the trailing token) are preserved verbatim.
fn strip_ebox_extension(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i..].starts_with(b".ebox") {
            let after = i + 5;
            let (esc_end, esc) = ansi_color_run(&input[after..]);
            let tail_start = after + esc_end;
            let tail_is_arrow = input[tail_start..].starts_with(b" ->");
            let tail_is_eol = tail_start == input.len() || input[tail_start] == b'\n';
            if tail_is_arrow || tail_is_eol {
                out.extend_from_slice(esc);
                if tail_is_arrow {
                    out.extend_from_slice(b" ->");
                    i = tail_start + 3;
                } else {
                    i = tail_start;
                }
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// Match `\x1B\[[0-9]+m` at the start of `input` and return (length,
/// slice). Length is 0 / slice is empty if no match.
fn ansi_color_run(input: &[u8]) -> (usize, &[u8]) {
    if input.len() < 3 || input[0] != 0x1B || input[1] != b'[' {
        return (0, &[]);
    }
    let mut j = 2;
    let mut saw_digit = false;
    while j < input.len() && input[j].is_ascii_digit() {
        saw_digit = true;
        j += 1;
    }
    if !saw_digit || j >= input.len() || input[j] != b'm' {
        return (0, &[]);
    }
    (j + 1, &input[..=j])
}

/// Mirrors `check_sneaky_paths` in piggy.sh / the per-module
/// `sneaky_path_reason` in `rm.rs`, `init.rs`, `copy_move.rs`.
fn sneaky_path_reason(path: &str) -> Option<&'static str> {
    for component in Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Some("`..` component");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_default_print_no_args() {
        let opts = parse_args(&s(&[])).unwrap();
        assert_eq!(opts.mode, Mode::Print);
        assert_eq!(opts.selected_line, 1);
        assert_eq!(opts.path, "");
    }

    #[test]
    fn parse_print_with_path() {
        let opts = parse_args(&s(&["cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Print);
        assert_eq!(opts.path, "cred1");
    }

    #[test]
    fn parse_path_trims_trailing_slash() {
        let opts = parse_args(&s(&["folder/"])).unwrap();
        assert_eq!(opts.path, "folder");
    }

    #[test]
    fn parse_short_clip_bare() {
        let opts = parse_args(&s(&["-c", "cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Clip);
        assert_eq!(opts.selected_line, 1);
        assert_eq!(opts.path, "cred1");
    }

    #[test]
    fn parse_short_clip_with_glued_value() {
        let opts = parse_args(&s(&["-c3", "cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Clip);
        assert_eq!(opts.selected_line, 3);
        assert_eq!(opts.path, "cred1");
    }

    #[test]
    fn parse_long_clip_with_value() {
        let opts = parse_args(&s(&["--clip=4", "cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Clip);
        assert_eq!(opts.selected_line, 4);
    }

    #[test]
    fn parse_long_qrcode_bare() {
        let opts = parse_args(&s(&["--qrcode", "cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Qrcode);
        assert_eq!(opts.selected_line, 1);
    }

    #[test]
    fn parse_long_qrcode_with_value() {
        let opts = parse_args(&s(&["--qrcode=7", "cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Qrcode);
        assert_eq!(opts.selected_line, 7);
    }

    #[test]
    fn parse_short_qrcode_glued() {
        let opts = parse_args(&s(&["-q2", "cred1"])).unwrap();
        assert_eq!(opts.mode, Mode::Qrcode);
        assert_eq!(opts.selected_line, 2);
    }

    #[test]
    fn parse_rejects_clip_and_qrcode_combined() {
        let err = parse_args(&s(&["-c", "-q", "cred1"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn parse_rejects_non_numeric_line() {
        let err = parse_args(&s(&["-cabc", "cred1"])).unwrap_err();
        assert!(err.contains("not a number"), "got: {err}");
    }

    #[test]
    fn parse_rejects_too_many_positionals() {
        let err = parse_args(&s(&["a", "b"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn nth_line_returns_first_line() {
        assert_eq!(nth_line(b"foo\nbar\nbaz", 1), Some(b"foo".to_vec()));
    }

    #[test]
    fn nth_line_returns_second_line() {
        assert_eq!(nth_line(b"foo\nbar\nbaz", 2), Some(b"bar".to_vec()));
    }

    #[test]
    fn nth_line_returns_last_line_without_trailing_newline() {
        assert_eq!(nth_line(b"foo\nbar\nbaz", 3), Some(b"baz".to_vec()));
    }

    #[test]
    fn nth_line_returns_none_when_out_of_range() {
        assert_eq!(nth_line(b"foo\n", 5), None);
    }

    #[test]
    fn nth_line_empty_line_returns_none() {
        assert_eq!(nth_line(b"foo\n\nbar\n", 2), None);
    }

    #[test]
    fn nth_line_handles_no_trailing_newline() {
        assert_eq!(nth_line(b"only line", 1), Some(b"only line".to_vec()));
    }

    #[test]
    fn strip_first_line_removes_banner() {
        assert_eq!(strip_first_line(b"a/b\n  contents\n"), b"  contents\n");
    }

    #[test]
    fn strip_first_line_empty_when_no_newline() {
        assert_eq!(strip_first_line(b"only"), b"");
    }

    #[test]
    fn strip_ebox_extension_removes_at_eol() {
        let got = strip_ebox_extension(b"   cred1.ebox\n   cred2.ebox\n");
        assert_eq!(got, b"   cred1\n   cred2\n");
    }

    #[test]
    fn strip_ebox_extension_preserves_ansi_color_reset() {
        let input = b"   \x1B[33mcred1.ebox\x1B[0m\n";
        let got = strip_ebox_extension(input);
        assert_eq!(got, b"   \x1B[33mcred1\x1B[0m\n");
    }

    #[test]
    fn strip_ebox_extension_preserves_symlink_arrow() {
        let got = strip_ebox_extension(b"cred1.ebox -> ../target.ebox\n");
        assert_eq!(got, b"cred1 -> ../target\n");
    }

    #[test]
    fn strip_ebox_extension_keeps_ebox_inside_filename() {
        // `.ebox` not at end-of-line, not before " ->" — must stay.
        let got = strip_ebox_extension(b"a.eboxname\n");
        assert_eq!(got, b"a.eboxname\n");
    }

    #[test]
    fn sneaky_path_rejects_parent() {
        assert!(sneaky_path_reason("../etc").is_some());
        assert!(sneaky_path_reason("..").is_some());
        assert!(sneaky_path_reason("a/../b").is_some());
    }

    #[test]
    fn sneaky_path_accepts_normal() {
        assert!(sneaky_path_reason("a/b").is_none());
        assert!(sneaky_path_reason("foo..bar").is_none());
    }
}
