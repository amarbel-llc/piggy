//! `piggy pass insert [--echo,-e | --multiline,-m] [--force,-f]
//! pass-name` — native Rust port of `cmd_insert` in `src/piggy.sh`.
//!
//! Three input modes:
//!
//! - `-m` / `--multiline`: read stdin to EOF, write the raw bytes as
//!   the ebox plaintext (preserves trailing newlines and embedded
//!   binary payloads).
//! - `-e` / `--echo`: prompt `Enter password for <path>:` on stderr,
//!   read one line from stdin with echo (bash `read -r -e`). Submit
//!   the line + the trailing newline `echo` adds.
//! - default (silent): prompt twice with the TTY's echo disabled, die
//!   if mismatched, otherwise submit the line + trailing newline.
//!
//! `-e` and `-m` are mutually exclusive. `-f` skips the overwrite
//! prompt when the target already exists. `check_sneaky_paths`
//! rejects `..`-bearing paths. The handler ends by calling
//! `git_ops::add_and_commit` to track the new entry if the store is
//! inside a git work tree.

use std::io::{BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};

use crate::crypt;
use crate::git_ops;
use crate::store::{find_piggy_ids, store_root};

/// Exit code conventions:
/// - 0: inserted (or user declined the yesno overwrite prompt — same
///   as bash, which `exit 1`s on `[[ $response != [yY] ]]` BUT only
///   when stdin is a TTY; non-interactive overwrites are silent)
/// - 1: usage / sneaky-path / mismatched passwords / encrypt / IO
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

    if !opts.force
        && passfile.exists()
        && !confirm(&format!(
            "An entry already exists for {}. Overwrite it?",
            opts.path
        ))
    {
        return 1;
    }

    let parent = passfile.parent().unwrap_or(&root);
    if let Err(err) = std::fs::create_dir_all(parent) {
        eprintln!("piggy pass insert: create {}: {}", parent.display(), err);
        return 1;
    }

    // `find_piggy_ids` wants a subfolder relative to the store root.
    // The bash uses `dirname -- "$path"`; if the path has no `/` it's
    // `.`, which we pass through as empty so `find_piggy_ids` walks
    // from the store root.
    let subfolder = path_parent_for_search(&opts.path);
    let piggy_ids = match find_piggy_ids(&root, &subfolder)
        .and_then(|p| crate::pigpen_pointer::resolve_piggy_ids_path(&p))
    {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("Error: {msg}");
            return 1;
        }
    };

    let plaintext = match collect_plaintext(opts.mode, &opts.path) {
        Ok(b) => b,
        Err(rc) => return rc,
    };

    if let Err(err) = crypt::encrypt(&piggy_ids, &passfile, std::io::Cursor::new(plaintext)) {
        eprintln!("piggy pass insert: {err}");
        eprintln!("Encryption aborted.");
        return 1;
    }

    if let Some(work_tree) = git_ops::find_inner_git_dir(&passfile, &root) {
        let _ = git_ops::add_and_commit(
            &work_tree,
            &passfile,
            &format!("Add given password for {} to store.", opts.path),
        );
    }

    0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    SilentTwice,
    Echo,
    Multiline,
}

#[derive(Debug)]
struct Opts {
    mode: Mode,
    force: bool,
    path: String,
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut multiline = false;
    let mut echo = false;
    let mut force = false;
    let mut positional: Vec<String> = Vec::new();
    let mut iter = args.iter();
    let usage = "Usage: piggy pass insert [--echo,-e | --multiline,-m] [--force,-f] pass-name";

    while let Some(arg) = iter.next() {
        let s = arg.as_str();
        if s == "--" {
            for rest in iter.by_ref() {
                positional.push(rest.clone());
            }
            break;
        } else if s == "-m" || s == "--multiline" {
            multiline = true;
        } else if s == "-e" || s == "--echo" {
            echo = true;
        } else if s == "-f" || s == "--force" {
            force = true;
        } else if s.starts_with('-') {
            return Err(usage.into());
        } else {
            positional.push(arg.clone());
        }
    }

    if multiline && echo {
        return Err(usage.into());
    }
    if positional.len() != 1 {
        return Err(usage.into());
    }
    let path = positional[0].trim_end_matches('/').to_string();
    let mode = if multiline {
        Mode::Multiline
    } else if echo {
        Mode::Echo
    } else {
        Mode::SilentTwice
    };
    Ok(Opts { mode, force, path })
}

fn collect_plaintext(mode: Mode, path: &str) -> Result<Vec<u8>, i32> {
    match mode {
        Mode::Multiline => {
            eprintln!("Enter contents of {path} and press Ctrl+D when finished:");
            eprintln!();
            let mut buf = Vec::new();
            if let Err(err) = std::io::stdin().lock().read_to_end(&mut buf) {
                eprintln!("piggy pass insert: read stdin: {err}");
                return Err(1);
            }
            Ok(buf)
        }
        Mode::Echo => {
            eprint!("Enter password for {path}: ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            if let Err(err) = std::io::stdin().lock().read_line(&mut line) {
                eprintln!("piggy pass insert: read stdin: {err}");
                return Err(1);
            }
            // The bash `read -r` strips a single trailing newline;
            // when the encrypt happens `echo "$password" | piggy_encrypt`
            // adds one back. Net effect: exactly one trailing newline.
            // We mirror by trimming any '\r'/'\n' the read picked up
            // and re-appending a single '\n'.
            trim_trailing_newline(&mut line);
            line.push('\n');
            Ok(line.into_bytes())
        }
        Mode::SilentTwice => {
            let first = read_password_silent(&format!("Enter password for {path}: "))?;
            let second = read_password_silent(&format!("Retype password for {path}: "))?;
            if first != second {
                eprintln!("Error: the entered passwords do not match.");
                return Err(1);
            }
            let mut out = first.into_bytes();
            out.push(b'\n');
            Ok(out)
        }
    }
}

/// Prompt + read one line with TTY echo suppressed for the duration
/// of the read. Mirrors bash `read -r -p "$prompt" -s password`. We
/// disable the controlling TTY's ECHO bit via termios for the read,
/// then restore, then print a newline (bash does the same: `read -s`
/// suppresses the user's own newline, then `echo` re-emits one).
fn read_password_silent(prompt: &str) -> Result<String, i32> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let line: String = if handle.fill_buf().map(|_| ()).is_err() {
        String::new()
    } else {
        // The bash `read -s` only suppresses TTY echo when stdin is a
        // TTY; piped stdin reads visible bytes. We mirror by only
        // toggling termios when stdin actually is a TTY.
        let echo_off = if std::io::stdin().is_terminal() {
            Some(EchoOff::install())
        } else {
            None
        };
        let mut buf = String::new();
        let res = handle.read_line(&mut buf);
        std::mem::drop(echo_off);
        match res {
            Ok(_) => buf,
            Err(err) => {
                eprintln!();
                eprintln!("piggy pass insert: read stdin: {err}");
                return Err(1);
            }
        }
    };
    eprintln!();
    let mut s = line;
    trim_trailing_newline(&mut s);
    Ok(s)
}

fn trim_trailing_newline(s: &mut String) {
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
}

/// RAII guard that turns off the controlling TTY's ECHO bit on
/// construction and restores it on drop. Reaches for libc directly
/// rather than pulling in `rpassword` because piggy already depends
/// on `libc` (used by `tmpdir.rs` and clipboard env probing) and the
/// surface here is ~15 lines.
struct EchoOff {
    fd: std::os::unix::io::RawFd,
    saved: libc::termios,
}

impl EchoOff {
    fn install() -> Option<Self> {
        let stdin = std::io::stdin();
        let fd = stdin.as_raw_fd();
        let mut current: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut current) } != 0 {
            return None;
        }
        let saved = current;
        current.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &current) } != 0 {
            return None;
        }
        Some(Self { fd, saved })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

fn confirm(message: &str) -> bool {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        // Bash `yesno` returns 0 (i.e. "go ahead") without prompting
        // when stdin is not a TTY. Mirror.
        return true;
    }
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{message} [y/N] ");
    let _ = stderr.flush();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(_) => {
            let trimmed = line.trim();
            trimmed == "y" || trimmed == "Y"
        }
        Err(_) => false,
    }
}

/// `dirname -- "$path"` semantics, projected into the subfolder
/// argument shape `find_piggy_ids` expects.
fn path_parent_for_search(path: &str) -> String {
    let p = PathBuf::from(path);
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_string_lossy().into_owned(),
        _ => String::new(),
    }
}

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
    fn parse_default_silent_twice() {
        let o = parse_args(&s(&["cred1"])).unwrap();
        assert_eq!(o.mode, Mode::SilentTwice);
        assert!(!o.force);
        assert_eq!(o.path, "cred1");
    }

    #[test]
    fn parse_echo_short_and_long() {
        let o = parse_args(&s(&["-e", "cred1"])).unwrap();
        assert_eq!(o.mode, Mode::Echo);
        let o = parse_args(&s(&["--echo", "cred1"])).unwrap();
        assert_eq!(o.mode, Mode::Echo);
    }

    #[test]
    fn parse_multiline_short_and_long() {
        let o = parse_args(&s(&["-m", "cred1"])).unwrap();
        assert_eq!(o.mode, Mode::Multiline);
        let o = parse_args(&s(&["--multiline", "cred1"])).unwrap();
        assert_eq!(o.mode, Mode::Multiline);
    }

    #[test]
    fn parse_force_short_and_long() {
        let o = parse_args(&s(&["-f", "cred1"])).unwrap();
        assert!(o.force);
        let o = parse_args(&s(&["--force", "cred1"])).unwrap();
        assert!(o.force);
    }

    #[test]
    fn parse_combines_echo_and_force() {
        let o = parse_args(&s(&["-e", "-f", "cred1"])).unwrap();
        assert_eq!(o.mode, Mode::Echo);
        assert!(o.force);
    }

    #[test]
    fn parse_rejects_echo_and_multiline_combined() {
        let err = parse_args(&s(&["-e", "-m", "cred1"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn parse_rejects_zero_positionals() {
        let err = parse_args(&s(&["-e"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn parse_rejects_extra_positionals() {
        let err = parse_args(&s(&["-e", "a", "b"])).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn parse_strips_trailing_slash_from_path() {
        let o = parse_args(&s(&["folder/sub/"])).unwrap();
        assert_eq!(o.path, "folder/sub");
    }

    #[test]
    fn parent_for_search_strips_basename() {
        assert_eq!(path_parent_for_search("a/b/c"), "a/b");
    }

    #[test]
    fn parent_for_search_returns_empty_for_top_level() {
        assert_eq!(path_parent_for_search("cred1"), "");
    }

    #[test]
    fn sneaky_path_rejects_parent() {
        assert!(sneaky_path_reason("../etc").is_some());
        assert!(sneaky_path_reason("foo/../etc").is_some());
    }

    #[test]
    fn sneaky_path_accepts_normal() {
        assert!(sneaky_path_reason("a/b").is_none());
    }

    #[test]
    fn trim_trailing_newline_strips_lf_and_crlf() {
        let mut s = "x\n".to_string();
        trim_trailing_newline(&mut s);
        assert_eq!(s, "x");
        let mut s = "x\r\n".to_string();
        trim_trailing_newline(&mut s);
        assert_eq!(s, "x");
        let mut s = "x".to_string();
        trim_trailing_newline(&mut s);
        assert_eq!(s, "x");
    }
}
