//! `clip` port — copy a string to the system clipboard and start a
//! detached worker that overwrites it after `CLIP_TIME` seconds.
//!
//! Mirrors `clip` in `src/piggy.sh:122` (Linux) and the macOS override
//! in `src/platform/darwin.sh:4`.
//!
//! Linux strategy:
//!   - prefer wl-copy / wl-paste if `WAYLAND_DISPLAY` is set + `wl-copy`
//!     is on PATH (respect `PIGGY_X_SELECTION=primary` → `--primary`),
//!   - else xclip if `DISPLAY` is set + `xclip` is on PATH
//!     (`-selection $X_SELECTION`, default `clipboard`),
//!   - else: error `No X11 or Wayland display and clipper detected`.
//!
//! macOS strategy: pbcopy / pbpaste.
//!
//! After picking the tool, the bash does this dance:
//!   1. `pkill -f "^$sleep_argv0"` — kill any prior outstanding clear
//!      from a previous `clip` call.  The `^…` anchor matters: this is
//!      a pgrep regex that compares against the full argv0 string set
//!      by `exec -a`, not against the binary path.  Anchoring with `^`
//!      keeps the kill from matching `something piggy sleep on …`.
//!   2. Snapshot the existing clipboard into a base64-encoded variable
//!      (bash can't hold binary; we don't need to — we hold the bytes
//!      as `Vec<u8>` and never round-trip through base64).
//!   3. Push the new value with the copy tool.
//!   4. Fork a background worker that sleeps for `CLIP_TIME`, then
//!      compares the clipboard to the value we pushed; if unchanged
//!      restore the snapshot, otherwise leave it alone (user changed
//!      it themselves).
//!   5. Print the user-facing "Copied $name to clipboard…" line.
//!
//! For step 9 we model the tool selection and assemble the argv lists
//! deterministically; we do NOT actually spawn the worker yet. That
//! comes in step 10 alongside the bash → Rust port of `show`. The
//! `copy_with_clear` entry point currently:
//!   - resolves the tool (env-driven, exposed as `select_tool`),
//!   - executes the initial copy step (pkill + paste-snapshot + copy),
//!   - returns the [`ClipPlan`] describing the deferred restoration
//!     step so step 10 can spawn the worker (and so tests can inspect
//!     it without forking subprocesses).
//!
//! All shell-out points go through the [`Runner`] trait so tests can
//! capture argv without spawning real binaries. Production uses
//! [`ProcessRunner`].

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

/// Resolved invocation: program name + argv. Stored as `OsString` so
/// callers can spawn directly with `Command::new(prog).args(args)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CopyInvocation {
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasteInvocation {
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
}

/// Result of picking a clipboard tool. Carries everything the
/// `clip` step needs: the copy & paste invocations, a human-readable
/// "display name" (matches bash `$display_name`), and the `sleep_argv0`
/// string used both for `pkill -f` and for `exec -a` argv-rename when
/// the worker is forked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClipperTool {
    pub(crate) copy: CopyInvocation,
    pub(crate) paste: PasteInvocation,
    pub(crate) display_name: OsString,
    pub(crate) sleep_argv0: String,
}

/// Errors from `select_tool` / `copy_with_clear`. The bash original
/// uses `die "Error: ..."` for all of these; we expose them as
/// structured values so step 10 can format consistently.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClipError {
    #[error("Error: No X11 or Wayland display and clipper detected")]
    NoDisplay,
    #[error("Error: Could not copy data to the clipboard ({0})")]
    CopyFailed(String),
}

/// Environment snapshot consumed by `select_tool`. Injected for
/// testability — production calls [`Env::from_process`].
#[derive(Debug, Clone, Default)]
pub(crate) struct Env {
    pub(crate) wayland_display: Option<OsString>,
    pub(crate) x_display: Option<OsString>,
    pub(crate) x_selection: String,
    /// Per-tool presence on PATH (driven by [`PathLookup`] in
    /// production; tests pass a precomputed map).
    pub(crate) has_wl_copy: bool,
    pub(crate) has_xclip: bool,
    pub(crate) has_pbcopy: bool,
    /// `id -u` output (uid). Used by the darwin sleep_argv0 string.
    pub(crate) uid: u32,
}

impl Env {
    /// Build an Env from real process state — `$WAYLAND_DISPLAY`,
    /// `$DISPLAY`, `$PIGGY_X_SELECTION` (defaulting to `clipboard`),
    /// and a PATH probe for each of `wl-copy`, `xclip`, `pbcopy`.
    pub(crate) fn from_process() -> Self {
        Self {
            wayland_display: std::env::var_os("WAYLAND_DISPLAY").filter(|s| !s.is_empty()),
            x_display: std::env::var_os("DISPLAY").filter(|s| !s.is_empty()),
            x_selection: std::env::var("PIGGY_X_SELECTION")
                .unwrap_or_else(|_| "clipboard".to_string()),
            has_wl_copy: which("wl-copy").is_some(),
            has_xclip: which("xclip").is_some(),
            has_pbcopy: which("pbcopy").is_some(),
            uid: unsafe { libc::getuid() } as u32,
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Decide which clipboard tool to use and assemble its argv. Pure
/// function over [`Env`] — no IO. Mirrors the chained `if/elif/else`
/// at the top of bash `clip`.
pub(crate) fn select_tool(env: &Env) -> Result<ClipperTool, ClipError> {
    let primary = env.x_selection == "primary";

    // macOS path: pbcopy/pbpaste. Bash darwin.sh has no DISPLAY check
    // because the macOS clipboard is always available; we mirror —
    // only require that `pbcopy` is on PATH.
    if cfg!(target_os = "macos") && env.has_pbcopy {
        return Ok(ClipperTool {
            copy: CopyInvocation {
                program: OsString::from("pbcopy"),
                args: vec![],
            },
            paste: PasteInvocation {
                program: OsString::from("pbpaste"),
                args: vec![],
            },
            display_name: OsString::from(format!("user {}", env.uid)),
            sleep_argv0: format!("piggy sleep for user {}", env.uid),
        });
    }

    if let Some(wl) = env.wayland_display.as_ref() {
        if env.has_wl_copy {
            let mut copy_args: Vec<OsString> = Vec::new();
            let mut paste_args: Vec<OsString> = vec![OsString::from("-n")];
            if primary {
                copy_args.push(OsString::from("--primary"));
                paste_args.push(OsString::from("--primary"));
            }
            return Ok(ClipperTool {
                copy: CopyInvocation {
                    program: OsString::from("wl-copy"),
                    args: copy_args,
                },
                paste: PasteInvocation {
                    program: OsString::from("wl-paste"),
                    args: paste_args,
                },
                display_name: wl.clone(),
                sleep_argv0: format!("piggy sleep on display {}", wl.to_string_lossy()),
            });
        }
    }

    if let Some(x) = env.x_display.as_ref() {
        if env.has_xclip {
            let sel = env.x_selection.clone();
            return Ok(ClipperTool {
                copy: CopyInvocation {
                    program: OsString::from("xclip"),
                    args: vec![OsString::from("-selection"), OsString::from(&sel)],
                },
                paste: PasteInvocation {
                    program: OsString::from("xclip"),
                    args: vec![
                        OsString::from("-o"),
                        OsString::from("-selection"),
                        OsString::from(&sel),
                    ],
                },
                display_name: x.clone(),
                sleep_argv0: format!("piggy sleep on display {}", x.to_string_lossy()),
            });
        }
    }

    Err(ClipError::NoDisplay)
}

/// A small command-executor abstraction so tests can capture argv.
///
/// `pkill(pattern)`        — `pkill -f "^pattern"`. Returns whether
///                            it matched (bash uses the exit code to
///                            decide whether to `sleep 0.5`).
/// `read_stdout(invocation)`— spawn the paste tool and capture stdout
///                            as raw bytes.
/// `write_stdin(invocation, bytes)` — spawn the copy tool, write
///                            `bytes` to stdin, wait for exit.
pub(crate) trait Runner {
    fn pkill(&self, pattern: &str) -> std::io::Result<bool>;
    fn read_stdout(&self, p: &PasteInvocation) -> std::io::Result<Vec<u8>>;
    fn write_stdin(&self, c: &CopyInvocation, bytes: &[u8]) -> std::io::Result<()>;
}

/// Real-process Runner used in production. The clipboard module
/// uses this; tests use a recording double.
pub(crate) struct ProcessRunner;

impl Runner for ProcessRunner {
    fn pkill(&self, pattern: &str) -> std::io::Result<bool> {
        use std::process::Command;
        // The bash uses `pkill -f "^$sleep_argv0"`. The leading `^` is
        // a regex anchor: we want to match argv0 starting with the
        // exact sleep_argv0 string, not any substring within a longer
        // argv. We forward it verbatim so the kill is the same
        // selection.
        let anchored = format!("^{pattern}");
        let status = Command::new("pkill")
            .arg("-f")
            .arg(&anchored)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        Ok(status.success())
    }

    fn read_stdout(&self, p: &PasteInvocation) -> std::io::Result<Vec<u8>> {
        use std::process::Command;
        let out = Command::new(&p.program).args(&p.args).output()?;
        // The bash uses `2>/dev/null | base64`; empty stdout on
        // failure is treated as "nothing to restore". Mirror by
        // returning whatever stdout we got (possibly empty) and
        // swallowing exit-status failure.
        Ok(out.stdout)
    }

    fn write_stdin(&self, c: &CopyInvocation, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new(&c.program)
            .args(&c.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(bytes)?;
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "{} exited {}",
                c.program.to_string_lossy(),
                status,
            )));
        }
        Ok(())
    }
}

/// Plan returned by [`copy_with_clear`]. Step 10 spawns a detached
/// worker that:
///   1. sleeps `clip_time`,
///   2. reads the current clipboard via `paste`,
///   3. if it still matches `pushed_bytes`, writes `restore_bytes`
///      back via `copy`,
///   4. exits.
///
/// The worker registers itself under `sleep_argv0` so subsequent
/// `clip` calls can `pkill -f "^…"` it.
///
/// Returning the plan here keeps step 9 free of process-management
/// concerns and gives step 10 a clean handoff point.
#[derive(Debug, Clone)]
pub(crate) struct ClipPlan {
    pub(crate) copy: CopyInvocation,
    pub(crate) paste: PasteInvocation,
    pub(crate) sleep_argv0: String,
    pub(crate) clip_time: Duration,
    pub(crate) pushed_bytes: Vec<u8>,
    pub(crate) restore_bytes: Vec<u8>,
    pub(crate) user_message: String,
}

/// Bash `clip "$1" "$2"`:
///   - `text` = data to copy
///   - `name` = decorative name printed to the user
///   - `clip_time` = how long until the worker restores
///
/// `runner` is injected so unit tests can verify argv assembly and
/// the pkill-then-snapshot order without spawning subprocesses.
pub(crate) fn copy_with_clear(
    env: &Env,
    text: &[u8],
    name: &str,
    clip_time: Duration,
    runner: &dyn Runner,
) -> Result<ClipPlan, ClipError> {
    let tool = select_tool(env)?;
    copy_with_clear_using(&tool, text, name, clip_time, runner)
}

/// Variant that takes a pre-resolved [`ClipperTool`] — useful when
/// tests want to bypass `Env` (or when the caller has already done
/// tool selection).
pub(crate) fn copy_with_clear_using(
    tool: &ClipperTool,
    text: &[u8],
    name: &str,
    clip_time: Duration,
    runner: &dyn Runner,
) -> Result<ClipPlan, ClipError> {
    // 1. Clobber any prior outstanding clear worker.
    let killed = runner
        .pkill(&tool.sleep_argv0)
        .map_err(|e| ClipError::CopyFailed(format!("pkill: {e}")))?;
    if killed {
        // Bash sleeps 0.5s here to give the prior worker time to
        // restore the snapshot it was holding before we overwrite
        // the clipboard. Pure pacing — no functional effect on this
        // call, only on whether the prior worker wins the race. We
        // mirror the sleep so a back-to-back `piggy show -c` cycle
        // behaves the same as in bash.
        std::thread::sleep(Duration::from_millis(500));
    }

    // 2. Snapshot the existing clipboard.
    let before = runner
        .read_stdout(&tool.paste)
        .map_err(|e| ClipError::CopyFailed(format!("paste: {e}")))?;

    // 3. Push the new value.
    runner
        .write_stdin(&tool.copy, text)
        .map_err(|e| ClipError::CopyFailed(format!("copy: {e}")))?;

    Ok(ClipPlan {
        copy: tool.copy.clone(),
        paste: tool.paste.clone(),
        sleep_argv0: tool.sleep_argv0.clone(),
        clip_time,
        pushed_bytes: text.to_vec(),
        restore_bytes: before,
        user_message: format!(
            "Copied {} to clipboard. Will clear in {} seconds.",
            name,
            clip_time.as_secs(),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ffi::OsStr;

    fn env_wayland() -> Env {
        Env {
            wayland_display: Some(OsString::from("wayland-0")),
            x_display: None,
            x_selection: "clipboard".to_string(),
            has_wl_copy: true,
            has_xclip: false,
            has_pbcopy: false,
            uid: 1000,
        }
    }

    fn env_x11() -> Env {
        Env {
            wayland_display: None,
            x_display: Some(OsString::from(":0")),
            x_selection: "clipboard".to_string(),
            has_wl_copy: false,
            has_xclip: true,
            has_pbcopy: false,
            uid: 1000,
        }
    }

    fn env_empty() -> Env {
        Env {
            wayland_display: None,
            x_display: None,
            x_selection: "clipboard".to_string(),
            has_wl_copy: false,
            has_xclip: false,
            has_pbcopy: false,
            uid: 1000,
        }
    }

    #[test]
    fn select_wl_copy_when_wayland_and_tool_present() {
        let tool = select_tool(&env_wayland()).unwrap();
        assert_eq!(tool.copy.program, OsString::from("wl-copy"));
        assert!(tool.copy.args.is_empty());
        assert_eq!(tool.paste.program, OsString::from("wl-paste"));
        assert_eq!(tool.paste.args, vec![OsString::from("-n")]);
        assert_eq!(tool.display_name, OsString::from("wayland-0"));
        assert_eq!(tool.sleep_argv0, "piggy sleep on display wayland-0");
    }

    #[test]
    fn select_wl_copy_with_primary_selection() {
        let mut env = env_wayland();
        env.x_selection = "primary".to_string();
        let tool = select_tool(&env).unwrap();
        assert_eq!(tool.copy.args, vec![OsString::from("--primary")]);
        assert_eq!(
            tool.paste.args,
            vec![OsString::from("-n"), OsString::from("--primary")]
        );
    }

    #[test]
    fn select_xclip_when_only_x11() {
        let tool = select_tool(&env_x11()).unwrap();
        assert_eq!(tool.copy.program, OsString::from("xclip"));
        assert_eq!(
            tool.copy.args,
            vec![OsString::from("-selection"), OsString::from("clipboard")]
        );
        assert_eq!(tool.paste.program, OsString::from("xclip"));
        assert_eq!(
            tool.paste.args,
            vec![
                OsString::from("-o"),
                OsString::from("-selection"),
                OsString::from("clipboard"),
            ]
        );
        assert_eq!(tool.sleep_argv0, "piggy sleep on display :0");
    }

    #[test]
    fn select_xclip_with_primary_selection() {
        let mut env = env_x11();
        env.x_selection = "primary".to_string();
        let tool = select_tool(&env).unwrap();
        assert_eq!(
            tool.copy.args,
            vec![OsString::from("-selection"), OsString::from("primary")]
        );
        assert!(tool.paste.args.iter().any(|a| a == OsStr::new("primary")));
    }

    #[test]
    fn prefer_wayland_over_x11_when_both_available() {
        let mut env = env_wayland();
        env.x_display = Some(OsString::from(":0"));
        env.has_xclip = true;
        let tool = select_tool(&env).unwrap();
        assert_eq!(tool.copy.program, OsString::from("wl-copy"));
    }

    #[test]
    fn fall_through_to_xclip_when_wayland_set_but_no_wl_copy() {
        let mut env = env_x11();
        env.wayland_display = Some(OsString::from("wayland-0"));
        env.has_wl_copy = false;
        let tool = select_tool(&env).unwrap();
        assert_eq!(tool.copy.program, OsString::from("xclip"));
    }

    #[test]
    fn no_display_errors() {
        let err = select_tool(&env_empty()).unwrap_err();
        assert!(matches!(err, ClipError::NoDisplay));
        assert_eq!(
            err.to_string(),
            "Error: No X11 or Wayland display and clipper detected"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picks_pbcopy_with_no_display_set() {
        let mut env = env_empty();
        env.has_pbcopy = true;
        env.uid = 501;
        let tool = select_tool(&env).unwrap();
        assert_eq!(tool.copy.program, OsString::from("pbcopy"));
        assert_eq!(tool.paste.program, OsString::from("pbpaste"));
        assert_eq!(tool.sleep_argv0, "piggy sleep for user 501");
    }

    #[derive(Debug, Default)]
    struct RecordingRunner {
        pkill_calls: RefCell<Vec<String>>,
        pkill_match: bool,
        paste_calls: RefCell<Vec<PasteInvocation>>,
        paste_bytes: Vec<u8>,
        copy_calls: RefCell<Vec<(CopyInvocation, Vec<u8>)>>,
    }

    impl RecordingRunner {
        fn new(paste_bytes: Vec<u8>, pkill_match: bool) -> Self {
            Self {
                pkill_calls: RefCell::new(Vec::new()),
                pkill_match,
                paste_calls: RefCell::new(Vec::new()),
                paste_bytes,
                copy_calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Runner for RecordingRunner {
        fn pkill(&self, pattern: &str) -> std::io::Result<bool> {
            self.pkill_calls.borrow_mut().push(pattern.to_string());
            Ok(self.pkill_match)
        }
        fn read_stdout(&self, p: &PasteInvocation) -> std::io::Result<Vec<u8>> {
            self.paste_calls.borrow_mut().push(p.clone());
            Ok(self.paste_bytes.clone())
        }
        fn write_stdin(&self, c: &CopyInvocation, bytes: &[u8]) -> std::io::Result<()> {
            self.copy_calls
                .borrow_mut()
                .push((c.clone(), bytes.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn copy_with_clear_records_pkill_paste_copy_in_order() {
        let runner = RecordingRunner::new(b"prior-clipboard".to_vec(), false);
        let plan = copy_with_clear(
            &env_wayland(),
            b"new-secret",
            "Password",
            Duration::from_secs(45),
            &runner,
        )
        .unwrap();

        let pkill = runner.pkill_calls.borrow();
        assert_eq!(pkill.len(), 1);
        assert_eq!(pkill[0], "piggy sleep on display wayland-0");

        let paste = runner.paste_calls.borrow();
        assert_eq!(paste.len(), 1);
        assert_eq!(paste[0].program, OsString::from("wl-paste"));

        let copy = runner.copy_calls.borrow();
        assert_eq!(copy.len(), 1);
        assert_eq!(copy[0].0.program, OsString::from("wl-copy"));
        assert_eq!(copy[0].1, b"new-secret");

        assert_eq!(plan.pushed_bytes, b"new-secret");
        assert_eq!(plan.restore_bytes, b"prior-clipboard");
        assert_eq!(plan.sleep_argv0, "piggy sleep on display wayland-0");
        assert_eq!(plan.clip_time, Duration::from_secs(45));
        assert_eq!(
            plan.user_message,
            "Copied Password to clipboard. Will clear in 45 seconds."
        );
    }

    #[test]
    fn copy_with_clear_pkill_pattern_unanchored_at_layer() {
        // The Runner gets the bare pattern; the production
        // ProcessRunner adds the `^` anchor when invoking pkill. The
        // layering keeps the regex-anchor semantics testable without
        // dragging pkill into the test fixture.
        let runner = RecordingRunner::new(vec![], false);
        let _ = copy_with_clear(&env_x11(), b"x", "n", Duration::from_secs(1), &runner).unwrap();
        let pkill = runner.pkill_calls.borrow();
        assert_eq!(pkill[0], "piggy sleep on display :0");
    }
}
