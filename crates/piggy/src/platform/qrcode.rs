//! `qrcode` port — render a password as a QR code.
//!
//! Mirrors `qrcode` in `src/piggy.sh:166` (Linux) and the macOS
//! override in `src/platform/darwin.sh:35`.
//!
//! Linux strategy:
//!   - if a GUI display is available (`DISPLAY` or `WAYLAND_DISPLAY`)
//!     AND one of feh / gm / display is on PATH, pipe a PNG-rendered
//!     QR code into that viewer with `--title "piggy: $name"`,
//!   - otherwise emit `qrencode -t utf8` to stdout.
//!
//! macOS strategy:
//!   - if `imgcat` is on PATH, pipe a PNG QR into it,
//!   - otherwise emit `qrencode -t utf8` to stdout.
//!
//! Step 9 produces the [`Plan`] enum describing what to do; step 10
//! wires it to actual `Command::new` invocations alongside the
//! bash→Rust port of `show -q`. The pure-logic surface
//! ([`pick_viewer`], [`render_plan`]) is exhaustively unit-tested
//! here.

use std::ffi::OsString;

/// Per-platform list of GUI viewers, in fallback order. Mirrors the
/// `type feh / type gm / type display` chain in bash.
#[cfg(target_os = "macos")]
pub(crate) const VIEWERS: &[&str] = &["imgcat"];
#[cfg(not(target_os = "macos"))]
pub(crate) const VIEWERS: &[&str] = &["feh", "gm", "display"];

/// Argv (minus the binary name) for piping a PNG QR into the named
/// viewer. The trailing `-` reads from stdin in every case. Mirrors
/// the bash one-liner.
pub(crate) fn viewer_argv(viewer: &str, name: &str) -> Vec<OsString> {
    let title = format!("piggy: {name}");
    match viewer {
        "feh" => vec![
            OsString::from("-x"),
            OsString::from("--title"),
            OsString::from(title),
            OsString::from("-g"),
            OsString::from("+200+200"),
            OsString::from("-"),
        ],
        "gm" => vec![
            OsString::from("display"),
            OsString::from("-title"),
            OsString::from(title),
            OsString::from("-geometry"),
            OsString::from("+200+200"),
            OsString::from("-"),
        ],
        "display" => vec![
            OsString::from("-title"),
            OsString::from(title),
            OsString::from("-geometry"),
            OsString::from("+200+200"),
            OsString::from("-"),
        ],
        "imgcat" => vec![],
        // Unknown viewer — bare stdin reader. Defensive; should
        // never be hit because callers iterate VIEWERS.
        _ => vec![OsString::from("-")],
    }
}

/// Environment snapshot consumed by render planning.
#[derive(Debug, Clone, Default)]
pub(crate) struct Env {
    // Read only by the non-macOS `pick_viewer` branch; on macOS the
    // imgcat path returns before consulting either field.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub(crate) display: Option<OsString>,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub(crate) wayland_display: Option<OsString>,
    /// Map of viewer name → on-PATH presence.
    pub(crate) viewers_present: std::collections::BTreeMap<String, bool>,
}

impl Env {
    pub(crate) fn from_process() -> Self {
        let mut viewers_present = std::collections::BTreeMap::new();
        for v in VIEWERS {
            viewers_present.insert((*v).to_string(), which(v).is_some());
        }
        Self {
            display: std::env::var_os("DISPLAY").filter(|s| !s.is_empty()),
            wayland_display: std::env::var_os("WAYLAND_DISPLAY").filter(|s| !s.is_empty()),
            viewers_present,
        }
    }
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Choose a GUI viewer, if eligible. `None` means "fall back to
/// stdout text rendering".
///
/// On Linux: requires `DISPLAY` or `WAYLAND_DISPLAY` set, plus at
/// least one of [`VIEWERS`] on PATH (first match wins).
///
/// On macOS: ignores `DISPLAY` — `imgcat` works in any modern terminal
/// emulator that speaks the iTerm image protocol.
pub(crate) fn pick_viewer(env: &Env) -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        if env.viewers_present.get("imgcat").copied().unwrap_or(false) {
            return Some("imgcat");
        }
        None
    }
    #[cfg(not(target_os = "macos"))]
    {
        let has_display = env.display.is_some() || env.wayland_display.is_some();
        if !has_display {
            return None;
        }
        for v in VIEWERS {
            if env.viewers_present.get(*v).copied().unwrap_or(false) {
                return Some(v);
            }
        }
        None
    }
}

/// What `qrcode` should do for a given password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Pipe `qrencode --size 10 -o -` (PNG output) into
    /// `viewer args...`. Step 10 wires this with the standard
    /// process-spawn pattern from `reencrypt.rs`.
    Gui {
        viewer: &'static str,
        viewer_args: Vec<OsString>,
    },
    /// Render `qrencode -t utf8` to stdout. No GUI display
    /// available or no viewer on PATH.
    Stdout,
}

/// Build the plan from an environment + the password name (used in
/// the window title).
pub(crate) fn render_plan(env: &Env, name: &str) -> Plan {
    match pick_viewer(env) {
        Some(viewer) => Plan::Gui {
            viewer,
            viewer_args: viewer_argv(viewer, name),
        },
        None => Plan::Stdout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(viewers: &[(&str, bool)], display: bool, wayland: bool) -> Env {
        let mut env = Env::default();
        for (k, v) in viewers {
            env.viewers_present.insert((*k).to_string(), *v);
        }
        if display {
            env.display = Some(OsString::from(":0"));
        }
        if wayland {
            env.wayland_display = Some(OsString::from("wayland-0"));
        }
        env
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn picks_feh_when_first_in_chain() {
        let env = env_with(
            &[("feh", true), ("gm", true), ("display", true)],
            true,
            false,
        );
        assert_eq!(pick_viewer(&env), Some("feh"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn falls_back_to_gm_when_feh_missing() {
        let env = env_with(
            &[("feh", false), ("gm", true), ("display", true)],
            true,
            false,
        );
        assert_eq!(pick_viewer(&env), Some("gm"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn falls_back_to_display_when_feh_gm_missing() {
        let env = env_with(
            &[("feh", false), ("gm", false), ("display", true)],
            true,
            false,
        );
        assert_eq!(pick_viewer(&env), Some("display"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn no_viewer_when_no_display_set_even_with_tools() {
        let env = env_with(&[("feh", true)], false, false);
        assert_eq!(pick_viewer(&env), None);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn wayland_display_alone_is_enough_for_gui_path() {
        let env = env_with(&[("feh", true)], false, true);
        assert_eq!(pick_viewer(&env), Some("feh"));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn no_viewer_when_display_set_but_tools_missing() {
        let env = env_with(
            &[("feh", false), ("gm", false), ("display", false)],
            true,
            false,
        );
        assert_eq!(pick_viewer(&env), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_picks_imgcat_with_no_display() {
        let env = env_with(&[("imgcat", true)], false, false);
        assert_eq!(pick_viewer(&env), Some("imgcat"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_no_viewer_when_imgcat_missing() {
        let env = env_with(&[("imgcat", false)], true, false);
        assert_eq!(pick_viewer(&env), None);
    }

    #[test]
    fn viewer_argv_for_feh_has_title_and_geometry() {
        let argv = viewer_argv("feh", "secret/email");
        assert!(argv.contains(&OsString::from("--title")));
        assert!(argv.contains(&OsString::from("piggy: secret/email")));
        assert!(argv.contains(&OsString::from("-g")));
        assert!(argv.contains(&OsString::from("+200+200")));
        assert_eq!(argv.last(), Some(&OsString::from("-")));
    }

    #[test]
    fn viewer_argv_for_gm_starts_with_display_subcommand() {
        let argv = viewer_argv("gm", "x");
        assert_eq!(argv.first(), Some(&OsString::from("display")));
        assert!(argv.contains(&OsString::from("-title")));
        assert!(argv.contains(&OsString::from("piggy: x")));
        assert_eq!(argv.last(), Some(&OsString::from("-")));
    }

    #[test]
    fn viewer_argv_for_display_omits_subcommand() {
        let argv = viewer_argv("display", "x");
        assert_eq!(argv.first(), Some(&OsString::from("-title")));
        assert!(argv.contains(&OsString::from("piggy: x")));
        assert_eq!(argv.last(), Some(&OsString::from("-")));
    }

    #[test]
    fn viewer_argv_for_imgcat_is_empty() {
        let argv = viewer_argv("imgcat", "x");
        assert!(argv.is_empty());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn render_plan_stdout_when_no_display() {
        let env = env_with(&[("feh", true)], false, false);
        assert_eq!(render_plan(&env, "x"), Plan::Stdout);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn render_plan_gui_when_viewer_available() {
        let env = env_with(&[("feh", true)], true, false);
        match render_plan(&env, "my-pw") {
            Plan::Gui {
                viewer,
                viewer_args,
            } => {
                assert_eq!(viewer, "feh");
                assert!(viewer_args.contains(&OsString::from("piggy: my-pw")));
            }
            Plan::Stdout => panic!("expected GUI plan"),
        }
    }
}
