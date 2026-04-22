# Design: Default SSH_ASKPASS / SSH_NOTIFY_SEND / SSH_CONFIRM in install-service

## Problem

pivy-agent supports `SSH_ASKPASS`, `SSH_NOTIFY_SEND`, and `SSH_CONFIRM`
environment variables for PIN prompts, touch notifications, and connection
confirmations. However, `install-service` does not set these in the generated
service files, so users must configure them manually.

On macOS, the situation is worse: the common tools (`terminal-notifier`,
`osascript`) use named flags rather than the positional arguments pivy-agent
passes, so they can't be used directly without wrapper scripts.

## Solution

Ship wrapper scripts as part of the pivy nix package and have `install-service`
set the environment variables by default, with opt-out flags.

## Wrapper Scripts

Installed to `$out/libexec/pivy/`.

### `pivy-askpass`

Zenity-based, cross-platform (zenity builds on both Linux and macOS in nixpkgs):

```sh
#!/bin/sh
exec zenity --password --title="$1"
```

Zenity `--password` reads input via GUI dialog and prints to stdout, matching
pivy-agent's `try_askpass` calling convention: `execlp(askpass, askpass, prompt,
NULL)`, read PIN from child's stdout.

### `pivy-notify`

Platform-conditional, bridges pivy-agent's positional `(title, msg)` convention:

```sh
#!/bin/sh
case "$(uname)" in
  Darwin) exec terminal-notifier -title "$1" -message "$2" ;;
  *)      exec notify-send "$1" "$2" ;;
esac
```

pivy-agent calls: `execlp(notify, notify, title, msg, NULL)`.

- `notify-send` accepts positional args directly — no wrapper needed on Linux,
  but we use one for consistency and to bake in the nix store path.
- `terminal-notifier` requires `-title` and `-message` named flags — the wrapper
  translates.

## Nix Packaging Changes (`flake.nix`)

Add dependencies:

- `zenity` — both platforms (askpass + confirm)
- `libnotify` — Linux only (notify-send for pivy-notify)
- `terminal-notifier` — Darwin only (for pivy-notify)

In `installPhase`:

- Install wrapper scripts to `$out/libexec/pivy/`
- Bake in absolute nix store paths to dependencies (e.g.,
  `${pkgs.zenity}/bin/zenity` instead of bare `zenity`)

## C Code Changes (`src/pivy-agent.c`)

### New flags for `install-service`

- `--no-askpass` — suppress `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE` from the
  generated service file
- `--no-notify` — suppress `SSH_NOTIFY_SEND` from the generated service file

These are long-only options (no single-char flag) to avoid conflicts with the
existing getopt string.

### Path resolution

Derive `libexec_dir` from `exe_path` the same way `exe_dir` is already derived
on Linux. The wrapper scripts live at `<libexec_dir>/../libexec/pivy/`.

For nix builds, `exe_path` is an absolute nix store path, so this resolves
correctly.

### Linux (systemd unit)

Add `Environment=` lines after the existing ones:

```ini
Environment=SSH_ASKPASS=<libexec>/pivy-askpass
Environment=SSH_ASKPASS_REQUIRE=force
Environment=SSH_NOTIFY_SEND=<libexec>/pivy-notify
Environment=SSH_CONFIRM=<zenity_path>
```

### macOS (plist)

Add an `EnvironmentVariables` dict before the closing `</dict>`:

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>SSH_ASKPASS</key>
    <string><libexec>/pivy-askpass</string>
    <key>SSH_ASKPASS_REQUIRE</key>
    <string>force</string>
    <key>SSH_NOTIFY_SEND</key>
    <string><libexec>/pivy-notify</string>
    <key>SSH_CONFIRM</key>
    <string><zenity_path></string>
</dict>
```

`SSH_ASKPASS_REQUIRE=force` is needed on macOS because `DISPLAY` is typically
not set (no X11), and without it the askpass program may be skipped.

## Bats Tests

- Verify generated plist contains `EnvironmentVariables` dict with
  `SSH_ASKPASS`, `SSH_NOTIFY_SEND`, `SSH_CONFIRM`
- Verify `--no-askpass` suppresses `SSH_ASKPASS` and `SSH_ASKPASS_REQUIRE`
- Verify `--no-notify` suppresses `SSH_NOTIFY_SEND`
- Verify systemd unit contains the `Environment=` lines (Linux-only test, or
  skip on Darwin)

## Deferred

- C-level `terminal-notifier` auto-detection in `send_touch_notify` (add
  basename detection like existing `zenity`/`notify-send` detection in
  `try_confirm_client`). This would allow users to set
  `SSH_NOTIFY_SEND=terminal-notifier` directly without a wrapper.

## Scope

- Wrapper scripts: 2 files, ~5 lines each
- flake.nix: add 3 dependencies, install wrapper scripts in installPhase
- pivy-agent.c: ~40 lines of new fprintf output, ~15 lines for opt-out flag
  parsing
- Bats tests: ~4 new test functions
