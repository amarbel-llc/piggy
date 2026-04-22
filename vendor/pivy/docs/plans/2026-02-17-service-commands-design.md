# Design: pivy-agent install-service / restart-service / uninstall-service

## Problem

Installing pivy-agent as a system service currently requires manual steps:
writing config files, substituting placeholders in service templates, and
running platform-specific service manager commands. The macOS `.pkg`
postinstall script automates this but only for that install path.

## Solution

Add subcommands to pivy-agent itself:

```
pivy-agent install-service [-g guid] [-K cak] [-A] [-a socket]
pivy-agent restart-service
pivy-agent uninstall-service
```

## CLI Interface

Subcommands are detected as positional `argv[1]` before the existing getopt
loop runs. All existing flag-only invocations are unaffected.

`install-service` reuses the same `-g`, `-K`, `-A`, `-a` flags already in the
getopt string. If neither `-g` nor `-A` is provided, auto-detect from an
inserted card.

## Card Auto-Detection

When `-g` and `-A` are both omitted from `install-service`:

1. Open PCSC context, call `piv_enumerate()` to find inserted tokens
2. One token found: use its GUID and 9E public key as CAK
3. Zero tokens: error with "Insert a PIV token and retry, or pass -g explicitly"
4. Multiple tokens: error listing the GUIDs, ask user to pick with `-g`

## Platform Behavior

### Linux (systemd)

**install-service:**

1. Get own exe path via `readlink("/proc/self/exe")`
2. Write env config to `~/.config/pivy-agent/default`:
   ```
   PIV_AGENT_GUID=<guid>
   PIV_AGENT_CAK=<cak>
   ```
3. Generate `pivy-agent@.service` with correct binary path (no `@@BINDIR@@`
   placeholder -- write the unit file directly with the resolved path)
4. Install to `~/.config/systemd/user/pivy-agent@.service`
5. `systemctl --user daemon-reload && systemctl --user enable --now pivy-agent@default.service`
6. Print the socket path: `$XDG_RUNTIME_DIR/piv-ssh-default.socket`

**restart-service:**
`systemctl --user restart pivy-agent@default.service`

**uninstall-service:**
`systemctl --user disable --now pivy-agent@default.service`, remove unit file
and config.

### macOS (launchd)

**install-service:**

1. Get own exe path via `_NSGetExecutablePath()`
2. Generate plist with resolved binary path, GUID, CAK, HOME
3. Install to `~/Library/LaunchAgents/net.cooperi.pivy-agent.plist`
4. `launchctl load ~/Library/LaunchAgents/net.cooperi.pivy-agent.plist`
5. Print the socket path: `~/.ssh/pivy-agent.sock`

**restart-service:**
`launchctl kickstart -k gui/<uid>/net.cooperi.pivy-agent`

**uninstall-service:**
`launchctl unload` the plist, remove it.

### -A (all-card) mode

On Linux: config file omits `PIV_AGENT_GUID`/`PIV_AGENT_CAK`, adds `-A` to
`PIV_AGENT_OPTS`.

On macOS: plist uses `-A` instead of `-g`/`-K` arguments.

## Implementation Structure

All code in `src/pivy-agent.c`. No new files or build dependencies.

1. **Subcommand dispatch** (~15 lines) -- top of `main()`, before existing init
2. **`get_self_exe_path()`** (~20 lines) -- platform-specific binary path discovery
3. **`detect_card()`** (~40 lines) -- PCSC enumerate, return GUID + 9E CAK
4. **`cmd_install_service()`** (~120 lines) -- parse flags, detect card, write
   config/service files, enable service
5. **`cmd_restart_service()`** (~20 lines) -- exec into systemctl/launchctl
6. **`cmd_uninstall_service()`** (~30 lines) -- stop, disable, remove files

Estimated ~250 lines of C. Platform selection via `#if defined(__APPLE__)` /
`#if defined(__linux__)`, matching existing patterns in pivy-agent.c.

Service file content is generated directly in C (fprintf), not read from
template files at runtime. The existing template files remain for
Makefile-based installs.

## Scope

- Platforms: Linux + macOS
- Instance naming: `default` only (multi-instance later)
- Shell profile setup: not included (just print the socket path)
