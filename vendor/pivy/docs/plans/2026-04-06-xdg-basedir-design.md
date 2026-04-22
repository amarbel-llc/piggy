# XDG Base Directory Migration

Addresses [#6](https://github.com/amarbel-llc/pivy/issues/6) and
[#7](https://github.com/amarbel-llc/pivy/issues/7).

## Problem

pivy stores user data in platform-specific, non-XDG paths:

- Templates: `~/.pivy/tpl/` (Linux), `~/Library/Preferences/pivy/tpl/` (macOS)
- Agent config: hardcoded `~/.config/pivy-agent/` (no `$XDG_CONFIG_HOME`)
- Agent logs: `~/Library/Logs/pivy-agent.log` (macOS)

These don't follow the [XDG Base Directory
Specification](https://specifications.freedesktop.org/basedir-spec/latest/),
extended by [amarbel-llc/xdg](https://github.com/amarbel-llc/xdg) with
`$XDG_LOG_HOME` (default `$HOME/.local/log`) and `$XDG_LOG_DIRS`.

## Design

### Shared helper: `src/xdg.c` and `src/xdg.h`

Added to `_PIV_COMMON_SOURCES` so all binaries get it.

Functions (all return `malloc`'d strings, caller frees):

| Function             | Env var            | Default              |
|----------------------|--------------------|----------------------|
| `xdg_config_home()`  | `$XDG_CONFIG_HOME` | `$HOME/.config`      |
| `xdg_data_home()`    | `$XDG_DATA_HOME`   | `$HOME/.local/share` |
| `xdg_state_home()`   | `$XDG_STATE_HOME`  | `$HOME/.local/state` |
| `xdg_log_home()`     | `$XDG_LOG_HOME`    | `$HOME/.local/log`   |
| `xdg_cache_home()`   | `$XDG_CACHE_HOME`  | `$HOME/.cache`       |
| `xdg_runtime_dir()`  | `$XDG_RUNTIME_DIR` | `NULL`               |

Plus `xdg_mkdir_p(path, mode)` to create directories with parents.

For `pam_pivy.c` (which resolves paths for a target user, not the calling
process), helpers accept an explicit `home` parameter to avoid relying on
`$HOME`.

### ebox-cmd.c (Issue #6)

Template search order:

1. `$XDG_CONFIG_HOME/pivy/tpl/$TPL` (new default, read/write)
2. `$HOME/.pivy/tpl/$TPL` (legacy, read-only fallback)
3. `$HOME/.ebox/tpl/$TPL` (legacy, read-only fallback, existing)
4. `$PIVY_EBOX_TPL_PATH` entries (unchanged)
5. `/etc/pivy/tpl/$TPL` (system-wide, unchanged)

`EBOX_USER_TPL_PATH` macro changes to `$XDG_CONFIG_HOME/pivy/tpl/$TPL`. The
`compose_path()` system already supports `$ENV_VAR` segments, so
`XDG_CONFIG_HOME` works with existing infrastructure.

Writes always go to entry 1 (XDG path).

### pivy-agent.c (Issue #7)

**Linux install-service:**

- Config: `$XDG_CONFIG_HOME/pivy-agent/default` (via `xdg_config_home()`)
- Systemd unit: `$XDG_CONFIG_HOME/systemd/user/pivy-agent@.service`
- Socket: already XDG-compliant (`$XDG_STATE_HOME/ssh/`), no change

**macOS install-service:**

- Plist: stays at `~/Library/LaunchAgents/net.cooperi.pivy-agent.plist`
  (launchctl requirement)
- Log: `$XDG_LOG_HOME/pivy/pivy-agent.log` (was `~/Library/Logs/`)

**uninstall-service:** checks both XDG and legacy paths when removing.

### pam_pivy.c

`PIVY_AGENT_ENV_DIR` uses `$XDG_CONFIG_HOME/pivy-agent` with fallback to
`$HOME/.config/pivy-agent` (constructed from passwd home dir).

### Files modified

1. `src/xdg.c` (new)
2. `src/xdg.h` (new)
3. `src/ebox-cmd.c`
4. `src/pivy-agent.c`
5. `src/pam_pivy.c`
6. `Makefile`

## Rollback

Legacy paths remain as read-only fallbacks permanently. New files are always
written to XDG paths. Reverting the commit restores the old behavior with no
data loss.
