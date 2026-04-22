# XDG Base Directory Migration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Migrate all pivy file storage paths to XDG Base Directory spec (with amarbel-llc/xdg extensions).

**Architecture:** A shared `src/xdg.c`/`src/xdg.h` library provides XDG path resolution for all binaries. Each consumer (ebox-cmd, pivy-agent, pam_pivy) is updated to use the helpers. Legacy paths remain as read-only fallbacks.

**Tech Stack:** C (no new dependencies beyond libc)

**Rollback:** Revert the commits. Legacy paths are never removed, so old installs continue working.

---

### Task 1: Create `src/xdg.h` and `src/xdg.c`

**Promotion criteria:** N/A (new code)

**Files:**
- Create: `src/xdg.h`
- Create: `src/xdg.c`
- Modify: `Makefile:314-326` (add to `_PIV_COMMON_SOURCES` and `_PIV_COMMON_HEADERS`)

**Step 1: Write `src/xdg.h`**

```c
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#ifndef _XDG_H
#define _XDG_H

/*
 * XDG Base Directory helpers.
 *
 * Each function returns a malloc'd string (caller frees).
 * The _for() variants accept an explicit home dir (for PAM modules
 * that resolve paths for a target user, not the calling process).
 *
 * Follows amarbel-llc/xdg spec v0.9 which adds XDG_LOG_HOME.
 */

/* $XDG_CONFIG_HOME, default $HOME/.config */
char *xdg_config_home(void);
char *xdg_config_home_for(const char *home);

/* $XDG_DATA_HOME, default $HOME/.local/share */
char *xdg_data_home(void);
char *xdg_data_home_for(const char *home);

/* $XDG_STATE_HOME, default $HOME/.local/state */
char *xdg_state_home(void);
char *xdg_state_home_for(const char *home);

/* $XDG_LOG_HOME, default $HOME/.local/log (amarbel-llc/xdg extension) */
char *xdg_log_home(void);
char *xdg_log_home_for(const char *home);

/* $XDG_CACHE_HOME, default $HOME/.cache */
char *xdg_cache_home(void);
char *xdg_cache_home_for(const char *home);

/* $XDG_RUNTIME_DIR, no default (returns NULL if unset) */
char *xdg_runtime_dir(void);

/*
 * Create directory and parents with given mode.
 * Returns 0 on success, -1 on error (errno set).
 */
int xdg_mkdir_p(const char *path, mode_t mode);

#endif /* _XDG_H */
```

**Step 2: Write `src/xdg.c`**

```c
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

#include "xdg.h"

static char *
xdg_dir(const char *env, const char *home, const char *suffix)
{
	const char *val;
	char *buf;

	if (env != NULL) {
		val = getenv(env);
		if (val != NULL && val[0] == '/')
			return (strdup(val));
	}

	if (home == NULL)
		return (NULL);

	buf = malloc(PATH_MAX);
	if (buf == NULL)
		return (NULL);
	snprintf(buf, PATH_MAX, "%s/%s", home, suffix);
	return (buf);
}

static char *
xdg_dir_env(const char *env, const char *suffix)
{
	const char *home = getenv("HOME");
	return (xdg_dir(env, home, suffix));
}

char *
xdg_config_home(void)
{
	return (xdg_dir_env("XDG_CONFIG_HOME", ".config"));
}

char *
xdg_config_home_for(const char *home)
{
	return (xdg_dir("XDG_CONFIG_HOME", home, ".config"));
}

char *
xdg_data_home(void)
{
	return (xdg_dir_env("XDG_DATA_HOME", ".local/share"));
}

char *
xdg_data_home_for(const char *home)
{
	return (xdg_dir("XDG_DATA_HOME", home, ".local/share"));
}

char *
xdg_state_home(void)
{
	return (xdg_dir_env("XDG_STATE_HOME", ".local/state"));
}

char *
xdg_state_home_for(const char *home)
{
	return (xdg_dir("XDG_STATE_HOME", home, ".local/state"));
}

char *
xdg_log_home(void)
{
	return (xdg_dir_env("XDG_LOG_HOME", ".local/log"));
}

char *
xdg_log_home_for(const char *home)
{
	return (xdg_dir("XDG_LOG_HOME", home, ".local/log"));
}

char *
xdg_cache_home(void)
{
	return (xdg_dir_env("XDG_CACHE_HOME", ".cache"));
}

char *
xdg_cache_home_for(const char *home)
{
	return (xdg_dir("XDG_CACHE_HOME", home, ".cache"));
}

char *
xdg_runtime_dir(void)
{
	return (xdg_dir_env("XDG_RUNTIME_DIR", NULL));
}

int
xdg_mkdir_p(const char *path, mode_t mode)
{
	char buf[PATH_MAX];
	size_t len;
	size_t i;

	len = strlcpy(buf, path, sizeof (buf));
	if (len >= sizeof (buf)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	for (i = 1; i < len; ++i) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		if (mkdir(buf, mode) != 0 && errno != EEXIST)
			return (-1);
		buf[i] = '/';
	}
	if (mkdir(buf, mode) != 0 && errno != EEXIST)
		return (-1);
	return (0);
}
```

**Step 3: Add to Makefile**

In `_PIV_COMMON_SOURCES` (line 314), add `xdg.c` after `slot-spec.c`:

```makefile
_PIV_COMMON_SOURCES=		\
	piv.c			\
	...
	slot-spec.c		\
	xdg.c
```

In `_PIV_COMMON_HEADERS` (line 328), add `xdg.h`:

```makefile
_PIV_COMMON_HEADERS=		\
	piv.h			\
	...
	utils.h			\
	xdg.h
```

**Step 4: Verify it compiles**

Run: `just build` (or `nix build`)
Expected: clean build, no warnings from xdg.c

**Step 5: Commit**

```
feat: add XDG Base Directory helpers (xdg.c/xdg.h)

Shared library for resolving XDG paths with env var override and
defaults per amarbel-llc/xdg spec v0.9 (includes XDG_LOG_HOME).
Provides _for() variants for PAM modules that resolve paths for
a target user. Includes xdg_mkdir_p() for recursive dir creation.

Part of #6 and #7.
```

---

### Task 2: Fix underscore parsing in `parse_tpl_path_segs()`

**Promotion criteria:** N/A (bug fix)

**Files:**
- Modify: `src/ebox-cmd.c:1175-1178`

The env var parser in `parse_tpl_path_segs()` doesn't accept `_` in env var
names. `$XDG_CONFIG_HOME` would be parsed as `$XDG` + literal `_CONFIG_HOME`.
This must be fixed before Task 3.

**Step 1: Fix the character class**

At `src/ebox-cmd.c:1175-1178`, add `*p == '_'` to the while condition:

```c
			while (*p != '\0' && (
			    (*p >= 'A' && *p <= 'Z') ||
			    (*p >= 'a' && *p <= 'z') ||
			    (*p >= '0' && *p <= '9') ||
			    *p == '_')) {
```

**Step 2: Verify it compiles**

Run: `just build` (or `nix build`)
Expected: clean build

**Step 3: Commit**

```
fix: allow underscores in env var names in template path parser

The parse_tpl_path_segs() character class only accepted [A-Za-z0-9],
so $XDG_CONFIG_HOME was parsed as $XDG followed by literal _CONFIG_HOME.
Add underscore to the valid character set.

Part of #6.
```

---

### Task 3: Migrate ebox template paths to XDG (Issue #6)

**Promotion criteria:** N/A (legacy fallback is permanent)

**Files:**
- Modify: `src/ebox-cmd.c:67-68` (EBOX_USER_TPL_PATH macro)
- Modify: `src/ebox-cmd.c:1206-1262` (parse_tpl_path_env — add legacy fallback)

**Step 1: Change the default macro**

At `src/ebox-cmd.c:67-68`, change:

```c
#if !defined(EBOX_USER_TPL_PATH)
#define	EBOX_USER_TPL_PATH	"$XDG_CONFIG_HOME/pivy/tpl/$TPL"
#endif
```

**Step 2: Add legacy `~/.pivy/tpl/` as read-only fallback**

In `parse_tpl_path_env()` at `src/ebox-cmd.c:1220`, after the
`EBOX_USER_TPL_PATH` entry and before the existing `NO_LEGACY_EBOX_TPL_PATH`
block, add a new legacy entry:

```c
	/* Legacy ~/.pivy/tpl/ path (read-only fallback) */
	tpe = calloc(1, sizeof (*tpe));
	if (ebox_tpl_path == NULL)
		ebox_tpl_path = tpe;
	if (last != NULL)
		last->tpe_next = tpe;
	tpe->tpe_path_tpl = strdup("$HOME/.pivy/tpl/$TPL");
	tpe->tpe_segs = parse_tpl_path_segs(tpe->tpe_path_tpl);
	last = tpe;
```

This goes between the current EBOX_USER_TPL_PATH block (line 1213-1220) and the
`NO_LEGACY_EBOX_TPL_PATH` block (line 1222). The old `$HOME/.pivy/tpl/$TPL`
that was previously in EBOX_USER_TPL_PATH is now a fallback.

The resulting search order is:
1. `$XDG_CONFIG_HOME/pivy/tpl/$TPL` (from EBOX_USER_TPL_PATH)
2. `$HOME/.pivy/tpl/$TPL` (new legacy fallback)
3. `$HOME/.ebox/tpl/$TPL` (existing legacy, guarded by NO_LEGACY_EBOX_TPL_PATH)
4. `$PIVY_EBOX_TPL_PATH` entries
5. `/etc/pivy/tpl/$TPL` (EBOX_SYSTEM_TPL_PATH)

**Step 3: Verify it compiles**

Run: `just build` (or `nix build`)
Expected: clean build

**Step 4: Commit**

```
feat: migrate ebox templates to XDG_CONFIG_HOME

Default template path is now $XDG_CONFIG_HOME/pivy/tpl/ instead of
~/.pivy/tpl/. Legacy paths (~/.pivy/tpl/ and ~/.ebox/tpl/) remain
as read-only fallbacks so existing templates are still found.

Fixes #6.
```

---

### Task 4: Migrate pivy-agent install-service to XDG (Issue #7)

**Promotion criteria:** N/A (legacy paths checked on uninstall)

**Files:**
- Modify: `src/pivy-agent.c:64` (add xdg.h include)
- Modify: `src/pivy-agent.c:3441-3523` (Linux install-service)
- Modify: `src/pivy-agent.c:3552-3639` (macOS install-service log path)
- Modify: `src/pivy-agent.c:3705-3761` (uninstall-service, both platforms)

**Step 1: Add include**

At `src/pivy-agent.c`, add `#include "xdg.h"` near the other local includes.
Find the right location by looking for the last `#include` of a local header
(e.g. `#include "bunyan.h"` or similar).

**Step 2: Linux install-service — use `xdg_config_home()`**

Replace the hardcoded `$HOME/.config` paths in `cmd_install_service()` (lines
3444-3481) with `xdg_config_home()`:

```c
#if defined(__linux__)
	exe_dir_buf = strdup(exe_path);
	exe_dir = dirname(exe_dir_buf);

	char *config_home = xdg_config_home();
	if (config_home == NULL)
		fatal("cannot determine XDG_CONFIG_HOME");

	/* Write config to $XDG_CONFIG_HOME/pivy-agent/default */
	snprintf(path, sizeof (path),
	    "%s/pivy-agent", config_home);
	if (xdg_mkdir_p(path, 0700) != 0)
		fatal("mkdir %s: %s", path, strerror(errno));

	snprintf(path, sizeof (path),
	    "%s/pivy-agent/default", config_home);
	f = fopen(path, "w");
	if (f == NULL)
		fatal("fopen %s: %s", path, strerror(errno));

	if (opt_allcard) {
		fprintf(f, "PIV_AGENT_OPTS=-A\n");
	} else {
		fprintf(f, "PIV_AGENT_GUID=%s\n", opt_guid);
		if (opt_cak != NULL)
			fprintf(f, "PIV_AGENT_CAK=%s\n", opt_cak);
	}
	fclose(f);
	fprintf(stderr, "Wrote %s\n", path);

	/* Write systemd unit to $XDG_CONFIG_HOME/systemd/user/ */
	snprintf(path, sizeof (path),
	    "%s/systemd/user", config_home);
	if (xdg_mkdir_p(path, 0700) != 0)
		fatal("mkdir %s: %s", path, strerror(errno));

	snprintf(path, sizeof (path),
	    "%s/systemd/user/pivy-agent@.service", config_home);
```

The rest of the systemd unit fprintf block stays the same except the
`EnvironmentFile` line must reference `config_home` instead of `%h/.config`:

```c
	fprintf(f,
	    ...
	    "EnvironmentFile=%s/pivy-agent/%%I\n",
	    config_home);
```

Add `free(config_home);` after the Linux block finishes (before the `#elif`).

**Step 3: macOS install-service — use `xdg_log_home()` for log path**

In the macOS `#elif defined(__APPLE__)` block, replace the log path (line 3606):

```c
	char *log_home = xdg_log_home();
	if (log_home == NULL)
		fatal("cannot determine XDG_LOG_HOME");

	snprintf(path, sizeof (path), "%s/pivy", log_home);
	if (xdg_mkdir_p(path, 0700) != 0)
		fatal("mkdir %s: %s", path, strerror(errno));

	/* ... in the plist fprintf, replace the StandardErrorPath line: */
	fprintf(f,
	    "    <key>StandardErrorPath</key>\n"
	    "    <string>%s/pivy/pivy-agent.log</string>\n",
	    opt_socket, log_home);

	free(log_home);
```

**Step 4: uninstall-service — check legacy paths too**

In `cmd_uninstall_service()` (line 3705), for Linux, replace the hardcoded
`$HOME/.config` paths with `xdg_config_home()` and also try legacy paths:

```c
#if defined(__linux__)
	char *config_home = xdg_config_home();
	...
	/* Try XDG path first, then legacy */
	snprintf(path, sizeof (path),
	    "%s/systemd/user/pivy-agent@.service", config_home);
	if (unlink(path) != 0) {
		/* Try legacy path */
		snprintf(path, sizeof (path),
		    "%s/.config/systemd/user/pivy-agent@.service", home);
		unlink(path);
	}
	/* ... same pattern for pivy-agent/default */
	free(config_home);
```

**Step 5: Verify it compiles**

Run: `just build` (or `nix build`)
Expected: clean build

**Step 6: Run existing bats tests**

Run: `just test-bats`
Expected: all existing install-service tests pass (they use `$HOME` in a temp
dir, so `xdg_config_home()` will fall back to `$HOME/.config` since
`XDG_CONFIG_HOME` is unset in the test environment — same behavior as before).

**Step 7: Commit**

```
feat: migrate pivy-agent install-service to XDG paths

Linux: config and systemd unit now use $XDG_CONFIG_HOME instead of
hardcoded ~/.config. macOS: log path uses $XDG_LOG_HOME/pivy/ instead
of ~/Library/Logs/. Plist stays in ~/Library/LaunchAgents/ (launchctl
requirement). Uninstall checks both XDG and legacy paths.

Part of #7.
```

---

### Task 5: Migrate pam_pivy to XDG

**Promotion criteria:** N/A (legacy fallback is permanent)

**Files:**
- Modify: `src/pam_pivy.c:71-73` (PIVY_AGENT_ENV_DIR and related macros)
- Modify: `src/pam_pivy.c:236-244` (config dir resolution in pam_sm_authenticate)

**Step 1: Add include and update macros**

Add `#include "xdg.h"` to `src/pam_pivy.c`.

The PAM module can't rely on `$XDG_CONFIG_HOME` being set for the target user
(it runs as root authenticating another user). Change the config dir resolution
at line 244 to use `xdg_config_home_for()`:

```c
	char *config_home = xdg_config_home_for(pwent->pw_dir);
	if (config_home == NULL) {
		res = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	snprintf(akpath, PATH_MAX, "%s/pivy-agent", config_home);
	d = opendir(akpath);
	if (d == NULL) {
		/* Fallback to legacy hardcoded path */
		snprintf(akpath, PATH_MAX, "%s/.config/pivy-agent",
		    pwent->pw_dir);
		d = opendir(akpath);
	}
```

Update the `PIVY_AGENT_ENV_FILE` usage (line 248) to construct the path from
`akpath` (which already has the resolved dir) rather than using the macro with
`pwent->pw_dir`.

Add `free(config_home)` in the `out:` cleanup block.

**Step 2: Verify it compiles**

Run: `just build` (or `nix build`)
Expected: clean build (pam_pivy.so is only built when `HAVE_PAM=yes`)

**Step 3: Commit**

```
feat: migrate pam_pivy config dir to XDG_CONFIG_HOME

Uses xdg_config_home_for() to resolve config path for the target user.
Falls back to legacy ~/.config/pivy-agent if XDG path doesn't exist.

Part of #7.
```

---

### Task 6: Add bats tests for XDG path behavior

**Promotion criteria:** N/A

**Files:**
- Modify: `zz-tests_bats/pivy_agent.bats` (add XDG-specific install-service tests)

**Step 1: Add test for XDG_CONFIG_HOME override**

```bash
function install_service_respects_xdg_config_home { # @test
  install_service_setup
  export XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/custom-config"
  run pivy-agent install-service -A
  assert_success
  if [[ "$(uname)" == "Darwin" ]]; then
    assert [ -f "$HOME/Library/LaunchAgents/net.cooperi.pivy-agent.plist" ]
  else
    assert [ -f "$XDG_CONFIG_HOME/pivy-agent/default" ]
    assert [ -f "$XDG_CONFIG_HOME/systemd/user/pivy-agent@.service" ]
  fi
}
```

**Step 2: Add test for XDG_LOG_HOME on macOS (if on macOS)**

```bash
function install_service_log_uses_xdg_log_home { # @test
  [[ "$(uname)" == "Darwin" ]] || skip "macOS only"
  install_service_setup
  export XDG_LOG_HOME="$BATS_TEST_TMPDIR/custom-log"
  run pivy-agent install-service -A
  assert_success
  assert [ -d "$XDG_LOG_HOME/pivy" ]
  run cat "$HOME/Library/LaunchAgents/net.cooperi.pivy-agent.plist"
  assert_output --partial "$XDG_LOG_HOME/pivy/pivy-agent.log"
}
```

**Step 3: Run tests**

Run: `just test-bats`
Expected: all tests pass

**Step 4: Commit**

```
test: add bats tests for XDG path overrides in install-service

Verifies that XDG_CONFIG_HOME and XDG_LOG_HOME are respected when
installing the pivy-agent service.

Part of #6 and #7.
```
