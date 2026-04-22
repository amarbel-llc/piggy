# SSH Environment Variable Defaults Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Have `pivy-agent install-service` automatically configure `SSH_ASKPASS`, `SSH_NOTIFY_SEND`, and `SSH_CONFIRM` in the generated service files using bundled wrapper scripts.

**Architecture:** Two small wrapper scripts (`pivy-askpass`, `pivy-notify`) installed to `$out/libexec/pivy/`. The nix `installPhase` bakes in absolute store paths to dependencies (zenity, notify-send, terminal-notifier). The C `cmd_install_service()` function writes these paths into the systemd unit / launchd plist. Opt-out via `--no-askpass` and `--no-notify` long flags.

**Tech Stack:** C (pivy-agent.c), Nix (flake.nix), Shell (wrapper scripts), Bats (tests)

---

### Task 1: Create wrapper scripts

**Files:**
- Create: `libexec/pivy-askpass`
- Create: `libexec/pivy-notify`

**Step 1: Create `libexec/` directory and `pivy-askpass`**

```sh
mkdir -p libexec
```

Write `libexec/pivy-askpass`:

```sh
#!/bin/sh
exec zenity --password --title="$1"
```

**Step 2: Create `pivy-notify`**

Write `libexec/pivy-notify`:

```sh
#!/bin/sh
case "$(uname)" in
  Darwin) exec terminal-notifier -title "$1" -message "$2" ;;
  *)      exec notify-send "$1" "$2" ;;
esac
```

**Step 3: Make both executable**

```bash
chmod +x libexec/pivy-askpass libexec/pivy-notify
```

**Step 4: Commit**

```bash
git add libexec/
git commit -m "feat: add pivy-askpass and pivy-notify wrapper scripts"
```

---

### Task 2: Update flake.nix to install wrapper scripts with baked-in paths

**Files:**
- Modify: `flake.nix:151-161` (buildInputs), `flake.nix:251-290` (installPhase)

**Step 1: Add dependencies to buildInputs**

In `flake.nix`, the `buildInputs` list at line 151 needs platform-conditional
additions. After the existing `pkgs.lib.optionals (!pkgs.stdenv.isDarwin)` block,
the wrapper scripts need runtime dependencies. These aren't C build inputs — they're
runtime deps for the wrapper scripts. Use `makeWrapper` or bake paths directly.

Add after the `nativeBuildInputs` definition (around line 171), a new variable for
the wrapper dependencies:

```nix
askpassDeps = [
  pkgs.zenity
] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
  pkgs.libnotify
] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
  pkgs.terminal-notifier
];
```

**Step 2: Install wrapper scripts in installPhase**

After the existing service file installation block (line 288), before
`runHook postInstall`, add:

```nix
# Install askpass/notify wrapper scripts with baked-in paths
mkdir -p $out/libexec/pivy

cat > $out/libexec/pivy/pivy-askpass <<'ASKPASS'
#!/bin/sh
exec ${pkgs.zenity}/bin/zenity --password --title="$1"
ASKPASS
chmod +x $out/libexec/pivy/pivy-askpass

cat > $out/libexec/pivy/pivy-notify <<NOTIFY
#!/bin/sh
case "\$(uname)" in
  Darwin) exec ${if pkgs.stdenv.isDarwin then "${pkgs.terminal-notifier}/bin/terminal-notifier" else "terminal-notifier"} -title "\$1" -message "\$2" ;;
  *)      exec ${if pkgs.stdenv.isLinux then "${pkgs.libnotify}/bin/notify-send" else "notify-send"} "\$1" "\$2" ;;
esac
NOTIFY
chmod +x $out/libexec/pivy/pivy-notify
```

Note: The `pivy-notify` script is generated at build time with platform-specific
paths baked in. The `case` is kept for when someone copies the binary outside nix,
but in practice only one branch will have a valid store path.

**Step 3: Build and verify**

```bash
nix build
```

Verify the wrapper scripts exist:

```bash
ls -la ./result/libexec/pivy/
cat ./result/libexec/pivy/pivy-askpass
cat ./result/libexec/pivy/pivy-notify
```

Expected: both scripts exist with absolute nix store paths baked in.

**Step 4: Commit**

```bash
git add flake.nix
git commit -m "feat(nix): install pivy-askpass and pivy-notify with baked-in deps"
```

---

### Task 3: Write bats tests for env vars in generated service files

**Files:**
- Modify: `zz-tests_bats/pivy_agent.bats`

**Step 1: Add test for plist containing env vars**

Add after the existing `install_service_reinstall_updates_socket_path` test
(line 63 in `pivy_agent.bats`):

```bash
function install_service_plist_contains_askpass_env { # @test
  local home="$BATS_TEST_TMPDIR/home"
  mkdir -p "$home/Library"
  local plist="$home/Library/LaunchAgents/net.cooperi.pivy-agent.plist"

  HOME="$home" run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$plist" ]
  run grep 'SSH_ASKPASS' "$plist"
  assert_success
  run grep 'SSH_ASKPASS_REQUIRE' "$plist"
  assert_success
  run grep 'force' "$plist"
  assert_success
}

function install_service_plist_contains_notify_env { # @test
  local home="$BATS_TEST_TMPDIR/home"
  mkdir -p "$home/Library"
  local plist="$home/Library/LaunchAgents/net.cooperi.pivy-agent.plist"

  HOME="$home" run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$plist" ]
  run grep 'SSH_NOTIFY_SEND' "$plist"
  assert_success
}

function install_service_plist_contains_confirm_env { # @test
  local home="$BATS_TEST_TMPDIR/home"
  mkdir -p "$home/Library"
  local plist="$home/Library/LaunchAgents/net.cooperi.pivy-agent.plist"

  HOME="$home" run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$plist" ]
  run grep 'SSH_CONFIRM' "$plist"
  assert_success
}
```

**Step 2: Add test for --no-askpass opt-out**

```bash
function install_service_no_askpass_omits_askpass_env { # @test
  local home="$BATS_TEST_TMPDIR/home"
  mkdir -p "$home/Library"
  local plist="$home/Library/LaunchAgents/net.cooperi.pivy-agent.plist"

  HOME="$home" run pivy-agent install-service -A -a /tmp/test.sock --no-askpass
  assert [ -f "$plist" ]
  run grep 'SSH_ASKPASS' "$plist"
  assert_failure
}
```

**Step 3: Add test for --no-notify opt-out**

```bash
function install_service_no_notify_omits_notify_env { # @test
  local home="$BATS_TEST_TMPDIR/home"
  mkdir -p "$home/Library"
  local plist="$home/Library/LaunchAgents/net.cooperi.pivy-agent.plist"

  HOME="$home" run pivy-agent install-service -A -a /tmp/test.sock --no-notify
  assert [ -f "$plist" ]
  run grep 'SSH_NOTIFY_SEND' "$plist"
  assert_failure
}
```

**Step 4: Run tests to verify they fail**

```bash
just test-bats
```

Expected: all new tests FAIL (env vars not yet written by install-service).

**Step 5: Commit**

```bash
git add zz-tests_bats/pivy_agent.bats
git commit -m "test: add bats tests for install-service env var defaults"
```

---

### Task 4: Add --no-askpass / --no-notify flag parsing to cmd_install_service

**Files:**
- Modify: `src/pivy-agent.c:3253-3289` (cmd_install_service flag parsing)

**Step 1: Add opt-out boolean variables**

At line 3263 in `cmd_install_service`, after `boolean_t opt_allcard = B_FALSE;`,
add:

```c
	boolean_t opt_no_askpass = B_FALSE;
	boolean_t opt_no_notify = B_FALSE;
```

**Step 2: Add long option parsing**

The existing `getopt` at line 3269 only handles short flags. Since `--no-askpass`
and `--no-notify` are long-only options, add a pre-scan loop before `getopt` that
strips them from `av`:

```c
	/* Pre-scan for long options */
	int i, j;
	for (i = 0, j = 0; i < ac; i++) {
		if (strcmp(av[i], "--no-askpass") == 0) {
			opt_no_askpass = B_TRUE;
		} else if (strcmp(av[i], "--no-notify") == 0) {
			opt_no_notify = B_TRUE;
		} else {
			av[j++] = av[i];
		}
	}
	ac = j;
	optind = 0;
```

Place this before the existing `while ((ch = getopt(...))` loop at line 3269.

**Step 3: Update usage string**

At line 3285, update the usage message:

```c
			fprintf(stderr,
			    "usage: pivy-agent install-service "
			    "[-g guid] [-K cak] [-A] [-a socket]\n"
			    "       [--no-askpass] [--no-notify]\n");
```

**Step 4: Build and run tests**

```bash
nix build && just test-bats
```

Expected: new tests still fail (flags parsed but env vars not yet written).

**Step 5: Commit**

```bash
git add src/pivy-agent.c
git commit -m "feat: add --no-askpass and --no-notify flags to install-service"
```

---

### Task 5: Compute libexec path from exe_path

**Files:**
- Modify: `src/pivy-agent.c:3253-3300` (cmd_install_service)

**Step 1: Add libexec_dir variable and computation**

After `exe_path = get_self_exe_path();` (line 3296), add code to derive the
libexec directory. The exe lives at `$out/bin/pivy-agent` and libexec is at
`$out/libexec/pivy/`. So we need `dirname(dirname(exe_path))/libexec/pivy`.

```c
	char libexec_dir[PATH_MAX];
	{
		char *tmp = strdup(exe_path);
		char *bindir = dirname(tmp);
		char *prefix = dirname(bindir);
		snprintf(libexec_dir, sizeof (libexec_dir),
		    "%s/libexec/pivy", prefix);
		free(tmp);
	}
```

Note: `dirname()` may modify its argument, so we use a strdup'd copy. Also,
the second `dirname()` call modifies the same buffer which is fine since we
only need the final result for `snprintf`.

Add to the `#if defined(__linux__)` variable block at line 3257:

Change:
```c
#if defined(__linux__)
	char *exe_dir, *exe_dir_buf;
#endif
```

To remove the `#if` guard from `exe_dir_buf` since we now need it on both
platforms, OR just declare `libexec_dir` unconditionally (which is what we do
above — it's declared after the `#endif`).

**Step 2: Build to verify compilation**

```bash
nix build
```

**Step 3: Commit**

```bash
git add src/pivy-agent.c
git commit -m "feat: compute libexec path from exe_path in install-service"
```

---

### Task 6: Write env vars into systemd unit (Linux)

**Files:**
- Modify: `src/pivy-agent.c:3395-3415` (systemd fprintf block)

**Step 1: Add Environment lines to the systemd unit**

In the `fprintf` that generates the systemd unit (line 3395), after the existing
`Environment=PIV_SLOTS=all\n` line, add conditionally:

After line 3402 (`"Environment=PIV_SLOTS=all\n"`), close the current fprintf
and add conditional blocks:

```c
	if (!opt_no_askpass) {
		fprintf(f,
		    "Environment=SSH_ASKPASS=%s/pivy-askpass\n"
		    "Environment=SSH_ASKPASS_REQUIRE=force\n"
		    "Environment=SSH_CONFIRM=%s/pivy-askpass\n",
		    libexec_dir, libexec_dir);
	}
	if (!opt_no_notify) {
		fprintf(f,
		    "Environment=SSH_NOTIFY_SEND=%s/pivy-notify\n",
		    libexec_dir);
	}
```

This requires splitting the existing single `fprintf` call into multiple calls.
The first `fprintf` ends after the `EnvironmentFile` line. Then the conditional
env var lines. Then the `ExecStartPre`, `ExecStart`, `Restart`, `[Install]`
section in the final `fprintf`.

**Step 2: Build and verify**

```bash
nix build
```

Note: Tests are macOS-only (plist tests), so we can't test the systemd path
on Darwin. Verify manually by inspecting the generated service file.

**Step 3: Commit**

```bash
git add src/pivy-agent.c
git commit -m "feat: write SSH env vars into generated systemd unit"
```

---

### Task 7: Write env vars into launchd plist (macOS)

**Files:**
- Modify: `src/pivy-agent.c:3494-3507` (plist fprintf block)

**Step 1: Add EnvironmentVariables dict to plist**

In the `fprintf` block starting at line 3494, before the closing `</dict>` and
`</plist>` tags, insert the `EnvironmentVariables` dict.

The current code at line 3494 writes:
```
    </array>
    <key>StandardErrorPath</key>
    ...
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Split this fprintf. After the `</array>` line and `StandardErrorPath`, add:

```c
	if (!opt_no_askpass || !opt_no_notify) {
		fprintf(f,
		    "    <key>EnvironmentVariables</key>\n"
		    "    <dict>\n");
		if (!opt_no_askpass) {
			fprintf(f,
			    "        <key>SSH_ASKPASS</key>\n"
			    "        <string>%s/pivy-askpass</string>\n"
			    "        <key>SSH_ASKPASS_REQUIRE</key>\n"
			    "        <string>force</string>\n"
			    "        <key>SSH_CONFIRM</key>\n"
			    "        <string>%s/pivy-askpass</string>\n",
			    libexec_dir, libexec_dir);
		}
		if (!opt_no_notify) {
			fprintf(f,
			    "        <key>SSH_NOTIFY_SEND</key>\n"
			    "        <string>%s/pivy-notify</string>\n",
			    libexec_dir);
		}
		fprintf(f,
		    "    </dict>\n");
	}
```

Place this before the `RunAtLoad` / `KeepAlive` / closing tags fprintf.

**Step 2: Build and run tests**

```bash
nix build && just test-bats
```

Expected: all new bats tests PASS.

**Step 3: Commit**

```bash
git add src/pivy-agent.c
git commit -m "feat: write SSH env vars into generated launchd plist"
```

---

### Task 8: Final verification

**Step 1: Full build**

```bash
nix build
```

**Step 2: Run all bats tests**

```bash
just test-bats
```

Expected: all tests pass.

**Step 3: Verify wrapper scripts in output**

```bash
cat ./result/libexec/pivy/pivy-askpass
cat ./result/libexec/pivy/pivy-notify
```

Expected: scripts contain absolute nix store paths to zenity, notify-send or
terminal-notifier.

**Step 4: Verify install-service output (dry run)**

```bash
HOME=/tmp/pivy-test-home ./result/bin/pivy-agent install-service -A -a /tmp/test.sock
cat /tmp/pivy-test-home/Library/LaunchAgents/net.cooperi.pivy-agent.plist
```

Expected: plist contains `EnvironmentVariables` dict with `SSH_ASKPASS`,
`SSH_ASKPASS_REQUIRE`, `SSH_NOTIFY_SEND`, `SSH_CONFIRM`.

**Step 5: Clean up and final commit if needed**

```bash
rm -rf /tmp/pivy-test-home
```

---

### Deferred: TODO for follow-up

Add C-level `terminal-notifier` auto-detection in `send_touch_notify()` (line
936 of `pivy-agent.c`). Detect `terminal-notifier` by basename the same way
`try_confirm_client()` already detects `zenity` and `notify-send`, and pass
`-title` / `-message` flags instead of positional args. This would allow
`SSH_NOTIFY_SEND=terminal-notifier` to work without the wrapper script.
