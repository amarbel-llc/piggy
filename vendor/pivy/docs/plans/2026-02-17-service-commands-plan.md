# Service Commands Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `install-service`, `restart-service`, and `uninstall-service` subcommands to pivy-agent that auto-detect PIV cards and configure platform-native service managers.

**Architecture:** Subcommand dispatch added at top of `main()` in pivy-agent.c, before existing getopt processing. Each subcommand is a static function. Platform-specific code uses `#if defined(__APPLE__)` / `#if defined(__linux__)` guards, matching the existing codebase pattern.

**Tech Stack:** C, PCSC (via existing piv.h), systemd (Linux), launchd (macOS)

**Design doc:** `docs/plans/2026-02-17-service-commands-design.md`

---

### Task 1: Add `get_self_exe_path()` helper

**Files:**
- Modify: `src/pivy-agent.c` (insert before `usage()`, around line 3107)

**Step 1: Write the function**

Insert before the `usage()` function (line 3107):

```c
static char *
get_self_exe_path(void)
{
	char *path = malloc(PATH_MAX);
	VERIFY(path != NULL);
#if defined(__APPLE__)
	uint32_t size = PATH_MAX;
	if (_NSGetExecutablePath(path, &size) != 0)
		fatal("_NSGetExecutablePath failed");
	char *resolved = realpath(path, NULL);
	free(path);
	VERIFY(resolved != NULL);
	return (resolved);
#elif defined(__linux__)
	ssize_t len = readlink("/proc/self/exe", path, PATH_MAX - 1);
	if (len < 0)
		fatal("readlink(/proc/self/exe) failed: %s", strerror(errno));
	path[len] = '\0';
	return (path);
#else
	free(path);
	fatal("get_self_exe_path: unsupported platform");
	return (NULL);
#endif
}
```

**Step 2: Add macOS header include**

After the existing `#if defined(__APPLE__)` block at line 113-115, add the `mach-o/dyld.h` include:

```c
#if defined(__APPLE__)
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include <mach-o/dyld.h>
#else
```

**Step 3: Build to verify compilation**

Run: `nix build`
Expected: Builds successfully (function is unused for now, but should compile)

**Step 4: Commit**

```
feat(pivy-agent): add get_self_exe_path helper
```

---

### Task 2: Add `detect_card()` helper

**Files:**
- Modify: `src/pivy-agent.c` (insert after `get_self_exe_path`, before `usage()`)

**Step 1: Write the function**

This function opens PCSC, enumerates tokens, and returns a GUID hex string and CAK string. It reuses the same `piv_open`/`piv_establish_context`/`piv_enumerate` pattern from `agent_enumerate_all()` (line 630).

```c
static void
detect_card(char **out_guid, char **out_cak)
{
	struct piv_ctx *dctx;
	struct piv_token *tks, *tk;
	struct piv_slot *slot;
	errf_t *err;
	int count;
	FILE *f;
	char *cak_buf = NULL;
	size_t cak_len = 0;

	dctx = piv_open();
	VERIFY(dctx != NULL);
	err = piv_establish_context(dctx, SCARD_SCOPE_SYSTEM);
	if (err)
		errfx(1, err, "failed to establish PCSC context");

	err = piv_enumerate(dctx, &tks);
	if (err)
		errfx(1, err, "failed to enumerate PIV tokens");

	count = 0;
	for (tk = tks; tk != NULL; tk = piv_token_next(tk)) {
		if (!piv_token_has_chuid(tk))
			continue;
		count++;
	}

	if (count == 0) {
		fprintf(stderr,
		    "error: no PIV tokens found\n"
		    "Insert a PIV token and retry, or pass -g explicitly.\n");
		exit(1);
	}

	if (count > 1) {
		fprintf(stderr,
		    "error: multiple PIV tokens found, "
		    "specify one with -g:\n");
		for (tk = tks; tk != NULL; tk = piv_token_next(tk)) {
			if (!piv_token_has_chuid(tk))
				continue;
			fprintf(stderr, "  %s\n",
			    piv_token_guid_hex(tk));
		}
		piv_release(tks);
		piv_close(dctx);
		exit(1);
	}

	/* Exactly one token */
	for (tk = tks; tk != NULL; tk = piv_token_next(tk)) {
		if (piv_token_has_chuid(tk))
			break;
	}

	*out_guid = strdup(piv_token_guid_hex(tk));

	err = piv_txn_begin(tk);
	if (err)
		errfx(1, err, "failed to open transaction on token");
	err = piv_select(tk);
	if (err) {
		piv_txn_end(tk);
		errfx(1, err, "failed to select PIV applet");
	}
	err = piv_read_cert(tk, PIV_SLOT_CARD_AUTH);
	piv_txn_end(tk);

	slot = piv_get_slot(tk, PIV_SLOT_CARD_AUTH);
	if (err || slot == NULL) {
		errf_free(err);
		fprintf(stderr,
		    "warning: no 9E (card auth) key found, "
		    "skipping CAK\n");
		*out_cak = NULL;
	} else {
		f = open_memstream(&cak_buf, &cak_len);
		VERIFY(f != NULL);
		VERIFY0(sshkey_write(piv_slot_pubkey(slot), f));
		fclose(f);
		*out_cak = cak_buf;
	}

	piv_release(tks);
	piv_close(dctx);
}
```

**Step 2: Build to verify compilation**

Run: `nix build`
Expected: Builds successfully

**Step 3: Commit**

```
feat(pivy-agent): add detect_card helper for auto-detection
```

---

### Task 3: Add `cmd_install_service()` — Linux

**Files:**
- Modify: `src/pivy-agent.c` (insert after `detect_card`, before `usage()`)

**Step 1: Write the Linux install-service function**

```c
static int
run_command(const char *path, char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		fatal("fork failed: %s", strerror(errno));
	if (pid == 0) {
		execvp(path, argv);
		fatal("exec %s failed: %s", path, strerror(errno));
	}
	if (waitpid(pid, &status, 0) < 0)
		fatal("waitpid failed: %s", strerror(errno));
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}

static int
cmd_install_service(int ac, char **av)
{
	char *exe_path, *exe_dir;
	char *det_guid = NULL, *det_cak = NULL;
	const char *opt_guid = NULL, *opt_cak = NULL;
	const char *opt_socket = NULL;
	boolean_t opt_allcard = B_FALSE;
	char path[PATH_MAX];
	char *home;
	FILE *f;
	int ch;

	while ((ch = getopt(ac, av, "Ag:K:a:")) != -1) {
		switch (ch) {
		case 'A':
			opt_allcard = B_TRUE;
			break;
		case 'g':
			opt_guid = optarg;
			break;
		case 'K':
			opt_cak = optarg;
			break;
		case 'a':
			opt_socket = optarg;
			break;
		default:
			fprintf(stderr,
			    "usage: pivy-agent install-service "
			    "[-g guid] [-K cak] [-A] [-a socket]\n");
			return (1);
		}
	}

	if (opt_guid != NULL && opt_allcard) {
		fprintf(stderr, "error: -A and -g are mutually exclusive\n");
		return (1);
	}

	exe_path = get_self_exe_path();
	exe_dir = strdup(exe_path);
	exe_dir = dirname(exe_dir);

	home = getenv("HOME");
	if (home == NULL)
		fatal("HOME is not set");

	if (!opt_allcard && opt_guid == NULL) {
		detect_card(&det_guid, &det_cak);
		opt_guid = det_guid;
		if (opt_cak == NULL && det_cak != NULL)
			opt_cak = det_cak;
	}

#if defined(__linux__)
	/* Write config to ~/.config/pivy-agent/default */
	snprintf(path, sizeof (path),
	    "%s/.config/pivy-agent", home);
	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		fatal("mkdir %s: %s", path, strerror(errno));

	snprintf(path, sizeof (path),
	    "%s/.config/pivy-agent/default", home);
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

	/* Write systemd unit to ~/.config/systemd/user/ */
	snprintf(path, sizeof (path),
	    "%s/.config/systemd/user", home);
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		/* Try creating parent first */
		char parent[PATH_MAX];
		snprintf(parent, sizeof (parent),
		    "%s/.config/systemd", home);
		if (mkdir(parent, 0700) != 0 && errno != EEXIST)
			fatal("mkdir %s: %s", parent, strerror(errno));
		if (mkdir(path, 0700) != 0 && errno != EEXIST)
			fatal("mkdir %s: %s", path, strerror(errno));
	}

	snprintf(path, sizeof (path),
	    "%s/.config/systemd/user/pivy-agent@.service", home);
	f = fopen(path, "w");
	if (f == NULL)
		fatal("fopen %s: %s", path, strerror(errno));

	fprintf(f,
	    "[Unit]\n"
	    "Description=PIV SSH Agent\n"
	    "\n"
	    "[Service]\n"
	    "Environment=SSH_AUTH_SOCK=%%t/piv-ssh-%%I.socket\n"
	    "Environment=PIV_AGENT_OPTS=\n"
	    "Environment=PIV_SLOTS=all\n"
	    "EnvironmentFile=%%h/.config/pivy-agent/%%I\n"
	    "ExecStartPre=/bin/rm -f $SSH_AUTH_SOCK\n"
	    "ExecStart=%s/pivy-agent -i -a $SSH_AUTH_SOCK "
	    "-g $PIV_AGENT_GUID -K ${PIV_AGENT_CAK} "
	    "-S ${PIV_SLOTS} $PIV_AGENT_OPTS\n"
	    "Restart=always\n"
	    "RestartSec=3\n"
	    "\n"
	    "[Install]\n"
	    "WantedBy=default.target\n"
	    "DefaultInstance=default\n",
	    exe_dir);
	fclose(f);
	fprintf(stderr, "Wrote %s\n", path);

	/* Enable and start the service */
	char *reload_argv[] = {
	    "systemctl", "--user", "daemon-reload", NULL
	};
	char *enable_argv[] = {
	    "systemctl", "--user", "enable", "--now",
	    "pivy-agent@default.service", NULL
	};

	if (run_command("systemctl", reload_argv) != 0)
		fprintf(stderr, "warning: systemctl daemon-reload failed\n");
	if (run_command("systemctl", enable_argv) != 0) {
		fprintf(stderr, "error: failed to enable service\n");
		return (1);
	}

	fprintf(stderr,
	    "Installed and started pivy-agent@default.service\n"
	    "Socket: $XDG_RUNTIME_DIR/piv-ssh-default.socket\n");

#elif defined(__APPLE__)
	/* macOS implementation in next task */
	fprintf(stderr, "error: macOS not yet supported\n");
	return (1);
#else
	fprintf(stderr, "error: unsupported platform\n");
	return (1);
#endif

	free(exe_path);
	free(exe_dir);
	free(det_guid);
	free(det_cak);
	return (0);
}
```

**Step 2: Build to verify**

Run: `nix build`
Expected: Builds successfully

**Step 3: Commit**

```
feat(pivy-agent): add cmd_install_service for Linux/systemd
```

---

### Task 4: Add macOS support to `cmd_install_service()`

**Files:**
- Modify: `src/pivy-agent.c` (replace the `__APPLE__` stub in `cmd_install_service`)

**Step 1: Replace the macOS stub with real implementation**

Replace the `#elif defined(__APPLE__)` block:

```c
#elif defined(__APPLE__)
	if (opt_socket == NULL) {
		snprintf(path, sizeof (path),
		    "%s/.ssh/pivy-agent.sock", home);
		opt_socket = strdup(path);
	}

	snprintf(path, sizeof (path),
	    "%s/Library/LaunchAgents", home);
	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		fatal("mkdir %s: %s", path, strerror(errno));

	snprintf(path, sizeof (path),
	    "%s/Library/LaunchAgents/net.cooperi.pivy-agent.plist", home);
	f = fopen(path, "w");
	if (f == NULL)
		fatal("fopen %s: %s", path, strerror(errno));

	fprintf(f,
	    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	    "<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\""
	    " \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
	    "<plist version=\"1.0\">\n"
	    "<dict>\n"
	    "    <key>Label</key>\n"
	    "    <string>net.cooperi.pivy-agent</string>\n"
	    "    <key>ProgramArguments</key>\n"
	    "    <array>\n"
	    "        <string>%s</string>\n",
	    exe_path);

	if (opt_allcard) {
		fprintf(f,
		    "        <string>-A</string>\n");
	} else {
		fprintf(f,
		    "        <string>-g</string>\n"
		    "        <string>%s</string>\n",
		    opt_guid);
		if (opt_cak != NULL) {
			fprintf(f,
			    "        <string>-K</string>\n"
			    "        <string>%s</string>\n",
			    opt_cak);
		}
	}

	fprintf(f,
	    "        <string>-i</string>\n"
	    "        <string>-a</string>\n"
	    "        <string>%s</string>\n"
	    "    </array>\n"
	    "    <key>StandardErrorPath</key>\n"
	    "    <string>%s/Library/Logs/pivy-agent.log</string>\n"
	    "    <key>RunAtLoad</key>\n"
	    "    <true/>\n"
	    "    <key>KeepAlive</key>\n"
	    "    <true/>\n"
	    "</dict>\n"
	    "</plist>\n",
	    opt_socket, home);
	fclose(f);
	fprintf(stderr, "Wrote %s\n", path);

	char *load_argv[] = {
	    "launchctl", "load", path, NULL
	};
	if (run_command("launchctl", load_argv) != 0) {
		fprintf(stderr, "error: launchctl load failed\n");
		return (1);
	}

	fprintf(stderr,
	    "Installed and started net.cooperi.pivy-agent\n"
	    "Socket: %s\n", opt_socket);
```

**Step 2: Build to verify**

Run: `nix build`
Expected: Builds successfully

**Step 3: Commit**

```
feat(pivy-agent): add macOS/launchd support to install-service
```

---

### Task 5: Add `cmd_restart_service()` and `cmd_uninstall_service()`

**Files:**
- Modify: `src/pivy-agent.c` (insert after `cmd_install_service`, before `usage()`)

**Step 1: Write restart-service**

```c
static int
cmd_restart_service(int ac, char **av)
{
	(void)ac;
	(void)av;
#if defined(__linux__)
	char *argv[] = {
	    "systemctl", "--user", "restart",
	    "pivy-agent@default.service", NULL
	};
	if (run_command("systemctl", argv) != 0) {
		fprintf(stderr, "error: restart failed "
		    "(is the service installed?)\n");
		return (1);
	}
	fprintf(stderr, "Restarted pivy-agent@default.service\n");
#elif defined(__APPLE__)
	char uid_str[32];
	char label[128];
	snprintf(uid_str, sizeof (uid_str), "%u", getuid());
	snprintf(label, sizeof (label),
	    "gui/%s/net.cooperi.pivy-agent", uid_str);
	char *argv[] = {
	    "launchctl", "kickstart", "-k", label, NULL
	};
	if (run_command("launchctl", argv) != 0) {
		fprintf(stderr, "error: restart failed "
		    "(is the service installed?)\n");
		return (1);
	}
	fprintf(stderr, "Restarted net.cooperi.pivy-agent\n");
#else
	fprintf(stderr, "error: unsupported platform\n");
	return (1);
#endif
	return (0);
}
```

**Step 2: Write uninstall-service**

```c
static int
cmd_uninstall_service(int ac, char **av)
{
	char path[PATH_MAX];
	char *home;

	(void)ac;
	(void)av;

	home = getenv("HOME");
	if (home == NULL)
		fatal("HOME is not set");

#if defined(__linux__)
	char *disable_argv[] = {
	    "systemctl", "--user", "disable", "--now",
	    "pivy-agent@default.service", NULL
	};
	run_command("systemctl", disable_argv);

	snprintf(path, sizeof (path),
	    "%s/.config/systemd/user/pivy-agent@.service", home);
	if (unlink(path) == 0)
		fprintf(stderr, "Removed %s\n", path);

	snprintf(path, sizeof (path),
	    "%s/.config/pivy-agent/default", home);
	if (unlink(path) == 0)
		fprintf(stderr, "Removed %s\n", path);

	char *reload_argv[] = {
	    "systemctl", "--user", "daemon-reload", NULL
	};
	run_command("systemctl", reload_argv);

	fprintf(stderr, "Uninstalled pivy-agent@default.service\n");

#elif defined(__APPLE__)
	snprintf(path, sizeof (path),
	    "%s/Library/LaunchAgents/net.cooperi.pivy-agent.plist",
	    home);

	char *unload_argv[] = {
	    "launchctl", "unload", path, NULL
	};
	run_command("launchctl", unload_argv);

	if (unlink(path) == 0)
		fprintf(stderr, "Removed %s\n", path);

	fprintf(stderr, "Uninstalled net.cooperi.pivy-agent\n");

#else
	fprintf(stderr, "error: unsupported platform\n");
	return (1);
#endif
	return (0);
}
```

**Step 3: Build to verify**

Run: `nix build`
Expected: Builds successfully

**Step 4: Commit**

```
feat(pivy-agent): add restart-service and uninstall-service commands
```

---

### Task 6: Add subcommand dispatch and update usage

**Files:**
- Modify: `src/pivy-agent.c` (top of `main()` at line 3268, and `usage()` at line 3108)

**Step 1: Add subcommand dispatch at top of main()**

Insert after the opening brace of `main()` (line 3268), before all variable declarations. Actually, since we need `ac` and `av`, insert after the existing early init but before the getopt loop. The best insertion point is right after `slotspec_set_default(slot_ena);` (line 3317), before the `while ((ch = getopt(...))` loop (line 3319):

```c
	slotspec_set_default(slot_ena);

	if (ac >= 2) {
		if (strcmp(av[1], "install-service") == 0)
			return (cmd_install_service(ac - 1, av + 1));
		if (strcmp(av[1], "restart-service") == 0)
			return (cmd_restart_service(ac - 1, av + 1));
		if (strcmp(av[1], "uninstall-service") == 0)
			return (cmd_uninstall_service(ac - 1, av + 1));
	}

	while ((ch = getopt(ac, av, "AcCDdkisE:a:P:g:K:mZUS:u:z:")) != -1) {
```

**Step 2: Update usage() to include subcommands**

Add subcommand usage lines to the `usage()` function, after the existing usage lines (line 3115):

```c
	fprintf(stderr,
	    "usage: pivy-agent [-c | -s] [-Ddim] [-a bind_address] [-E fingerprint_hash]\n"
	    "                  [-K cak] -g guid [command [arg ...]]\n"
	    "       pivy-agent [-c | -s] [-Ddim] [-a bind_address] [-E fingerprint_hash]\n"
	    "                  -A [command [arg ...]]\n"
	    "       pivy-agent [-c | -s] -k\n"
	    "       pivy-agent install-service [-g guid] [-K cak] [-A] [-a socket]\n"
	    "       pivy-agent restart-service\n"
	    "       pivy-agent uninstall-service\n"
```

**Step 3: Build to verify**

Run: `nix build`
Expected: Builds successfully

**Step 4: Smoke test the subcommand dispatch**

Run: `./result/bin/pivy-agent install-service --help 2>&1 || true`
Expected: Should show install-service usage (or at least not the main agent usage)

Run: `./result/bin/pivy-agent restart-service 2>&1 || true`
Expected: Should show "restart failed (is the service installed?)" or similar

**Step 5: Commit**

```
feat(pivy-agent): wire up subcommand dispatch for service commands
```

---

### Task 7: Manual testing and edge cases

**Step 1: Test install-service with no card**

Run: `./result/bin/pivy-agent install-service 2>&1`
Expected: Error message about no PIV tokens found (or success if a card is inserted)

**Step 2: Test install-service with -A**

Run: `./result/bin/pivy-agent install-service -A 2>&1`
Expected: Should install the service with all-card mode, no card detection needed

**Step 3: Test uninstall-service cleans up**

Run: `./result/bin/pivy-agent uninstall-service 2>&1`
Expected: Removes service files, prints what was removed

**Step 4: Test mutual exclusivity**

Run: `./result/bin/pivy-agent install-service -A -g 1234 2>&1`
Expected: "error: -A and -g are mutually exclusive"

**Step 5: Verify existing pivy-agent behavior unchanged**

Run: `./result/bin/pivy-agent 2>&1 || true`
Expected: Shows usage (same as before, plus new subcommand lines)

**Step 6: Commit any fixes from testing**

```
fix(pivy-agent): address edge cases in service commands
```
