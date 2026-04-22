# Debugging: SSH_ASKPASS Sign Request Failure

## Problem Statement

After commit `2dc5617` (which added SSH_ASKPASS, SSH_NOTIFY_SEND, SSH_CONFIRM
env var defaults to `install-service`), the pivy-agent service correctly triggers
SSH_ASKPASS for PIN entry, but the **original sign request that triggered the PIN
prompt fails**. Subsequent sign requests succeed without re-prompting.

## Confirmed Facts

- **Slot**: 9a (PIV Authentication)
- **No -C flag**: confirmation mode is `C_NEVER` (default, disabled)
- **Zenity is launched**: user confirmed it appears and PIN is entered correctly
- **First request fails**: with `NoPINError` wrapping `PermissionError` wrapping
  `APDUError SW=6982 (SECURITY_STATUS_NOT_SATISFIED)`
- **Subsequent requests succeed**: without any dialog, proving the card IS
  unlocked and PIN is stored in memory
- **Service environment**: `SSH_ASKPASS` is set in the running process's
  environment (confirmed via `ps eww`)

## Log Analysis

Two distinct patterns observed in `~/Library/Logs/pivy-agent.log`:

### Pattern A — Failing (majority of cases)

- `SIGN_REQUEST` completes in ~150ms with `NoPINError`
- **No zenity GTK warnings** in stderr log between request and failure
- **No "executing askpass failed"** warning logged
- **No "storing PIN in memory"** entry logged
- User must manually run `ssh-add -X` (UNLOCK) to supply PIN
- Example: `18:32:04.241 REQUEST_IDENTITIES` → `18:32:04.397 SIGN_REQUEST
  fails` (156ms)

### Pattern B — Working (seen once at 18:42)

- Zenity GTK warnings appear in stderr log
- `"storing PIN in memory"` logged during `SIGN_REQUEST`
- `SIGN_REQUEST` succeeds
- Example: `18:42:09 REQUEST_IDENTITIES` → zenity at `18:42:16-21` →
  `18:42:21 "storing PIN in memory"` → `SIGN_REQUEST` succeeds (~12 seconds)

### Key Insight

Pattern A completes in sub-200ms — far too fast for a zenity dialog to have been
shown. `try_askpass()` IS being called (we reach the `nopinerrf` at line 1660),
but zenity is NOT being launched. Yet no error is logged.

## Code Flow Analysis

### Sign Request Path (`process_sign_request2`, line 1548)

```
agent_piv_open() → try_confirm_client() → agent_piv_try_pin(canskip)
  → piv_sign()
  → on PermissionError:
      try_askpass()
      if pin_len != 0 → goto pin_again (retry with PIN)
      else → nopinerrf(err) at line 1660  ← THIS IS HIT
```

### `try_askpass()` Silent Return Paths (line 851)

The function has three return paths that produce **no log output**:

1. **Line 866-867**: `askpass == NULL` — unlikely, env var confirmed set in
   process
2. **Line 869-870**: `pipe()` returns `-1` — no logging, silent return
3. **Line 871-872**: `fork()` returns `-1` — no logging, silent return

If zenity launched but exited non-zero, `"executing askpass failed"` would be
logged at line 900 — but this message does NOT appear in failing cases.

### `try_askpass()` Success Path

When it works (Pattern B), the flow is:

1. `fork()` + `execlp(askpass, ...)` launches zenity
2. Parent reads PIN from pipe
3. `piv_verify_pin()` verifies PIN on card
4. PIN stored in global `pin`/`pin_len`
5. `"storing PIN in memory"` logged at line 929

### Transaction Lifecycle Issue

`piv_txn_end()` (piv.c:2011) clears PIN status on the card:
- If `pt_used_pin != PIV_NO_PIN`, calls `piv_clear_pin()` and sets disposition
  to `SCARD_RESET_CARD`
- Resets `pt_used_pin = PIV_NO_PIN`

`agent_piv_close(B_FALSE)` at line 924 (inside `try_askpass`) only closes if
`now >= txntimeout`. But `agent_piv_close(B_TRUE)` at line 1659 (on failure
path) forces close, which resets the card.

This means: even if `try_askpass()` successfully verified the PIN, calling
`agent_piv_close(B_TRUE)` afterward would reset the card, requiring re-PIN. But
this is the failure path — `try_askpass()` didn't set `pin_len`, so this code
path means the PIN was never verified in this transaction.

### `agent_piv_try_pin()` (line 1155)

Called before `piv_sign()` with `canskip`. For slot 9a with `PIV_SLOT_AUTH_PIN`,
`canskip = B_FALSE`. This means:
- `try_askpass()` is called here FIRST (line 1161) if `pin_len == 0`
- If successful, PIN is verified via `piv_verify_pin()` at line 1163
- Then `piv_sign()` at line 1642 should succeed

But if `try_askpass()` silently fails in `agent_piv_try_pin()`, then
`pin_len` stays 0, `piv_verify_pin` is skipped, `piv_sign()` fails with
`PermissionError`, and the second `try_askpass()` call at line 1654 also silently
fails → `nopinerrf` at line 1660.

## Hypotheses (Ranked by Likelihood)

### 1. `fork()` or `pipe()` failing silently in launchd context

macOS launchd services can have resource restrictions. A `fork()` or `pipe()`
failure returns `-1` and the function returns silently without logging.

**Evidence for**: no log output at all from `try_askpass()` in Pattern A.

**Evidence against**: Pattern B shows it does work sometimes under the same
service.

### 2. Race condition with DISPLAY or session context

Zenity requires a GUI session. The service starts at login but the first sign
request may arrive before the GUI session is fully available. Later requests
(Pattern B) succeed because the session is ready by then.

**Evidence for**: Pattern A occurs early in session, Pattern B occurs later.

### 3. Nix store path mismatch

The running service uses nix store path
`hrbg1x8jy590zh3wnklmmh1fapffkfdl-pivy-0.12.1` while the current build output
is different. If the pivy-askpass at the old store path was garbage-collected,
`execlp` would fail and the child exits 1. However, this should trigger the
`"executing askpass failed"` log at line 900.

**Evidence against**: `execlp` failure would cause child to `exit(1)`, which
would be caught by the `WEXITSTATUS` check at line 898 and logged.

### 4. `STDIN` closed in child breaks zenity

`try_askpass()` closes `STDIN` in the child (line 873-876) without replacing it.
Zenity may need `STDIN` or may fail silently when it's closed.

**Evidence**: unclear — zenity `--password` reads from its own GTK input, but
some GTK initialization may check stdin.

## Recommended Next Steps

### Diagnostic Step 1: Add logging to silent return paths

Add `bunyan_log` calls to the three silent return paths in `try_askpass()`:

```c
if (askpass == NULL) {
    bunyan_log(BNY_DEBUG, "try_askpass: no askpass configured", NULL);
    return;
}
if (pipe(p) == -1) {
    bunyan_log(BNY_WARN, "try_askpass: pipe() failed",
        "errno", BNY_INT, errno, NULL);
    return;
}
if ((kid = fork()) == -1) {
    bunyan_log(BNY_WARN, "try_askpass: fork() failed",
        "errno", BNY_INT, errno, NULL);
    return;
}
```

### Diagnostic Step 2: Log the askpass path being used

Before `pipe()`, add:

```c
bunyan_log(BNY_DEBUG, "try_askpass: launching askpass",
    "askpass", BNY_STRING, askpass,
    "prompt", BNY_STRING, prompt, NULL);
```

### Diagnostic Step 3: Reproduce and check logs

1. Rebuild with diagnostics
2. Reinstall service (`pivy-agent install-service -A ...`)
3. Restart agent
4. Trigger a sign request
5. Check `~/Library/Logs/pivy-agent.log` for new diagnostic messages

### Diagnostic Step 4: Verify nix store path

Check if the pivy-askpass file exists at the path the running service uses:

```sh
ls -la /nix/store/hrbg1x8jy590zh3wnklmmh1fapffkfdl-pivy-0.12.1/libexec/pivy/pivy-askpass
```

## Files Referenced

| File | Lines | What |
|------|-------|------|
| `src/pivy-agent.c` | 851-934 | `try_askpass()` — forks zenity, reads PIN, verifies |
| `src/pivy-agent.c` | 1155-1170 | `agent_piv_try_pin()` — calls `try_askpass()` if no PIN |
| `src/pivy-agent.c` | 1548-1700 | `process_sign_request2()` — sign flow with retry logic |
| `src/pivy-agent.c` | 423-435 | `agent_piv_close()` — conditional transaction close |
| `src/piv.c` | 2011-2039 | `piv_txn_end()` — clears PIN, resets card |
| `flake.nix` | 290-306 | Install phase with wrapper scripts |
| `libexec/pivy-askpass` | 1-2 | Zenity password prompt wrapper |
