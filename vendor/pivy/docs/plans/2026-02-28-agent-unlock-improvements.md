# pivy-agent Unlock Flow Improvements

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make pivy-agent more resilient to card reinsertion and give clients actionable error information when PIN is needed, so all clients (not just madder) benefit.

**Architecture:** Two changes to `pivy-agent.c`: (1) retry with delay in `agent_piv_open()` when a previously-known token isn't found after card reinsertion, and (2) return a structured error extension response instead of bare `SSH_AGENT_EXT_FAILURE` when the failure is `NoPINError`, so clients can distinguish "need PIN" from "malformed request" or "card not found".

**Tech Stack:** C, OpenSSH agent protocol, PCSC

---

## Background

### The problem

When a YubiKey is removed and re-inserted:

1. `agent_piv_open()` calls `piv_find()` which talks to PCSC. If PCSC hasn't
   detected the re-inserted card yet, `piv_find()` fails immediately.
2. The ECDH extension handler returns `send_extfail()` — a single
   `SSH_AGENT_EXT_FAILURE` byte. Clients see "agent: generic extension failure"
   with no way to distinguish card-not-found from PIN-needed from bad-request.
3. Clients have no recovery path except "try again later and hope it works."

### Key files

- `pivy/src/pivy-agent.c` — all changes are here
  - `agent_piv_open()` (line 544) — token discovery via PCSC
  - `process_ext_ecdh()` (line 1718) — ECDH extension handler
  - `send_extfail()` (line 1405) — sends `SSH_AGENT_EXT_FAILURE`
  - `process_lock_agent()` (line 2393) — LOCK/UNLOCK handler
  - `process_extension()` (line 2330) — extension dispatcher, catches errors
  - `try_askpass()` (line 851) — forks `$SSH_ASKPASS` for PIN entry
  - `agent_piv_try_pin()` (line 1155) — PIN verification with askpass fallback

### Relevant protocol details

- `SSH_AGENT_EXT_FAILURE` (0x1c): single byte, no payload — this is what
  `send_extfail()` sends today for ALL extension errors
- `SSH_AGENT_SUCCESS` (0x06): can carry a payload as a length-prefixed string
- pivy-agent's error types: `NoPINError`, `NotFoundError`, `EnumerationError`,
  `PermissionError`, `ParseError`, `FlagsError`, `AuthzError`
- Go's `agent.Extension()` returns the raw response bytes on success, or
  `errors.New("agent: generic extension failure")` on `SSH_AGENT_EXT_FAILURE`

---

### Task 1: Add retry with delay to `agent_piv_open()` for card re-discovery

**Files:**
- Modify: `pivy/src/pivy-agent.c:544-628` (`agent_piv_open`)

**Context:** When a card is removed and re-inserted, PCSC may not detect it
immediately. Currently `agent_piv_open()` calls `piv_find()` once and fails.
The `PCSCContextError` case already has retry logic (the `findagain` label),
but the `NotFoundError` case (card not present) does not.

**Step 1: Add retry logic when card is not found after `piv_find()`**

In `agent_piv_open()`, after the `piv_find()` call, when `selk == NULL`
(line 582-588), add a single retry with a short delay. The idea is: if we
previously knew about a token (`guid` is set), and `piv_find()` returns no
results, wait briefly and try once more before giving up.

Replace lines 582-588:

```c
		if (selk == NULL) {
			err = errf("NotFoundError", NULL, "PIV card with "
			    "given GUID is not present on the system");
			if (monotime() - last_update > 5000)
				drop_pin();
			return (err);
		}
```

With:

```c
		if (selk == NULL) {
			static int find_retries = 0;
			if (find_retries == 0 &&
			    monotime() - last_update < 30000) {
				/*
				 * Card was recently known but not found now.
				 * PCSC may not have detected reinsertion yet.
				 * Wait briefly and retry once.
				 */
				find_retries = 1;
				bunyan_log(BNY_DEBUG,
				    "card not found, retrying after delay",
				    NULL);
				usleep(500000); /* 500ms */
				goto findagain;
			}
			find_retries = 0;
			err = errf("NotFoundError", NULL, "PIV card with "
			    "given GUID is not present on the system");
			if (monotime() - last_update > 5000)
				drop_pin();
			return (err);
		}
```

**Step 2: Reset retry counter on success**

After `selk` is set successfully (line 580), reset the counter:

```c
		selk = ks;
		find_retries = 0;   /* <-- add this line */
```

Wait — `find_retries` is a static local, so it persists. It should be reset
after a successful find. Actually, let's move the static to file scope and
reset it more cleanly. Replace the `static int find_retries` inside the
function with a file-scoped static near the other state variables (around
line 184):

```c
static int card_find_retries = 0;
```

And use `card_find_retries` in the code above instead of `find_retries`.
Reset it to 0 both on success (after `selk = ks;`) and on final failure
(before returning the `NotFoundError`).

**Step 3: Build and verify**

Run: `make` (or `nix build`)
Expected: compiles cleanly

**Step 4: Manual test**

1. Start pivy-agent, insert YubiKey
2. Perform an SSH sign or ECDH operation (should work)
3. Remove YubiKey
4. Re-insert YubiKey
5. Immediately perform the operation again
6. Observe in pivy-agent debug logs: "card not found, retrying after delay"
   followed by a successful operation

**Step 5: Commit**

```
git add src/pivy-agent.c
git commit -m "fix: retry card discovery after brief delay on reinsertion

When a previously-known PIV card is not found by piv_find(), wait 500ms
and retry once before returning NotFoundError. This handles the race
between physical card reinsertion and PCSC detection."
```

---

### Task 2: Return structured error for NoPINError via extension response

**Files:**
- Modify: `pivy/src/pivy-agent.c:2370-2384` (`process_extension` error handler)

**Context:** Currently, when an extension handler returns an error,
`process_extension()` calls `send_extfail()` which sends a bare
`SSH_AGENT_EXT_FAILURE` byte. Clients cannot distinguish NoPINError from any
other failure. The SSH agent protocol allows extension responses to carry
arbitrary payload data. We can use a custom failure response for NoPINError.

**Design decision:** Rather than inventing a new wire format, use the existing
`SSH_AGENT_EXT_FAILURE` for most errors but send `SSH_AGENT_SUCCESS` with a
structured payload for NoPINError. The payload format:

```
SSH_AGENT_SUCCESS (0x06)
string("error@joyent.com")
string("NoPINError")
string("no PIN has been supplied to the agent (try ssh-add -X)")
```

This way:
- Legacy clients that don't understand the payload still get a response they
  can parse (they'll see a "success" with unexpected data and likely ignore it
  or error on parsing)
- Smart clients can check for the `error@joyent.com` prefix and extract the
  error type

**Alternative (simpler):** Keep `SSH_AGENT_EXT_FAILURE` but add a custom
extension `pin-status@joyent.com` that clients can call to check whether a PIN
is cached. This is less invasive and doesn't change existing behavior.

**Recommended approach: the alternative.** A `pin-status@joyent.com` extension
is safer because it doesn't change the behavior of existing error paths. The
`process_lock_agent` UNLOCK-with-empty-password already provides this
functionality, but it uses the LOCK/UNLOCK protocol which is semantically
wrong (UNLOCK is supposed to unlock the agent, not query status). A dedicated
extension is cleaner.

**Step 1: Add `process_ext_pin_status` handler**

Add after `process_ext_ecdh` (around line 1830):

```c
static errf_t *
process_ext_pin_status(socket_entry_t *e, struct sshbuf *buf)
{
	int r;
	struct sshbuf *msg;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	/*
	 * Return whether a PIN is currently cached.
	 * Response: SSH_AGENT_SUCCESS + u8(has_pin) + u8(has_card)
	 */
	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	if ((r = sshbuf_put_u8(msg, pin_len > 0 ? 1 : 0)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	/* Check if card is present (best effort) */
	{
		errf_t *err;
		uint8_t card_present = 0;
		if (selk != NULL) {
			err = piv_txn_begin(selk);
			if (err == ERRF_OK) {
				card_present = 1;
				piv_txn_end(selk);
			} else {
				errf_free(err);
			}
		}
		if ((r = sshbuf_put_u8(msg, card_present)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
	return (ERRF_OK);
}
```

**Step 2: Register the extension in `exthandlers` table**

In the `exthandlers` array (around line 2324), add:

```c
{ "pin-status@joyent.com",		B_FALSE,	process_ext_pin_status },
```

Note: `eh_string = B_FALSE` because this extension takes no payload (no outer
string wrapper needed).

**Step 3: Build and verify**

Run: `make`
Expected: compiles cleanly

**Step 4: Manual test with ssh-add**

```bash
# Check PIN status (should show no PIN cached after fresh start)
ssh-add -T "pin-status@joyent.com" 2>&1 || true

# This won't work with ssh-add directly since it doesn't support custom
# extensions. Test with a small Go or C program instead, or defer to
# the Go client integration in Task 3.
```

**Step 5: Commit**

```
git add src/pivy-agent.c
git commit -m "feat: add pin-status@joyent.com extension

Returns whether a PIN is cached and whether the card is currently
present. Allows clients to check status before attempting operations
that require PIN, and provide better error messages when things fail."
```

---

### Task 3: Integration guide for Go clients (madder)

This task does not involve changes to pivy. It documents how Go clients should
use the new and existing pivy-agent capabilities.

**The Go client (madder) should implement this flow in
`go/lib/delta/pivy/agent.go`:**

```
callAgentECDH(socketPath, recipientPubkey, ephemeralPubkey):
  1. Connect to PIVY_AUTH_SOCK
  2. Call client.List()           — forces token re-enumeration
  3. Call Extension("ecdh@joyent.com", payload)
  4. If success: parse response, return shared secret
  5. If failure:
     a. Call Extension("pin-status@joyent.com", nil)
        - If card not present: return clear "card not present" error
        - If card present but no PIN:
          i.  Try $SSH_ASKPASS to get PIN
          ii. Call client.Unlock(pin) to cache PIN in agent
          iii. Retry Extension("ecdh@joyent.com", payload)
     b. If pin-status extension not available (old pivy-agent):
        - Call client.Unlock("") to check PIN via legacy mechanism
          (empty password = status check)
        - Fall back to prompting for PIN and retrying
  6. Return error with actionable message
```

**Additionally, in `go/lib/delta/pivy/identity.go`:**

The `Unwrap` method (line 23-38) currently swallows all errors from
`tryUnwrap` with `continue`. It should distinguish between AEAD failures
(wrong recipient, continue to next stanza) and agent errors (card not found,
PIN needed — propagate immediately).

```go
func (id *Identity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
    var lastErr error
    for _, s := range stanzas {
        if s.Type != StanzaTypePivyEcdhP256 {
            continue
        }
        fileKey, err := id.tryUnwrap(s)
        if err != nil {
            lastErr = err
            continue
        }
        return fileKey, nil
    }
    if lastErr != nil {
        return nil, lastErr  // propagate agent/card errors
    }
    return nil, age.ErrIncorrectIdentity
}
```

**These Go changes should be made in the madder-pivy worktree**, not in the
pivy repo. The pivy changes (Tasks 1-2) should be landed first, then the Go
client can take advantage of the new `pin-status@joyent.com` extension. The
Go client changes that use only existing pivy-agent capabilities (List,
Unlock, retry logic) can be implemented immediately without waiting for the
pivy changes.

---

## Implementation order

1. **Now (madder, no pivy changes needed):** Implement retry logic and better
   error handling in the Go client using existing pivy-agent capabilities
   (`List()`, `Unlock("")`, retry). Fix error swallowing in `Unwrap`.

2. **pivy repo (Tasks 1-2):** Land the card re-discovery retry and
   `pin-status@joyent.com` extension.

3. **Later (madder, after pivy changes):** Update Go client to use
   `pin-status@joyent.com` for smarter error handling and pre-flight checks.
