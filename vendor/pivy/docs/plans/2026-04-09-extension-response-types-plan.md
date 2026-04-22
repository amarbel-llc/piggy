# Extension Response Types Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Fix SSH agent extension response types so pivy is interoperable with spec-compliant agents (OpenSSH, Go x/crypto, ssh-agent-lib). Fixes #15.

**Architecture:** Three layers: (1) add the missing `SSH2_AGENT_EXT_RESPONSE` constant, (2) fix pivy-agent to send it for data-bearing extensions, (3) fix the piv.c client to accept it. Additionally, fix the query extension wire format to use SSH string encoding and handle both formats on the client side.

**Tech Stack:** C, OpenSSH sshbuf API, pivy's openssh.patch mechanism for adding defines.

**Rollback:** Client accepting both types is strictly additive. Agent-side changes revert in one commit. No deployed fleet.

---

### Task 1: Add SSH2_AGENT_EXT_RESPONSE constant

**Files:**
- Modify: `openssh.patch:55-56`

**Step 1: Add the define**

In `openssh.patch`, after the `SSH_AGENT_EXT_FAILURE` define (line 55), add `SSH2_AGENT_EXT_RESPONSE`:

```c
+#define	SSH_AGENT_EXT_FAILURE			28
+
+#define	SSH2_AGENT_EXT_RESPONSE			29
+
```

The full hunk context (lines 52-57) currently reads:

```
 /* generic extension mechanism */
 #define SSH_AGENTC_EXTENSION			27

+#define	SSH_AGENT_EXT_FAILURE			28
+
 #define	SSH_AGENT_CONSTRAIN_LIFETIME		1
```

After the edit it should read:

```
 /* generic extension mechanism */
 #define SSH_AGENTC_EXTENSION			27

+#define	SSH_AGENT_EXT_FAILURE			28
+#define	SSH2_AGENT_EXT_RESPONSE			29
+
 #define	SSH_AGENT_CONSTRAIN_LIFETIME		1
```

Note: the hunk header line count (`@@ ... @@`) must be updated to account for the extra line. The current hunk adds 2 lines (`+2`); after this change it adds 3 lines (`+3`). Read the full hunk to get the exact before/after line counts right.

**Step 2: Verify the patch applies**

Run: `just build` (or `nix build --show-trace`)
Expected: builds successfully with the new constant available.

**Step 3: Commit**

```
git add openssh.patch
git commit -m "Add SSH2_AGENT_EXT_RESPONSE (29) constant to openssh.patch"
```

---

### Task 2: Agent — send type 29 for data-bearing extensions

**Files:**
- Modify: `src/pivy-agent.c`

**Step 1: Change response type in all data-bearing extension handlers**

Replace `SSH_AGENT_SUCCESS` with `SSH2_AGENT_EXT_RESPONSE` in these locations:

| Handler                  | Line  | Context                                              |
|--------------------------|-------|------------------------------------------------------|
| `process_ext_ecdh`       | 1721  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |
| `process_ext_rebox`      | 1869  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |
| `process_ext_x509_certs` | 1939  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |
| `process_ext_prehash`    | 2044  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |
| `process_ext_attest`     | 2174  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |
| `process_ext_query`      | 2206  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |
| `process_ext_pin_status` | 2233  | `sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)`              |

Do NOT change:
- `process_ext_sessbind` (line 2094) — no-data extension, type 6 is correct.
- Any `SSH_AGENT_SUCCESS` outside of extension handlers (e.g. `process_lock`/`process_remove` at line 1322).

Each change is the same pattern. For example, line 1721:

Before:
```c
  if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
```

After:
```c
  if ((r = sshbuf_put_u8(msg, SSH2_AGENT_EXT_RESPONSE)) != 0 ||
```

**Step 2: Build**

Run: `just build`
Expected: compiles cleanly.

**Step 3: Commit**

```
git add src/pivy-agent.c
git commit -m "Agent: send SSH2_AGENT_EXT_RESPONSE (29) for data-bearing extensions

Per draft-ietf-sshm-ssh-agent §3.8, data-bearing extension responses
use type 29, not type 6. Type 6 (SSH_AGENT_SUCCESS) is reserved for
extensions that return no data (e.g. session-bind@openssh.com)."
```

---

### Task 3: Client — accept both type 6 and type 29

**Files:**
- Modify: `src/piv.c`

**Step 1: Update the three response type checks**

There are three checks in `piv_box_open_agent()`:

**Line 7336 (query response):**

Before:
```c
	if (code != SSH_AGENT_SUCCESS) {
		err = errf("NotSupportedError", NULL, "SSH agent does not "
		    "support 'query' extension (returned code %d)", (int)code);
```

After:
```c
	if (code != SSH_AGENT_SUCCESS && code != SSH2_AGENT_EXT_RESPONSE) {
		err = errf("NotSupportedError", NULL, "SSH agent does not "
		    "support 'query' extension (returned code %d)", (int)code);
```

**Line 7427 (rebox response):**

Before:
```c
		if (code != SSH_AGENT_SUCCESS) {
			err = errf("SSHAgentError", NULL, "SSH agent returned "
			    "message code %d to rebox request", (int)code);
```

After:
```c
		if (code != SSH_AGENT_SUCCESS && code != SSH2_AGENT_EXT_RESPONSE) {
			err = errf("SSHAgentError", NULL, "SSH agent returned "
			    "message code %d to rebox request", (int)code);
```

**Line 7500 (ecdh response):**

Before:
```c
		if (code != SSH_AGENT_SUCCESS) {
			err = errf("SSHAgentError", NULL, "SSH agent returned "
			    "message code %d to ECDH request", (int)code);
```

After:
```c
		if (code != SSH_AGENT_SUCCESS && code != SSH2_AGENT_EXT_RESPONSE) {
			err = errf("SSHAgentError", NULL, "SSH agent returned "
			    "message code %d to ECDH request", (int)code);
```

**Step 2: Build**

Run: `just build`
Expected: compiles cleanly.

**Step 3: Commit**

```
git add src/piv.c
git commit -m "Client: accept SSH2_AGENT_EXT_RESPONSE (29) from agents

Accept both type 6 and type 29 when parsing extension responses. This
makes pivy-box compatible with spec-compliant agents (OpenSSH, Go
x/crypto, ssh-agent-lib) while remaining backward compatible with older
pivy-agent instances that send type 6."
```

---

### Task 4: Query wire format — agent side

**Files:**
- Modify: `src/pivy-agent.c:2195-2219` (`process_ext_query`)

The current format is `u32 count` + `count x cstring` (NUL-terminated strings
with length prefix from `sshbuf_put_cstring`). The spec format is a single
`string` blob containing the extension names separated by SSH string encoding.

OpenSSH's query response format: the response body (after the type byte) is a
single SSH `string` (u32-length-prefixed blob). Inside that blob, each extension
name is also an SSH `string`. So the wire looks like:

```
u8   29                          (SSH2_AGENT_EXT_RESPONSE)
u32  total_inner_len             (length of inner blob)
  u32  len_0                     (length of name[0])
  byte name[0][0..len_0]
  u32  len_1
  byte name[1][0..len_1]
  ...
```

**Step 1: Rewrite process_ext_query**

Replace the body of `process_ext_query` (lines 2195-2219) with:

```c
static errf_t *process_ext_query(socket_entry_t *e, struct sshbuf *buf) {
  int r;
  struct exthandler *h;
  struct sshbuf *msg, *inner;

  if ((msg = sshbuf_new()) == NULL || (inner = sshbuf_new()) == NULL)
    fatal("%s: sshbuf_new failed", __func__);

  for (h = exthandlers; h->eh_name != NULL; ++h) {
    if ((r = sshbuf_put_cstring(inner, h->eh_name)) != 0)
      fatal("%s: buffer error: %s", __func__, ssh_err(r));
  }

  if ((r = sshbuf_put_u8(msg, SSH2_AGENT_EXT_RESPONSE)) != 0 ||
      (r = sshbuf_put_stringb(msg, inner)) != 0)
    fatal("%s: buffer error: %s", __func__, ssh_err(r));

  if ((r = sshbuf_put_stringb(e->se_output, msg)) != 0)
    fatal("%s: buffer error: %s", __func__, ssh_err(r));
  sshbuf_free(inner);
  sshbuf_free(msg);

  return (NULL);
}
```

Key differences from current code:
- Uses `SSH2_AGENT_EXT_RESPONSE` (already done in task 2, but this rewrite
  replaces the whole function)
- Builds extension names into an `inner` buffer using `sshbuf_put_cstring`
  (which writes `u32 length + bytes + NUL` — the SSH `cstring` encoding)
- Wraps the inner buffer as a single SSH string via `sshbuf_put_stringb`
- No more `u32 count` field — the count is implicit in the blob length

Note: `sshbuf_put_cstring` writes `u32 len + bytes + NUL`. This matches what
OpenSSH does. The receiver uses `sshbuf_get_cstring` to read each name from
the inner blob, stopping when the blob is exhausted.

**Step 2: Build**

Run: `just build`
Expected: compiles cleanly.

**Step 3: Commit**

```
git add src/pivy-agent.c
git commit -m "Agent: use SSH string encoding for query extension response

Replace u32 count + cstrings with a single SSH string blob containing
cstring-encoded extension names. This matches the wire format used by
OpenSSH and other spec-compliant agents."
```

---

### Task 5: Query wire format — client side

**Files:**
- Modify: `src/piv.c:7336-7356`

The client must handle both wire formats:
- **Type 6 (legacy pivy):** `u32 count` + `count x cstring`
- **Type 29 (spec):** `string blob` containing `cstring` entries

**Step 1: Rewrite the query response parser**

Replace lines 7336-7356 (the type check through the extension-name loop) with:

```c
	if (code != SSH_AGENT_SUCCESS && code != SSH2_AGENT_EXT_RESPONSE) {
		err = errf("NotSupportedError", NULL, "SSH agent does not "
		    "support 'query' extension (returned code %d)", (int)code);
		goto out;
	}
	if (code == SSH2_AGENT_EXT_RESPONSE) {
		/*
		 * Spec format: extension names are cstrings packed inside
		 * a single SSH string blob.
		 */
		struct sshbuf *inner = NULL;
		if ((rc = sshbuf_froms(reply, &inner))) {
			err = ssherrf("sshbuf_froms", rc);
			goto out;
		}
		while (sshbuf_len(inner) > 0) {
			if ((rc = sshbuf_get_cstring(inner, &extname, &len))) {
				err = ssherrf("sshbuf_get_cstring", rc);
				sshbuf_free(inner);
				goto out;
			}
			if (strcmp("ecdh-rebox@joyent.com", extname) == 0)
				has_rebox = 1;
			else if (strcmp("ecdh@joyent.com", extname) == 0)
				has_ecdh = 1;
			free(extname);
			extname = NULL;
		}
		sshbuf_free(inner);
	} else {
		/*
		 * Legacy pivy format: u32 count followed by count cstrings.
		 */
		if ((rc = sshbuf_get_u32(reply, &nexts))) {
			err = ssherrf("sshbuf_get_u32", rc);
			goto out;
		}
		for (i = 0; i < nexts; ++i) {
			if ((rc = sshbuf_get_cstring(reply, &extname, &len))) {
				err = ssherrf("sshbuf_get_cstring", rc);
				goto out;
			}
			if (strcmp("ecdh-rebox@joyent.com", extname) == 0)
				has_rebox = 1;
			else if (strcmp("ecdh@joyent.com", extname) == 0)
				has_ecdh = 1;
			free(extname);
			extname = NULL;
		}
	}
```

Note: `inner` is declared inside the block. The variable `i` and `nexts` are
already declared at function scope. `extname` and `len` are also at function
scope.

**Step 2: Build**

Run: `just build`
Expected: compiles cleanly.

**Step 3: Commit**

```
git add src/piv.c
git commit -m "Client: handle both query response wire formats

Type 29 responses use spec format (SSH string blob with cstring entries).
Type 6 responses use legacy pivy format (u32 count + cstrings). This
allows pivy-box to work with both pivy-agent and spec-compliant agents."
```

---

### Task 6: Update RFC doc

**Files:**
- Modify: `docs/rfcs/0001-ssh-agent-extensions.md`

**Step 1: Add SSH2_AGENT_EXT_RESPONSE to the constants table**

At line 76, after the `SSH_AGENT_EXT_FAILURE` row, add:

```
| `SSH2_AGENT_EXT_RESPONSE`    | 29    |
```

**Step 2: Update the Extension Dispatch section**

After the error responses section (around line 114), add a paragraph about
data-bearing responses:

```markdown
#### Data-Bearing Responses

When an extension handler returns data, the agent MUST respond with
`SSH2_AGENT_EXT_RESPONSE` (29):

\```
u32   response_length
u8    29
...   extension-specific payload
\```

Extensions that return no data (e.g. `session-bind@openssh.com`) respond with
`SSH_AGENT_SUCCESS` (6) instead.
```

**Step 3: Update the query extension response format**

Replace the query response block (lines 131-138) with:

```markdown
#### Response

\```
u8       SSH2_AGENT_EXT_RESPONSE (29)
string   names_blob               (SSH string containing extension names)
\```

The `names_blob` contains each extension name encoded as a `cstring` (u32 length
+ bytes + NUL), packed sequentially. Extension names are returned in registration
order. Clients iterate the blob until exhausted rather than relying on a count.

This extension MUST NOT return an error.
```

**Step 4: Update all other data-bearing extension response blocks**

For each of these extensions, change `SSH_AGENT_SUCCESS (6)` to
`SSH2_AGENT_EXT_RESPONSE (29)` in their Response sections:

- `ecdh@joyent.com` (line 165)
- `ecdh-rebox@joyent.com` (line 217)
- `x509-certs@joyent.com` (line 248)
- `ykpiv-attest@joyent.com` (line 280)
- `sign-prehash@arekinath.github.io` (line 322)
- `pin-status@joyent.com` (line 391)

Do NOT change:
- `session-bind@openssh.com` (line 367) — no-data extension
- `lock`/`unlock`/`update-pin` — these use `SSH_AGENT_SUCCESS` correctly

For the `lock`/`unlock` extensions: check their response sections. If they
document `SSH_AGENT_SUCCESS` and they truly return no data, leave them. If they
return data, change them.

**Step 5: Build (sanity check)**

Run: `just build`
Expected: no change (doc only).

**Step 6: Commit**

```
git add docs/rfcs/0001-ssh-agent-extensions.md
git commit -m "RFC: document SSH2_AGENT_EXT_RESPONSE (29) for data-bearing extensions

Update extension RFC to match the IETF spec and our implementation.
Data-bearing extensions use type 29; no-data extensions use type 6.
Query response now uses SSH string blob format."
```

---

### Task 7: Build and verify

**Step 1: Full build**

Run: `just build`
Expected: clean build, no warnings related to our changes.

**Step 2: Run bats tests**

Run: `just test-bats`
Expected: all existing tests pass. The bats tests don't exercise the query
extension directly (that requires a running agent with PCSC), but they verify
no regressions in the agent CLI.

**Step 3: Note for manual verification**

The full round-trip (pivy-box through ssh-agent-mux to pivy-agent) requires
a YubiKey and cannot be tested in the sandbox. Note in the final commit message
what was verified and what requires manual testing.
