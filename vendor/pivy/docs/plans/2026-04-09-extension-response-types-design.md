# SSH Agent Extension Response Types

Fixes #15.

## Problem

pivy uses `SSH_AGENT_SUCCESS` (type 6) for all extension responses. The IETF
spec (draft-ietf-sshm-ssh-agent, section 3.8) requires `SSH_AGENT_EXTENSION_RESPONSE`
(type 29) for data-bearing extensions, reserving type 6 for no-data extensions.

This makes pivy incompatible with spec-compliant agents (OpenSSH, Go x/crypto,
ssh-agent-lib). The client rejects type 29 responses, and the agent sends type 6
where 29 is expected.

Additionally, the query extension wire format differs: pivy uses `u32 count` +
`count x cstring`, while the spec uses SSH string encoding (`u32 total-byte-length`
+ length-prefixed strings).

## Changes

### 1. Define SSH2_AGENT_EXT_RESPONSE

Add `#define SSH2_AGENT_EXT_RESPONSE 29` to `openssh.patch`, next to the existing
`SSH_AGENT_EXT_FAILURE` (28).

### 2. Agent: send type 29 for data-bearing extensions

In `pivy-agent.c`, change `SSH_AGENT_SUCCESS` to `SSH2_AGENT_EXT_RESPONSE` in:

- `process_ext_query` (query)
- `process_ext_ecdh` (ecdh@joyent.com)
- `process_ext_rebox` (ecdh-rebox@joyent.com)
- `process_ext_x509_certs` (x509-certs@joyent.com)
- `process_ext_attest` (ykpiv-attest@joyent.com)
- `process_ext_prehash` (sign-prehash@arekinath.github.io)
- `process_ext_pin_status` (pin-status@joyent.com)

Leave `process_ext_sessbind` as `SSH_AGENT_SUCCESS` -- no-data extension.

### 3. Client: accept both type 6 and type 29

In `piv.c`, change the three response type checks (query, rebox, ecdh) from:

```c
if (code != SSH_AGENT_SUCCESS) {
```

to:

```c
if (code != SSH_AGENT_SUCCESS && code != SSH2_AGENT_EXT_RESPONSE) {
```

### 4. Query wire format interop

**Agent side:** Change `process_ext_query` to emit SSH string encoding: replace
`u32 count` + cstrings with the extension list wrapped in standard SSH string
format (`u32 total-byte-length` + `u32 length` + `bytes` per name).

**Client side:** Detect format based on response type:
- Type 6 -> legacy pivy format (`u32 count` + cstrings)
- Type 29 -> spec format (SSH string encoding)

This preserves backward compat with older pivy-agent instances while supporting
spec-compliant agents.

### 5. Update RFC doc

Update `docs/rfcs/0001-ssh-agent-extensions.md` to document type 29 for
data-bearing extension responses.

## Rollback

Client accepting both types is strictly additive. Agent changes revert in one
commit. No deployed fleet -- single-user tool.
