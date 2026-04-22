---
status: proposed
date: 2026-02-28
---

# pivy-agent SSH Agent Protocol Extensions (`@joyent.com`)

## Abstract

pivy-agent extends the OpenSSH agent protocol with custom extensions for PIV
smart card operations. These extensions enable ECDH key agreement, certificate
retrieval, YubiKey attestation, key re-boxing, and agent status queries over the
standard `SSH_AGENTC_EXTENSION` (type 27) message. This document specifies the
wire format, dispatch mechanism, and behavioral requirements for each extension.

## Introduction

The OpenSSH agent protocol provides a generic extension mechanism via
`SSH_AGENTC_EXTENSION` messages. pivy-agent uses this to expose PIV smart card
operations to clients over a Unix domain socket, allowing programs to perform
cryptographic operations without direct PCSC access.

The extensions fall into three categories:

1. **Cryptographic operations** — `ecdh@joyent.com`, `ecdh-rebox@joyent.com`,
   `sign-prehash@arekinath.github.io`
2. **Certificate retrieval** — `x509-certs@joyent.com`,
   `ykpiv-attest@joyent.com`
3. **Status and discovery** — `query`, `pin-status@joyent.com`

Additionally, pivy-agent extends the standard `SSH_AGENTC_UNLOCK` message to
support PIN caching and status queries.

This specification covers the `@joyent.com` extensions, the third-party
extensions pivy-agent implements, and the extended LOCK/UNLOCK behavior.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### Wire Format Conventions

All messages use the standard SSH agent framing:

```
u32   msg_len     (length of remaining bytes, excluding this field)
u8    type        (message type code)
...   payload     (type-specific; msg_len - 1 bytes)
```

The maximum accepted `msg_len` is 262144 bytes (256 KiB).

Data types used throughout this specification:

| Type      | Encoding                                                     |
|-----------|--------------------------------------------------------------|
| `u8`      | Single byte                                                  |
| `u32`     | 4 bytes, big-endian                                          |
| `string`  | `u32` length prefix followed by that many raw bytes          |
| `cstring` | `string` with a trailing NUL byte included in the length     |
| `sshkey`  | `string` containing an SSH public key in standard wire format|

Relevant protocol constants:

| Constant                     | Value |
|------------------------------|-------|
| `SSH_AGENT_FAILURE`          | 5     |
| `SSH_AGENT_SUCCESS`          | 6     |
| `SSH_AGENTC_LOCK`            | 22    |
| `SSH_AGENTC_UNLOCK`          | 23    |
| `SSH_AGENTC_EXTENSION`       | 27    |
| `SSH_AGENT_EXT_FAILURE`      | 28    |
| `SSH2_AGENT_EXT_RESPONSE`    | 29    |

### Extension Dispatch

Extension requests use message type 27 (`SSH_AGENTC_EXTENSION`):

```
u8       type = 27
cstring  extname       (extension name, e.g. "ecdh@joyent.com")
...      payload       (extension-specific)
```

The agent dispatches by matching `extname` against its handler table. If no
handler matches, the agent MUST respond with `SSH_AGENT_FAILURE` (5).

#### String-Wrapped Extensions

Some extensions use an additional `string` wrapper around their payload. When
an extension is string-wrapped, the wire format is:

```
u8       type = 27
cstring  extname
string   inner_payload    (u32 length + extension-specific fields)
```

The inner payload is unwrapped before being passed to the handler. Extensions
that use string wrapping are noted in their individual sections.

#### Data-Bearing Responses

When an extension handler returns data, the agent MUST respond with
`SSH2_AGENT_EXT_RESPONSE` (29). Per draft-ietf-sshm-ssh-agent §3.8, all
`SSH2_AGENT_EXT_RESPONSE` messages MUST echo the extension name as the first
`cstring` field. Extensions that return no data (e.g.
`session-bind@openssh.com`) respond with `SSH_AGENT_SUCCESS` (6) instead and
do not include a name echo.

This follows the convention established in draft-ietf-sshm-ssh-agent (section
3.8) and matches the behavior of OpenSSH, Go x/crypto/ssh/agent, and
ssh-agent-lib.

#### Error Responses

When an extension handler returns an error, the agent MUST respond with
`SSH_AGENT_EXT_FAILURE` (28) as a single-byte response:

```
u32   1
u8    28
```

This response carries no error details. Clients that need to distinguish error
conditions SHOULD use the `pin-status@joyent.com` extension to query agent
state after a failure.

### Extension: `query`

Enumerates all extensions supported by the agent.

- **String-wrapped:** No

#### Request

No payload beyond `extname`.

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "query"                  (extension name echo)
cstring  name[0]                  (first supported extension)
cstring  name[1]                  ...
```

The response echoes the extension name `"query"` as required by the IETF spec
(draft-ietf-sshm-ssh-agent §3.8), followed by each supported extension name as
a flat `cstring`. Extension names are returned in registration order. Clients
read the echo, validate it matches `"query"`, then iterate remaining cstrings
until the message is exhausted. This matches the wire format used by OpenSSH's
`process_ext_query` in `ssh-agent.c`.

This extension MUST NOT return an error.

### Extension: `ecdh@joyent.com`

Performs ECDH key agreement using a PIV slot's private key.

- **String-wrapped:** Yes

#### Request

```
sshkey   key        (EC public key identifying the PIV slot)
sshkey   partner    (remote EC public key)
u32      flags      (MUST be 0; reserved for future use)
```

Both `key` and `partner` MUST be ECDSA keys. The agent MUST return an error if
either key is not `KEY_ECDSA`.

Non-zero `flags` MUST cause a `FlagsError`.

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "ecdh@joyent.com"    (extension name echo)
string   secret               (raw ECDH shared secret)
```

The agent MUST zero the shared secret from memory after writing the response.

#### Errors

| Error type        | Condition                                        |
|-------------------|--------------------------------------------------|
| `ParseError`      | Malformed request                                |
| `FlagsError`      | Non-zero flags value                             |
| `NotFoundError`   | No PIV slot matches `key`                        |
| `InvalidKeysError`| Keys are not both EC                             |
| `AuthzError`      | Client blocked by confirmation policy            |
| `NoPINError`      | PIN required but not cached and askpass failed    |
| `PermissionError` | PIV operation denied (PIN not presented)          |
| `TokenLocked`     | PIN retry counter exhausted                      |

#### PIN and Touch Handling

If the slot requires PIN authentication (`PIV_SLOT_AUTH_PIN`), the agent
attempts to present a cached PIN. If no PIN is cached, the agent SHOULD attempt
`$SSH_ASKPASS` to obtain one. If askpass is unavailable or the user cancels, the
agent MUST return `NoPINError`.

If the slot requires touch confirmation (`PIV_SLOT_AUTH_TOUCH`), the agent
SHOULD send an `SSH_NOTIFY_SEND` message to prompt the user before the PIV
operation.

### Extension: `ecdh-rebox@joyent.com`

Decrypts a `piv_ecdh_box` and re-encrypts the plaintext to a new recipient.

- **String-wrapped:** Yes

#### Request

```
string   boxbuf     (serialized piv_ecdh_box)
string   guidb      (GUID of target token for re-encryption; empty for default)
u8       slotid     (slot ID on target token)
sshkey   partner    (new recipient EC public key)
u32      flags      (MUST be 0)
```

If `guidb` is empty (zero-length string), the agent uses the currently selected
token for the re-encrypted box metadata.

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "ecdh-rebox@joyent.com" (extension name echo)
string   newbox               (serialized re-encrypted piv_ecdh_box)
```

The agent MUST zero the plaintext from memory after sealing the new box.

#### Errors

Same error types as `ecdh@joyent.com`, plus:

| Error type         | Condition                                   |
|--------------------|---------------------------------------------|
| `WrongTokenError`  | Box requires a different token (non-allcard) |
| `KeyDisabledError` | Box's key slot is disabled in agent config   |

### Extension: `x509-certs@joyent.com`

Retrieves the X.509 certificate stored in a PIV slot.

- **String-wrapped:** No

#### Request

```
sshkey   key      (identifies the PIV slot)
u32      flags    (MUST be 0)
```

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "x509-certs@joyent.com" (extension name echo)
string   cert_der            (DER-encoded X.509 certificate)
```

This extension reads from the agent's in-memory certificate cache. It does NOT
open a transaction to the card.

#### Errors

| Error type              | Condition                        |
|-------------------------|----------------------------------|
| `ParseError`            | Malformed request                |
| `UnsupportedFlagsError` | Non-zero flags value             |
| `NotFoundError`         | No slot matches `key`            |
| `BadCertError`          | DER encoding failed              |

### Extension: `ykpiv-attest@joyent.com`

Retrieves a YubiKey attestation certificate chain for a PIV slot.

- **String-wrapped:** Yes

#### Request

```
sshkey   key      (identifies the PIV slot)
u32      flags    (MUST be 0)
```

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "ykpiv-attest@joyent.com" (extension name echo)
u32      2                    (certificate count)
string   attest_cert          (DER-encoded slot attestation certificate)
string   attest_ca_cert       (DER-encoded YubiKey attestation intermediate CA)
```

The count field MUST be 2. The first certificate attests the key in the
specified slot; the second is the YubiKey's attestation intermediate CA
certificate (read from `PIV_TAG_CERT_YK_ATTESTATION`).

This extension requires a card transaction and is YubiKey-specific. Non-YubiKey
PIV tokens will return an error.

#### Errors

| Error type         | Condition                              |
|--------------------|----------------------------------------|
| `ParseError`       | Malformed request                      |
| `FlagsError`       | Non-zero flags value                   |
| `NotFoundError`    | No slot matches `key`                  |
| `InvalidDataError` | Attestation chain has unexpected format |

### Extension: `sign-prehash@arekinath.github.io`

Signs a pre-computed hash using a PIV slot's private key.

- **String-wrapped:** No

#### Request

```
sshkey   key       (identifies the PIV slot)
string   data      (pre-computed hash bytes)
u32      flags     (read but not validated; SHOULD be 0)
```

The `data` field contains the raw hash output (e.g., SHA-256 digest). The agent
passes this directly to the PIV sign operation without further hashing.

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "sign-prehash@arekinath.github.io" (extension name echo)
string   rawsig               (raw signature bytes from the PIV operation)
```

The signature is in the algorithm's native format (not SSH signature wire
format). The agent MUST zero the signature from memory after writing.

#### Special Restrictions

If the matching slot is `PIV_SLOT_KEY_MGMT` (0x9D), the agent MUST refuse the
operation unless the `-m` flag was given at startup. This prevents unintended
use of the key management slot for signing.

#### Errors

| Error type        | Condition                                 |
|-------------------|-------------------------------------------|
| `ParseError`      | Malformed request                         |
| `NotFoundError`   | No slot matches `key`                     |
| `AuthzError`      | Client blocked by confirmation policy     |
| `PermissionError` | Slot 9D signing not enabled, or PIN issue |
| `NoPINError`      | PIN required but not available            |
| `TokenLocked`     | PIN retry counter exhausted               |

### Extension: `session-bind@openssh.com`

Records SSH session binding state for agent forwarding safety. This is an
OpenSSH standard extension, not pivy-specific.

- **String-wrapped:** No

#### Request

```
sshkey   hostkey        (server's SSH host key)
string   session_id     (SSH session identifier)
string   signature      (signature over session_id by hostkey)
u8       is_forwarding  (0 = direct auth, 1 = forwarded)
```

The agent records the forwarding state but does not verify `signature`.

#### Response

```
u8       SSH_AGENT_SUCCESS (6)
u32      2
```

Note: The `u32(2)` payload is required by `ssh-agent-mux`, which parses the
response and expects the extra bytes. Removing it causes a framing error that
crashes pivy-agent (see [#19]).

#### Behavior

If a connection previously received a direct-auth bind (`is_forwarding = 0`)
and subsequently receives a forwarding bind (`is_forwarding = 1`), the agent
MUST deny all future signing operations on that connection. This prevents a
compromised server from reusing a forwarded agent.

### Extension: `pin-status@joyent.com`

Queries whether the agent has a PIN cached and whether the card is present.

- **String-wrapped:** No

#### Request

No payload beyond `extname`.

#### Response

```
u8       SSH2_AGENT_EXT_RESPONSE (29)
cstring  "pin-status@joyent.com" (extension name echo)
u8       has_pin              (1 if a PIN is cached, 0 otherwise)
u8       has_card             (1 if card is present and responsive, 0 otherwise)
```

The card-present check attempts a PCSC transaction begin/end. If the
transaction fails (card removed, reader error), `has_card` is 0.

This extension MUST NOT return an error. It always responds with
`SSH2_AGENT_EXT_RESPONSE`.

#### Client Usage

Clients SHOULD call this extension after receiving `SSH_AGENT_EXT_FAILURE` from
a cryptographic operation to determine the failure cause:

```
1. Call Extension("ecdh@joyent.com", payload)
2. If SSH_AGENT_EXT_FAILURE:
   a. Call Extension("pin-status@joyent.com")
   b. If has_card=0: report "card not present"
   c. If has_card=1, has_pin=0: prompt for PIN, call UNLOCK, retry
   d. Otherwise: report generic failure
```

### Extended LOCK/UNLOCK Behavior

pivy-agent extends the standard `SSH_AGENTC_LOCK` (22) and `SSH_AGENTC_UNLOCK`
(23) messages to support PIN caching.

#### LOCK (type 22)

```
u8       type = 22
cstring  passwd     (ignored)
```

LOCK drops any cached PIN (zeroing it from memory) and responds with
`SSH_AGENT_SUCCESS`. The `passwd` field is consumed but not used.

#### UNLOCK (type 23)

```
u8       type = 23
cstring  passwd     (PIN or empty string)
```

**Empty password (status query):** If `passwd` is a zero-length string, the
agent responds with `SSH_AGENT_SUCCESS` if a PIN is cached, or
`SSH_AGENT_FAILURE` if no PIN is cached. This does not modify agent state.

**Non-empty password (PIN caching):** The `passwd` value is treated as a PIV
PIN. The agent:

1. Validates the PIN format: MUST be 4-8 characters, alphanumeric only
   (`[0-9A-Za-z]`). Invalid PINs receive `SSH_AGENT_FAILURE`.
2. Opens a transaction to the card.
3. Calls `piv_verify_pin` to verify the PIN against the card.
4. On success: caches the PIN in memory and responds with `SSH_AGENT_SUCCESS`.
5. On failure: responds with `SSH_AGENT_FAILURE`. If the PIN retry counter
   reaches zero, the agent drops any previously cached PIN.

### Error Type Summary

| Error type              | Meaning                                           |
|-------------------------|---------------------------------------------------|
| `ParseError`            | Request could not be parsed                       |
| `FlagsError`            | Unsupported flags value                           |
| `UnsupportedFlagsError` | Unsupported flags (x509-certs variant)            |
| `NotFoundError`         | PIV card or slot not found                        |
| `WrongTokenError`       | Operation requires a different token              |
| `InvalidKeysError`      | Keys are not the expected type                    |
| `KeyDisabledError`      | Slot is disabled in agent configuration           |
| `AuthzError`            | Client denied by confirmation policy              |
| `NoPINError`            | PIN required but not cached and not obtainable     |
| `PermissionError`       | PIV operation denied                              |
| `TokenLocked`           | PIN retry counter exhausted                       |
| `InvalidPIN`            | PIN format invalid (UNLOCK only)                  |
| `InvalidDataError`      | Response data has unexpected format               |
| `BadCertError`          | Certificate encoding failed                       |
| `EnumerationError`      | PCSC enumeration failed                           |

All error types cause `SSH_AGENT_EXT_FAILURE` (28) when returned from an
extension handler. For LOCK/UNLOCK, errors cause `SSH_AGENT_FAILURE` (5).
Neither response carries error details on the wire.

## Security Considerations

**PIN handling.** Cached PINs are stored in a dedicated memory buffer and zeroed
with `explicit_bzero` on LOCK, PIN change, or agent shutdown. The PIN buffer
MUST NOT be swapped to disk (implementations SHOULD use `mlock` or equivalent).

**Shared secrets.** ECDH shared secrets and plaintext from rebox operations are
zeroed from memory immediately after being written to the response buffer.
Implementations MUST NOT log or persist shared secret material.

**Agent forwarding.** The `session-bind@openssh.com` extension tracks whether a
connection is direct or forwarded. The agent MUST deny signing operations on
connections that transition from direct-auth to forwarded, preventing a
compromised server from reusing credentials. Note that pivy-agent does not
verify the session-bind signature — it relies on the SSH client to provide
correct binding information.

**PIN status disclosure.** The `pin-status@joyent.com` extension reveals
whether a PIN is cached. This is a deliberate trade-off: the information
enables better client UX (actionable error messages) but also tells an attacker
whether the agent is "hot" (PIN cached, ready for operations). This extension
is only accessible to clients connected to the agent socket, which is already a
trust boundary.

**Error opacity.** Extension errors return `SSH_AGENT_EXT_FAILURE` with no
details. This is intentional — leaking error specifics (e.g., "wrong PIN" vs.
"card locked") over the wire could aid brute-force attacks. Clients that need
error discrimination SHOULD use `pin-status@joyent.com` rather than parsing
error details.

**Client authorization.** Extensions that perform cryptographic operations
(`ecdh`, `ecdh-rebox`, `sign-prehash`) check the agent's confirmation policy
before proceeding. The confirmation mode (`-c` flag) MAY require interactive
user approval for each operation.

## Compatibility

The `pin-status@joyent.com` extension is new (added 2026-02-28). Clients
SHOULD probe for its availability via the `query` extension before relying on
it. Clients targeting older pivy-agent versions MAY fall back to the
empty-password UNLOCK mechanism for PIN status queries, though `pin-status` is
preferred because it also reports card presence and does not overload the
LOCK/UNLOCK semantics.

The empty-password UNLOCK status query is a pivy-agent extension to the
standard SSH agent protocol. Standard SSH agent implementations will return
`SSH_AGENT_FAILURE` for empty-password UNLOCK, which is indistinguishable from
"no PIN cached." Clients MUST NOT rely on this mechanism when talking to
non-pivy agents.

## References

### Normative

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [draft-ietf-sshm-ssh-agent] "The Secure Shell (SSH) Agent Protocol", IETF
  Internet-Draft, section 3.8 defines extension response types.
- [OpenSSH agent protocol] OpenSSH `PROTOCOL.agent`, defines
  `SSH_AGENTC_EXTENSION`, `SSH_AGENT_EXT_FAILURE`, and the extension dispatch
  mechanism.

### Informative

- [PIV] NIST SP 800-73-4, "Interfaces for Personal Identity Verification"
- [PCSC] PC/SC Workgroup, "Interoperability Specification for ICCs and Personal
  Computer Systems"
