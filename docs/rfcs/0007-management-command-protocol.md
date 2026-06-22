---
status: proposed
date: 2026-06-22
---

# Management Command Protocol (piggy `manage` JSON-RPC)

## Abstract

This document specifies the JSON-RPC **command** protocol an external program uses
to drive piggy headless: it invokes piggy management operations (card enumeration,
provisioning, signing) as RPC methods over a byte stream, and while an operation
runs piggy issues the [RFC 0006] *interaction* requests (PIN, confirmation,
progress) back over the same connection. It defines the transports (stdio and an
`AF_UNIX` socket), the single-connection bidirectional model, an `initialize`
handshake, and the v1 method set, so a program such as an enrollment tool or a
GUI can perform a full piggy workflow without spawning CLI subprocesses.

## Introduction

[RFC 0006] specified the *interaction* layer — the callbacks piggy needs *from* a
frontend (secret/confirm/progress) and its `Frontend` trait with a JSON-RPC
binding. This document specifies the complementary *command* layer — the
operations a client invokes *on* piggy — completing the piggy#197 management-API
epic.

The motivating consumer is amarbel-llc/papi (piggy#203): papi composes the
user-facing password-store semantics from piggy's neutral primitives and needs to
drive them without the CLI. A headless command channel lets papi run piggy as a
long-lived engine and is the prerequisite for removing the in-piggy `papi`
namespace (piggy#191). A graphical frontend (piggy#202) is a second consumer.

Scope is the **command** layer and how it composes with [RFC 0006]'s interaction
layer on one connection. The v1 method set is the neutral primitives papi needs —
`card.list`, `card.init`, `sign_bytes`; `recipients.*` and `pass.*` methods are
future work (the latter likely unnecessary in piggy, since papi composes them).
This specification is expected to be refined as piggy#201 implements it.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### 1. Model and roles

A **client** invokes management operations; the **server** is piggy. On one
connection the two roles run in both directions:

- **Command direction (client → server):** the client sends JSON-RPC *requests*
  whose `method` is a management operation (§5); the server returns the result.
- **Interaction direction (server → client):** while a command runs, the server
  issues the [RFC 0006] §2 interaction requests (`secret.request`,
  `confirm.request`, `mgmt_key.request`, `card_select.request`) and notifications
  (`progress`, `completed`) *to the client*, which answers them.

The client MUST be prepared to answer interaction requests between sending a
command request and receiving that command's result. This is the inverse of
[RFC 0006]'s socket binding (where piggy is the JSON-RPC client and the frontend
the server): here piggy is the command server **and** the interaction-request
issuer, and the client is the command invoker **and** the interaction responder.

### 2. Framing

Messages MUST be JSON-RPC 2.0 objects, UTF-8, one object per line, terminated by a
single `\n` (LF), exactly as [RFC 0006] §4.1. A message MUST NOT contain an
unescaped newline. Implementations MUST ignore blank lines.

### 3. Transports

An implementation MUST support **stdio**: the client spawns `piggy manage
--jsonrpc` and exchanges messages over the child's stdin (client → server) and
stdout (server → client). The server MUST NOT write non-protocol output to that
stdout (diagnostics go to stderr). This is the headless default.

An implementation MUST also support an `AF_UNIX` **socket** selected by
`--socket <PATH>`: the server creates and listens on the socket; the client
connects. (Note the listen/connect roles are reversed from [RFC 0006] §4.2, where
the frontend listens — appropriate because here piggy is the long-lived server.)

### 4. Session

The client MUST send `initialize` as the first request:

    request  params := { "protocol": "piggy-mgmt/1" }
    response result := { "protocol": "piggy-mgmt/1" }

The server MUST reply with the protocol version it supports or a `-32600` error if
it cannot. The version string is shared with [RFC 0006] (both layers are versioned
together as `piggy-mgmt/<major>`). A client MUST reject an unknown major.

A connection is **single-flight** (v1): after sending a command request, a client
MUST NOT send another command request until it receives that command's result. It
MUST still answer interaction requests in the interim. Concurrent in-flight
commands are out of scope for this version. Because the connection is
single-flight, command-request `id`s (client-assigned) and interaction-request
`id`s (server-assigned) occupy independent spaces and cannot be confused: a line
carrying `method` is a request to its recipient; a line carrying `result`/`error`
is a response to the most recent outstanding request that recipient issued.

### 5. Methods (v1)

#### 5.1 `card.list`

    params := { "include_uninitialized": <boolean> }   ; default true
    result := { "cards": [ <card record> ] }

Enumerates attached PIV cards (the data behind `piggy list`), including
factory-blank cards (piggy#193) when `include_uninitialized` is true. Read-only,
PIN-free; issues no interaction requests.

A `<card record>` is one JSON object per *populated slot* (or per blank card),
exactly the structured form `piggy list --format=ndjson` emits. Three shapes,
discriminated by the boolean markers `unsupported` / `uninitialized` (absent ⇒
a supported, recipient-eligible slot):

    ; supported populated slot
    { "id":     <string>,    ; the markl id (e.g. piggy-recipient-v1@pivy_ecdh_p256_pub-…,
                             ;   piggy-piv_auth-v1@… for slot 9A) — the key handle
      "guid":   <string>,    ; 32 uppercase hex
      "serial": <integer>,   ; OPTIONAL (YubiKey serial, when available)
      "reader": <string>,
      "slot":   <string>,    ; "9A" | "9C" | "9D" | "9E" | "82".."95"
      "cn":     <string>,    ; OPTIONAL (slot cert Subject CN)
      "pin_policy":   <string>,   ; OPTIONAL
      "touch_policy": <string> }  ; OPTIONAL

    ; slot whose key piggy cannot use as a recipient (e.g. non-P-256 9D)
    { "unsupported": true, "guid", "serial"?, "reader", "slot",
      "cn"?, "pin_policy"?, "touch_policy"?, "reason": <string> }

    ; factory-blank card (no CHUID) — card-level, no slot (piggy#193)
    { "uninitialized": true, "guid": <all-zeros>, "reader", "serial"? }

A client reconstructs derived forms itself from the markl `id`: e.g. papi
renders the OpenSSH `authorized_keys` line for a slot-9A entry from its
`piggy-piv_auth-v1@…` id, so the protocol intentionally exposes **no**
`--format=ssh` projection. The `id` (and the slot-9D `piggy-recipient-v1@…`
id, from which an age recipient is derived) is the neutral key handle; framing
is the client's concern. `include_uninitialized: false` omits the
`uninitialized` records.

#### 5.2 `card.init`

    params := { "serial": <integer>,             ; OPTIONAL; omitted ⇒ the sole eligible card
                "allow_reprovision": <boolean> }  ; OPTIONAL; default false
    result := { "guid": <string>, "generated_management_key": <string> }
                                  ; generated_management_key present iff a random
                                  ; key was generated (RFC 0006 §2.3 "random")

Provisions a factory-blank card (piggy#194). With `allow_reprovision: true`
(piggy#204) an already-initialized card-in-hand is also eligible and is
re-provisioned (the destructive `confirm` escalates accordingly); a card whose
credentials were rotated off the factory defaults fails — the full creds-lost
reset is out of scope. Issues `confirm`, `secret`
(new PIN/PUK), `mgmt_key`, and `progress`/`completed` interaction requests. The
`generated_management_key` is sensitive (§Security).

#### 5.3 `sign_bytes`

    params := {
      "slot":    <string>,           ; "9a" | "9c"
      "guid":    <string>,           ; OPTIONAL; selects among cards
      "format":  <string>,           ; "raw" | "der"; default "raw"
      "message": <string>            ; base64 of the bytes to sign
    }
    result := { "signature": <string> }   ; base64 of the r‖s (raw) or DER bytes

Signs `message` with a PIV signing slot (piggy#190); piggy applies no
canonicalization. Issues a `secret` (PIN) interaction request unless the PIN is
otherwise available.

Unknown methods MUST be rejected with JSON-RPC error `-32601`.

### 6. Errors

Method failures use JSON-RPC error responses. `-32601` (method not found),
`-32602` (invalid params), `-32600` (bad/unsupported `initialize`). An operator
decline propagated from an interaction surfaces as `-32010` ("interaction
declined", [RFC 0006] §4.4). Card/operation failures use a piggy-specific code
`-32050` with a human `message` and SHOULD carry the underlying detail in `data`.
Transport failure (the connection closes mid-command) aborts the operation.

## Security Considerations

- **Secrets cross the channel in both directions.** Interaction responses carry
  PINs/PUKs/management keys ([RFC 0006] §Security); additionally a method *result*
  MAY carry a sensitive value — notably `card.init`'s `generated_management_key`.
  Over the `--socket` transport the socket MUST be an `AF_UNIX` socket owned by the
  invoking user with its containing directory no broader than `0600`, and an
  implementation MUST NOT use TCP. Over stdio the channel inherits the trust of
  whoever spawned `piggy manage`. Sensitive values MUST NOT be written to logs or
  the server's stderr.
- **The client is a trust boundary.** A client drives card mutations
  (provisioning) and supplies PINs; the server MUST grant it no capability beyond
  the methods in §5 and MUST NOT return private key material (signing/ECDH stay on
  the card). Provisioning a blank card is destructive; `card.init` MUST issue a
  `confirm` interaction the client can decline.
- **Single-flight bounds ambiguity.** Because a connection carries at most one
  in-flight command, an injected or misordered message cannot be mistaken for a
  different command's interaction response.

## Conformance Testing

Conformance tests live in `zz-tests_bats/conformance/piggy_manage_fibby.bats`
(`hardware`-tagged; runs against a fibby virtual card). Tests use binary injection
via `bats-emo` (`require_bin PIGGY piggy`) and a scripted **manage client**
(`crates/manage-client`) that connects, performs the `initialize` handshake, sends
a command request, answers the interaction requests piggy issues, and checks the
result — over BOTH stdio and `--socket`.

### Covered requirements

| Requirement | Description |
|---|---|
| §2 framing | One `\n`-framed JSON-RPC 2.0 object per message. |
| §3 transports | The same workflow runs over stdio and `--socket`. |
| §4 handshake | `initialize` version check; single-flight. |
| §5 methods | `card.list` enumerates; `card.init` provisions a blank fibby card; `sign_bytes` returns a verifiable signature. |
| §6 errors | An unknown method returns `-32601`. |

## Compatibility

- The protocol is versioned by the `initialize` `protocol` string
  (`piggy-mgmt/1`), shared with [RFC 0006]. New methods are additive; a
  backwards-incompatible change MUST increment the major.
- The command layer is strictly additive to piggy: the CLI commands are
  unchanged; `piggy manage` is a new entry point.

## References

Normative:

- [RFC 0006] Management Interaction Protocol (`docs/rfcs/0006-management-interaction-protocol.md`).
- [JSON-RPC 2.0] https://www.jsonrpc.org/specification.
- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels.

Informative:

- piggy#197 — the management-API epic. piggy#201 — this protocol's implementation.
- piggy#203 — papi driving piggy headless; piggy#191 — removing `piggy papi`.
- piggy#190 (sign-bytes), #193 (card enumeration), #194 (`card init`) — the v1 methods' CLI counterparts.
