---
status: accepted
date: 2026-06-22
---

# Management Interaction Protocol (piggy `Frontend` + JSON-RPC)

## Abstract

This document specifies the interaction protocol between a piggy management
operation (the *engine* — e.g. signing, card provisioning) and a *frontend*
that supplies human input and renders progress. It defines a transport-agnostic
set of typed interactions — secret entry, management-key choice, confirmation,
card selection, and progress — and two bindings: an in-process default
(terminal/askpass) and a JSON-RPC 2.0 binding over a byte stream so an external
program (e.g. a TUI) can drive every interactive function. The protocol carries
structured **card identity** with each prompt so an operator handling multiple
cards is never asked for an unlabeled PIN.

## Introduction

Every interactive piggy operation today hand-rolls its own prompting: `piggy
sign-bytes` and the Rust agent build PIN-prompt strings inline, `pass show-batch`
formats its own, and the agentless path goes through `card_oracle`'s
`PinSupplier` closure. There is no shared notion of "ask the operator for X",
and no way for an alternate user interface to drive these operations. Two forces
make a single contract worthwhile now:

- **piggy#195** showed prompts must carry *structured* card identity (GUID,
  serial, CN): an unlabeled "Enter PIN" across two attached cards led an
  operator to enter the wrong PIN and block a card.
- **piggy#194** (`piggy card init`) needs a front-end seam to drive an
  interactive full-setup flow (admin/PIN/new-PIN/PUK/management-key +
  confirmation + progress), and the user directed that this seam be
  general — an external charmbracelet (Go) TUI should eventually drive *all*
  management functions over stdio/socket (the **piggy#197** epic).

This RFC specifies that seam once, so it is not provision-shaped. It is
**design-first**: piggy#194 Phase 3 is the first implementation (the engine and
both bindings), and this specification is expected to be refined as that lands.
Scope is the **interaction** layer (the callbacks an operation needs *from* a
frontend). A command-invocation layer (a frontend invoking piggy operations as
RPC methods) is out of scope here; for now a frontend invokes a piggy CLI command
and supplies `--frontend jsonrpc` so that command's interactions flow back over
the channel.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### 1. Model and roles

An *operation* runs inside piggy and drives a card. When it needs human input it
issues an **interaction request** and blocks until a **response**; it MAY also
emit non-blocking **notifications** (progress, completion). A *frontend*
satisfies requests and consumes notifications.

A frontend MUST implement every interaction defined in §2. Two bindings are
defined: an in-process terminal/askpass frontend (§5, the default) and a
JSON-RPC frontend over a byte stream (§4). The engine MUST be agnostic to which
binding is in use — it interacts only through the abstract operations in §2.

### 2. Interactions

Each interaction has a request and, unless noted as a notification, a response.

#### 2.1 Card identity

Requests that concern a specific card MUST carry a card-identity object so the
frontend can render *which* card the input is for:

    CardId := {
      "guid":   <string>,    ; REQUIRED, 32 uppercase hex chars (all-zeros = uninitialized)
      "serial": <integer>,   ; OPTIONAL, YubiKey factory serial; omitted if unavailable
      "cn":     <string>     ; OPTIONAL, the relevant slot cert's Subject CN
    }

A frontend MUST surface at least one human-distinguishing field (serial when
present, else GUID) in any card-scoped prompt.

#### 2.2 `secret` — request a PIN, PUK, or management key value

    request params := {
      "kind":   <enum>,      ; REQUIRED: "current_pin" | "new_pin" | "confirm_new_pin"
                             ;   | "current_puk" | "new_puk" | "confirm_new_puk"
                             ;   | "management_key" | "generic"
      "prompt": <string>,    ; REQUIRED human-readable text (the fallback rendering)
      "card":   CardId,      ; OPTIONAL; present for card-scoped secrets
      "slot":   <string>,    ; OPTIONAL PIV slot id, e.g. "9a"
      "attempts_remaining": <integer>, ; OPTIONAL; remaining tries before lockout
      "detail": <string>     ; OPTIONAL operation-specific context, e.g.
                             ;   "decrypt 5 secrets: a, b, c"
    }
    response result := { "secret": <string> }

`detail` is free-text context a frontend renders alongside (not in place of) the
card identity — telling the operator *what* they are authorizing (e.g.
`show-batch`'s pending decrypt set). It is distinct from `prompt` (the verb the
fallback rendering opens with) and `card` (the structured #2.1 identity): a
frontend SHOULD surface `detail` without displacing the card naming required by
§2.1 / §5.

The engine MUST treat the returned `secret` as sensitive: it MUST NOT be logged
and MUST be zeroized after use. A frontend that cannot or will not provide the
secret MUST return an interaction-declined error (§4.4) rather than an empty
secret.

#### 2.3 `mgmt_key` — choose a management-key source on provision

    request params := { "prompt": <string>, "card": CardId }
    response result :=
        { "source": "default" }            ; use the factory default management key
      | { "source": "hex", "key": <string> } ; a hex-encoded key the operator supplied
      | { "source": "random" }             ; generate and set a new random key

#### 2.4 `confirm` — a yes/no decision

    request params := { "message": <string>, "default": <boolean> }  ; default OPTIONAL
    response result := { "confirmed": <boolean> }

#### 2.5 `card_select` — choose among candidate cards

    request params := {
      "reason": <string>,
      "candidates": [ CardId + { "state": "provisioned" | "uninitialized" } ]
    }
    response result := { "guid": <string> }   ; MUST equal one candidate's guid

#### 2.6 `progress` — notification (no response)

    notification params := {
      "step":    <string>,   ; REQUIRED machine token, e.g. "generate-9d", "write-cert"
      "message": <string>,   ; REQUIRED human-readable
      "current": <integer>,  ; OPTIONAL
      "total":   <integer>   ; OPTIONAL
    }

#### 2.7 `completed` — terminal notification (no response)

    notification params := {
      "status":  "ok" | "error",  ; REQUIRED
      "summary": <object>,        ; OPTIONAL operation-specific result (e.g. {"guid": ...})
      "error":   <string>         ; OPTIONAL; present when status = "error"
    }

### 3. The in-process interface

The engine SHOULD express the interactions in §2 as a single Rust trait so both
bindings share one surface and the engine stays binding-agnostic, e.g.:

    pub trait Frontend {
        fn request_secret(&mut self, req: SecretRequest) -> Result<Zeroizing<String>, FrontendError>;
        fn request_mgmt_key(&mut self, req: MgmtKeyRequest) -> Result<MgmtKeyChoice, FrontendError>;
        fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError>;
        fn select_card(&mut self, req: CardSelectRequest) -> Result<Guid, FrontendError>;
        fn progress(&mut self, ev: ProgressEvent);
        fn completed(&mut self, ev: CompletedEvent);
    }

The request/response payload types MUST be the same serde types used on the wire
(§4) so the in-process and JSON-RPC paths cannot diverge. This trait generalizes
the existing `card_oracle::PinSupplier` (a PIN-only `FnMut(&str)` closure), which
SHOULD be re-expressed as a `request_secret` of `kind: "current_pin"`.

### 4. JSON-RPC binding

#### 4.1 Framing

Messages MUST be JSON-RPC 2.0 objects, UTF-8 encoded, one object per line,
terminated by a single `\n` (LF). A message MUST NOT contain an unescaped
newline. Implementations MUST ignore blank lines.

#### 4.2 Roles and channel

For interactions, **piggy is the JSON-RPC client** (it issues requests and
notifications) and **the frontend is the server** (it returns responses). The
channel MUST be distinct from the operation's data `stdout` (e.g. `sign-bytes`
writes the signature to stdout). Therefore:

- An implementation MUST support a dedicated channel selected by
  `--socket <PATH>` (an `AF_UNIX` stream socket). The frontend MUST create and
  listen on the socket before invoking the operation; piggy connects to it.
- An implementation MAY additionally support an inherited file descriptor for
  the channel; it MUST NOT multiplex the JSON-RPC channel onto a stdout that
  also carries operation data.

#### 4.3 Methods

| JSON-RPC `method` | §2 interaction | Has response |
|---|---|---|
| `secret.request` | 2.2 | yes |
| `mgmt_key.request` | 2.3 | yes |
| `confirm.request` | 2.4 | yes |
| `card_select.request` | 2.5 | yes |
| `progress` | 2.6 | no (notification) |
| `completed` | 2.7 | no (notification) |

Before the first request, piggy SHOULD send an `initialize` request with
`params := { "protocol": "piggy-mgmt/1", "operation": <string> }`; the frontend
MUST reply `{ "protocol": "piggy-mgmt/1" }` or an error if it does not support
the version. Unknown future methods MUST be rejected by a frontend with JSON-RPC
error `-32601` (method not found).

Example (frontend's view of one PIN request, `\n`-framed):

    <- {"jsonrpc":"2.0","id":1,"method":"secret.request","params":{"kind":"current_pin","prompt":"Enter PIN","card":{"guid":"2835305C6024B3255557BF6901443404","serial":15909078,"cn":"piv-auth@2835305C"},"slot":"9a","attempts_remaining":3}}
    -> {"jsonrpc":"2.0","id":1,"result":{"secret":"123456"}}

#### 4.4 Errors and cancellation

A frontend that declines or cancels an interaction MUST return a JSON-RPC error
response with code `-32010` ("interaction declined") and SHOULD include a human
message. The engine MUST treat `-32010` as an operator abort and unwind the
operation without retrying. Transport failure (the channel closes mid-operation)
MUST abort the operation as an error.

### 5. Terminal (default) binding

When no JSON-RPC channel is selected, the engine MUST use an in-process terminal
frontend that preserves piggy's current behavior: secrets are read via
`$SSH_ASKPASS` / the tty per `card_oracle::run_askpass` (honoring
`SSH_ASKPASS_REQUIRE`, #166), and progress/confirmation render to stderr/tty.

This binding MUST render the §2.1 card identity in card-scoped prompts: the
prompt text (the value passed to `$SSH_ASKPASS` as `argv[1]`, which a GUI askpass
shows without access to the caller's stderr) MUST name the card by serial (when
present) and short GUID, and SHOULD include the CN — satisfying piggy#195. (As of
this writing `piggy sign-bytes` already does so; this RFC makes it the contract
for every interactive operation.)

### 6. Selection

Interactive commands MUST accept `--frontend <tty|jsonrpc>` defaulting to `tty`,
and MUST accept `--socket <PATH>` when `--frontend jsonrpc` is given. A command
given `--frontend jsonrpc` without a usable channel MUST fail before performing
any card operation.

## Security Considerations

- **Secrets cross the channel.** `secret`/`mgmt_key` responses carry PINs, PUKs,
  and management keys. Over the JSON-RPC binding these traverse the socket in
  cleartext, so the socket MUST be an `AF_UNIX` socket owned by the invoking
  user with permissions no broader than `0600` on its containing directory; an
  implementation MUST NOT use a TCP transport for this protocol. Secrets MUST NOT
  be written to logs, traces, or the `progress`/`completed` notifications, and
  MUST be zeroized after use on the engine side.
- **The frontend is a trust boundary.** A malicious or compromised frontend can
  supply wrong/attacker-chosen secrets and observe prompts (which carry card
  identity, not secrets). The engine MUST NOT grant a JSON-RPC frontend any
  capability beyond answering the interactions it is asked; the frontend never
  receives private key material (signing/ECDH stay on the card) and never
  receives entered secrets back.
- **Card mis-identification is the motivating risk.** Because a wrong PIN can
  permanently block a card, the card-identity requirement (§2.1, §5) is
  security-relevant, not cosmetic: every card-scoped secret request MUST identify
  its card.
- **Attempts disclosure.** `attempts_remaining` reveals lockout proximity to the
  frontend; this is intentional (so a UI can warn) and is not sensitive.

## Conformance Testing

The reference implementation landed in piggy#194: the provisioning engine
(`crates/piggy/src/card/engine.rs`) and both bindings
(`crates/piggy/src/card/frontend/{tty,jsonrpc}.rs`), consumed by `piggy card
init`. Conformance lives in `zz-tests_bats/conformance/piggy_card_init_fibby.bats`
(`hardware` tag), which provisions a blank fibby card end-to-end through BOTH
bindings — the tty lane and a scripted JSON-RPC frontend server
(`crates/card-frontend-server`) over an `AF_UNIX` socket — exercising §4.1
framing, §4.3 methods + the `initialize` handshake, and §6 selection. The §5 tty
card-identity requirement additionally has card-free unit coverage in
`crates/piggy/src/card/frontend/tty.rs` and `crates/piggy/src/sign_bytes.rs`.

### Covered requirements (to be implemented with the engine)

| Requirement | Description |
|---|---|
| §4.1 framing | A JSON-RPC frontend receives one `\n`-framed JSON-RPC 2.0 object per message. |
| §4.2 channel | `--frontend jsonrpc --socket PATH` routes interactions to the socket; data stdout is unaffected. |
| §4.3 methods | Each interaction maps to its method; `initialize` version handshake. |
| §4.4 cancellation | A `-32010` error response aborts the operation without retry. |
| §5 tty identity | A card-scoped tty/askpass prompt names the card (serial + short GUID, CN when available) — piggy#195. |
| §6 selection | `--frontend jsonrpc` without a usable channel fails before any card op. |

Until the engine exists, the §5 tty card-identity requirement is already
exercised by `piggy sign-bytes`' prompt tests (`crates/piggy/src/sign_bytes.rs`).

## Compatibility

- The `tty` binding is the default and preserves current behavior, so existing
  callers and scripts are unaffected; the JSON-RPC binding is strictly additive
  and opt-in via `--frontend jsonrpc`.
- Existing interactive callers (`sign-bytes`, the Rust agent's on-demand PIN,
  `show-batch`, the `recipients` re-encrypt confirmations) SHOULD migrate onto
  the `Frontend` trait incrementally; each migration is behavior-preserving for
  the default `tty` binding. `card_oracle::PinSupplier` is the migration seed.
- The protocol is versioned by the `initialize` `protocol` string
  (`piggy-mgmt/1`). Backwards-incompatible changes MUST increment the major
  (`piggy-mgmt/2`); a frontend MUST reject an unknown major.

## References

Normative:

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels.
- [JSON-RPC 2.0] JSON-RPC 2.0 Specification, https://www.jsonrpc.org/specification.

Informative:

- piggy#197 — management JSON-RPC API epic (the inventory of interactive
  functions this protocol unifies).
- piggy#194 — `piggy card init` provisioning; the first engine + the first
  implementation of this protocol (`ProvisionFrontend`).
- piggy#195 — structured card identity in the PIN prompt (the §2.1/§5 driver).
- `crates/piggy/src/card_oracle.rs` — `run_askpass` / `PinSupplier`, the
  current PIN-supply seam this protocol generalizes.
