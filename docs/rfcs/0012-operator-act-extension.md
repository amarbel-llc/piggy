---
status: proposed
date: 2026-10-12
---

# Operator-Act Agent Extension, sshsig Namespaces, and Record Purposes (piggy normative; FDR 0006 wire RFC part 1)

## Abstract

This document specifies the `operator-act@piggy` SSH-agent extension, by
which a caller obtains an SSH signature (sshsig) from a hardware PIV slot
whose policy requires a PIN and a touch for every use, over a text the
agent shows to the operator at the PIN prompt before signing. It also
registers the sshsig namespaces such signatures may carry, the markl-id
purposes for signed-record digests and signatures, and the export format
of the slot's attestation chain. Together these let a verifier establish
that a deliberate human act produced a signature, and bind what the
operator saw to what was signed.

## Introduction

spinclass FDR 0032 puts every key behind the SSH-agent seam and makes
piggy the owner of the agent seam, the 9C slot and its attestation, and
"the markl-id purposes for record digests and sshsig signatures" (D7).
Its D10 revises operator acts from an ordinary sign request plus a
display sidecar into an agent extension: "the caller sends the text and
an sshsig namespace, never a pre-built blob; the agent builds the sshsig
itself, shows that exact text on the PIN prompt, and signs." Its D11
names 9C, enrolled PIN-always and touch-always, as the single attested
escalation slot, with the F9 attestation certificate published beside
the public key as the trust anchor.

piggy FDR 0006 (`docs/features/0006-fibby-guarded-key-holder.md`) is the
design record; this is the first of its two wire RFCs, scheduled with
phase (a) (piggy#303). Part 2 (`mint@piggy`, `retire@piggy`, fibby's
control verbs) comes with phase (d).

Scope: the request and response bytes of `operator-act@piggy`; what the
agent MUST check, show and refuse; how a proxy agent routes the request;
the sshsig namespace registry; two new markl-id purposes; and the
attestation-export document. Out of scope: the signed-record grammar and
canonicalization (troupe's RFC, FDR 0032 D8), the enrollment flow (papi),
and which acts require which assurance (FDR 0032 D15).

Terms: **card agent** is the `piggy agent` instance that reaches the PIV
card over PC/SC; **proxy agent** is a `piggy agent --proxy-only` front or
any agent that forwards to upstreams (FDR 0001, piggy#215); **operator**
is the human at the keyboard of the host the card is plugged into;
**text** is the caller-supplied bytes the operator is shown and that are
signed; **slot** is a PIV key slot (`piggy-piv-slots(7)`).

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### 1. Encoding conventions

All multi-byte integers are big-endian. `string` and `uint32` are the SSH
wire types of RFC 4251 §5. An **ssh public key blob** is the
`string`-framed public key encoding of RFC 4253 §6.6 (for ECDSA P-256,
RFC 5656 §3.1; for Ed25519, draft-ietf-curdle-ssh-ed25519-ed448), as
returned inside `SSH_AGENT_IDENTITIES_ANSWER`. An **sshsig blob** is the
unarmored signature structure of OpenSSH `PROTOCOL.sshsig` §2:

    byte[6]   "SSHSIG"
    uint32    1
    string    publickey
    string    namespace
    string    reserved
    string    hash_algorithm
    string    signature

and its **signed data** is `PROTOCOL.sshsig` §3:

    byte[6]   "SSHSIG"
    string    namespace
    string    reserved
    string    hash_algorithm
    string    H(message)

### 2. The `operator-act@piggy` extension

#### 2.1. Request

The request is an agent extension message (RFC 9987's extension
mechanism, `SSH_AGENTC_EXTENSION`, message number 27):

    byte      SSH_AGENTC_EXTENSION
    string    "operator-act@piggy"
    string    contents

where `contents` is:

    uint32    version            ; 1
    string    key                ; ssh public key blob of the signing slot
    string    namespace          ; sshsig namespace, §3
    string    hash_algorithm     ; "sha256" or "sha512"
    string    text               ; the bytes to show and sign
    uint32    flags              ; 0

A receiver MUST reject a request whose `version` is not 1, whose
`hash_algorithm` is neither `sha256` nor `sha512`, or whose `flags` is
not 0, with status `bad-request` (§2.3). Unknown trailing bytes after
`flags` MUST be rejected the same way; there is no extension point in
version 1.

The caller MUST send the text itself. It MUST NOT send a hash, a
pre-built sshsig, or any structure the agent is expected to sign without
displaying. There is no field for one.

#### 2.2. Response

On any outcome other than the agent not knowing the extension at all,
the agent MUST answer with an extension response carrying the same
extension name (RFC 9987 allows an extension-specific success message;
in ssh-agent-lib terms, an `Extension` with `name` set to
`operator-act@piggy`):

    string    "operator-act@piggy"
    string    contents

where `contents` is:

    uint32    version            ; 1
    uint32    status             ; §2.3
    string    sshsig             ; sshsig blob when status is 0, else empty
    string    detail             ; UTF-8, MAY be empty

An agent that does not implement the extension answers
`SSH_AGENT_EXTENSION_FAILURE` (message number 28), as for any unknown
extension. A caller MUST treat `SSH_AGENT_FAILURE` and
`SSH_AGENT_EXTENSION_FAILURE` as "not supported here", distinct from a
refusal, so that it can tell an old agent from a denied act.

#### 2.3. Status codes

| status | name              | meaning |
|-------:|-------------------|---------|
| 0      | `signed`          | `sshsig` holds the signature. |
| 1      | `no-such-key`     | No card agent reachable from this socket serves `key`. |
| 2      | `refused-policy`  | The slot's attested policy is not PIN-always and touch-always, or its attestation could not be read. |
| 3      | `refused-namespace` | `namespace` is not registered for operator acts (§3). |
| 4      | `refused-text`    | `text` is not displayable (§2.5). |
| 5      | `cancelled`       | The operator declined, the PIN prompt was dismissed, or the touch timed out. |
| 6      | `card-absent`     | The key is known but its card is not present. |
| 7      | `bad-request`     | Malformed request (§2.1). |
| 8      | `error`           | Any other failure; `detail` says what. |

Statuses 2, 3 and 4 MUST be decided before any PIN prompt is shown.
Status codes above 8 are reserved; a caller MUST treat an unknown
non-zero status as a failure.

#### 2.4. Policy check

Before prompting, the card agent MUST read the slot's attestation (the
YubiKey `ATTEST` command for the slot, as the existing
`ykpiv-attest@joyent.com` extension does) and MUST verify all of:

1. the attestation certificate's public key equals the key in `key`;
2. the attested PIN policy is `always`;
3. the attested touch policy is `always`;
4. the attestation certificate chains to the card's F9 certificate.

If any of these cannot be established, including because the card does
not answer `ATTEST`, the agent MUST answer `refused-policy`. Policy is
read from the card at request time; an agent MUST NOT cache a positive
result across card removal and MUST NOT substitute a configured or
assumed policy for the attested one. A virtual card that cannot attest
therefore cannot serve operator acts; FDR 0006 phase (c) gives fibby an
attestation key for this reason.

Slot 9A as enrolled by `piggy card init` (PIN `once`, touch `cached`)
fails check 2 and 3 and MUST be refused. The specification does not
name 9C: any slot whose attested policy satisfies §2.4 MAY serve an
operator act, and 9C is the slot `piggy card init` provisions to satisfy
it.

#### 2.5. Displayable text

The card agent MUST show `text` to the operator, verbatim, before the
PIN is read. For that to be meaningful, `text` MUST be valid UTF-8 and
MUST NOT contain any Unicode code point in the C0 or C1 control ranges
other than U+000A (LF) and U+0009 (TAB). It MUST NOT be empty and MUST
NOT exceed 4096 bytes. A request failing any of these MUST be answered
`refused-text`. A caller that needs to bind a binary object puts that
object's markl-id (RFC 0011) in the text; FDR 0032 D11's escalation
grant, "a record by the card over the request's digest", is the model.

#### 2.6. Display and prompt

The card agent MUST present, on the same prompt that collects the PIN:

- the words `operator act` (so the prompt is distinguishable from a
  routine PIN prompt);
- the card identity and slot (as `piggy health` names them);
- the `namespace`;
- the `text`, verbatim.

On the askpass route the agent carries this through the existing
`PIGGY_ASKPASS_CONTEXT` mechanism (`crates/piggy/src/card_oracle.rs`,
`run_askpass`); on the tty route it is rendered above the PIN line.
The display MUST come from the same process that computes the signed
data (§2.7); a proxy agent MUST NOT display anything (§2.8). An askpass
program MAY reformat but MUST NOT elide or truncate the text; a program
that cannot show it in full MUST fail the prompt, which the agent
reports as `cancelled`.

The PIN MUST be requested for this act regardless of any cached PIN the
agent holds, since the attested policy is PIN-always and the card will
demand it. The agent MUST then perform the sign and MUST surface the
touch wait to the operator (the existing touch notification path). A
touch timeout is `cancelled`.

#### 2.7. Signing

The card agent computes `H(text)` with `hash_algorithm`, builds the
signed data of §1 with `reserved` empty, and asks the card to sign it
with the slot key using the signature algorithm the key type requires
(`ecdsa-sha2-nistp256` for a P-256 slot; `ssh-ed25519` for an Ed25519
slot). It then assembles the sshsig blob of §1 with `publickey` equal to
`key`, the request's `namespace` and `hash_algorithm`, `reserved` empty,
and the SSH-encoded signature. The agent MUST compute the hash itself
from `text`; it MUST NOT accept a caller-supplied digest.

The result MUST verify under `ssh-keygen -Y verify` with an allowed
signers file naming the slot's public key and `-n namespace`, once
armored per `PROTOCOL.sshsig` §1. The agent returns the unarmored blob;
armoring is the caller's.

#### 2.8. Proxy agents

A proxy agent (FDR 0001) MUST advertise `operator-act@piggy` in its
`query` response when at least one upstream does, and MUST forward a
request unchanged to the upstream that serves `key` (the upstream from
whose identities list the key came). It MUST NOT display the text,
prompt, or alter any field, and MUST relay the upstream's response
unchanged. If no upstream serves `key`, it answers `no-such-key`. This
is what makes an operator act work from a remote host over a forwarded
agent: the prompt appears where the card is.

A card agent answers `no-such-key` for a key it does not hold only when
it has no upstreams; with upstreams it forwards as a proxy agent would
(the native-miss rule of piggy#215).

### 3. sshsig namespace registry

`PROTOCOL.sshsig` requires a non-empty namespace so a signature intended
for one domain is not accepted in another. piggy owns the namespaces
operator acts and FDR 0032 records use (FDR 0032 D7). A namespace is
registered by amendment to this section and MUST match
`system-kind-vN` in the sense of RFC 0011 §6.2 rule 1 (`kind` MAY
contain `_`).

| Namespace                | Path                 | Meaning |
|--------------------------|----------------------|---------|
| `piggy-operator_act-v1`  | `operator-act@piggy` | A deliberate human act over displayed text: FDR 0032 D10's tier-1 quote, D11's escalation grant, D2's root certificate when signed by the card. The text is what the operator saw. |
| `piggy-record-v1`        | ordinary sign request | A signed record (FDR 0032 D8) signed by a principal's own key through `ssh-keygen -Y sign -n piggy-record-v1` or an equivalent agent sign request; the message is the record's canonical bytes as troupe's RFC defines them. Not an operator act. |

`operator-act@piggy` MUST refuse (`refused-namespace`) any namespace not
registered in this table for the `operator-act@piggy` path. In
particular `file`, `git`, `email`, and `piggy-record-v1` MUST be
refused: the first three are OpenSSH's and git's domains, and the last
is reserved for signatures made without a display, so a verifier can
tell from the namespace alone whether a human saw the bytes.

Other systems MAY have namespaces registered here for the
`operator-act@piggy` path by amendment (troupe is expected to); a
verifier MUST accept only namespaces its policy names.

### 4. markl-id purposes

Two purposes are registered in RFC 0011 §6.1's sense, owned by piggy
(RFC 0011 §6.1, FDR 0032 D7), to be added to that table and to
`crates/piggy-markl/src/purpose.rs` with phase (a):

| Purpose                 | Owner | Compatible formats            | Description |
|-------------------------|-------|-------------------------------|-------------|
| `piggy-record-digest-v1` | piggy | `sha256`, `blake2b256`        | Digest of a signed record's canonical bytes (FDR 0032 D8). This is the `H(message)` of a `piggy-record-v1` or `piggy-operator_act-v1` sshsig when the hash algorithm matches, and the value a `prev` set and an escalation request name. |
| `piggy-record-sig-v1`    | piggy | `ed25519_sig`, `ecdsa_p256_sig` | The raw signature over a record: the `signature` field of the sshsig blob with its SSH framing stripped to the fixed-width form RFC 0011 §5 defines (as `papi-doc-sig-v1` does). The sshsig blob remains the authoritative, self-describing form; this purpose names it in a markl-id slot. |

Whether a record carries the sshsig blob, the markl-id of its raw
signature, or both, is troupe's grammar decision (FDR 0032 D8). This
section fixes only what the ids mean when they appear.

### 5. Attestation export

The trust anchor of FDR 0032 D11 is published as one UTF-8 text
document, the **attestation bundle**, produced by the phase (a) export
verb. It MUST consist of, in order:

1. one line `# piggy-attestation-bundle v1`;
2. one line `# key <markl-id>` where `<markl-id>` is the slot public key
   with its registered purpose, for example
   `piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…` (RFC 0011 §6.1);
3. one line holding the slot public key in OpenSSH `authorized_keys`
   form (key type, base64 blob, and a comment naming the card and slot);
4. the slot's attestation certificate as a PEM `CERTIFICATE` block;
5. the card's F9 attestation-intermediate certificate as a PEM
   `CERTIFICATE` block.

Lines 1 to 3 MUST appear exactly once; blocks 4 and 5 MUST appear
exactly once and in that order. A producer MUST NOT include the Yubico
root CA; the verifier supplies it. A verifier MUST check that the
`authorized_keys` key, the `# key` markl-id, and the attestation
certificate's subject public key are the same key, that the attestation
certificate is signed by the F9 certificate, and that the F9 certificate
chains to a Yubico PIV attestation root it trusts. A verifier of an
operator-act sshsig MUST additionally check that the sshsig's
`publickey` is that key.

The bundle carries the same two certificates the
`ykpiv-attest@joyent.com` extension returns, in text form.

### 6. Examples

A request for a quote of the operator's words, built by a client and
sent to the forwarded agent on a remote host:

    version        = 1
    key            = <ssh blob of ecdsa-sha2-nistp256 AAAAE2VjZHNh… (slot 9C)>
    namespace      = "piggy-operator_act-v1"
    hash_algorithm = "sha256"
    text           = "grant session \"swift-elder\" on <host> the right spinclass:force for 24h\n"
    flags          = 0

What the operator sees on the workstation:

    ┌ piggy: operator act ───────────────────────────────────────┐
    │ card 5da19c98, slot 9C                                      │
    │ namespace piggy-operator_act-v1                             │
    │                                                             │
    │ grant session "swift-elder" on <host> the right             │
    │ spinclass:force for 24h                                     │
    │                                                             │
    │ PIN:                                                        │
    └─────────────────────────────────────────────────────────────┘
    (then touch the key)

Response: `status = 0`, `sshsig` = the blob; armored by the caller:

    -----BEGIN SSH SIGNATURE-----
    U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEE…
    -----END SSH SIGNATURE-----

Refusals, as the caller sees them:

| request | response |
|---|---|
| same request with `key` = slot 9A | `status 2 refused-policy`, `detail "slot 9A: PIN once, touch cached"` |
| `namespace = "git"` | `status 3 refused-namespace` |
| `text` containing U+001B | `status 4 refused-text` |
| operator presses Escape at the prompt | `status 5 cancelled` |
| sent to an agent built before phase (a) | `SSH_AGENT_EXTENSION_FAILURE` |

An attestation bundle:

    # piggy-attestation-bundle v1
    # key piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…
    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB… PIV_slot_9C card:5da19c98
    -----BEGIN CERTIFICATE-----
    …slot attestation…
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    …F9 intermediate…
    -----END CERTIFICATE-----

## Security Considerations

**What you see is what you sign.** The displaying component is the
hashing component (§2.6, §2.7), and the proxy MUST NOT display (§2.8).
A same-uid process on the caller's host can send any text, but cannot
make the card sign a text other than the one the operator reads at the
prompt on the card's host. This closes the gap FDR 0032 D10 recorded on
2026-10-05.

**Attested policy, not configured policy.** §2.4 reads the policy from
the card's attestation every time. A configuration file saying "9C is
PIN-always" is not evidence; an attacker who can rewrite configuration
could then obtain a signature from a cached-touch slot. Fail-closed on a
missing attestation is deliberate and is why fibby needs an attestation
key before it can serve this extension.

**Namespaces as domain separation.** Refusing `git`, `file` and
`piggy-record-v1` on the operator-act path (§3) means a human-touched
signature can never be mistaken for an automatic one and vice versa,
and an operator cannot be tricked into signing a commit or a file under
the guise of a quote.

**Displayability.** Control characters and oversize texts are refused
(§2.5) because terminal escape sequences could reflow or hide text at
the prompt. Homoglyphs and bidirectional overrides remain possible
within valid UTF-8; an askpass program SHOULD render text in a way that
exposes them, and a verifier that cares SHOULD constrain the character
set of its own record kinds further.

**The text is not secret.** It is shown on screen and travels over the
agent socket and any forwarded channel; callers MUST NOT put secrets in
it.

**Denial of service.** An operator act costs the operator a PIN and a
touch. An agent-scope process can spam requests; each one interrupts
the operator. The agent SHOULD rate-limit prompts per connection, and
the frontend-scope restriction FDR 0032 D10 anticipates (refusing
agent-scope callers by cgroup) is the structural fix, scheduled with
FDR 0006 phase (d) once clown#244 defines the scopes. Until then an
operator who did not expect a prompt cancels it, and `cancelled` tells
the caller so.

**Software keys.** Nothing in this document raises a tier-1 software key
to an operator-act key: §2.4 is satisfied only by a slot that attests
PIN-always and touch-always, which a file key or a stock `ssh-agent`
cannot.

## Conformance Testing

Conformance tests for this specification live in `zz-tests_bats/` and
run in the fibby-backed agent lanes (`piggy-testing(7)`), once FDR 0006
phase (c) gives fibby an attestation key; until then the §2.4 fail-closed
path is testable against today's fibby, which answers `ATTEST` with
`6A80`, and the remaining rows run against a real card under the phase
(a) hand pass (piggy#303).

Tests use binary injection via `bats-emo`:

    require_bin PIGGY piggy
    require_bin FIBBY fibby

### Covered Requirements

| Requirement | Test File | Description |
|-------------|-----------|-------------|
| §2.1, MUST reject version ≠ 1, bad hash, flags ≠ 0, trailing bytes | `operator_act_request.bats` | malformed requests answer `bad-request` without prompting |
| §2.3, statuses 2–4 before any prompt | `operator_act_refusals.bats` | the askpass safety net records no prompt on policy, namespace and text refusals |
| §2.4, refuse when attestation unavailable | `operator_act_policy.bats` | today's fibby (`ATTEST` → 6A80) yields `refused-policy` |
| §2.4, refuse a PIN-once/touch-cached slot | `operator_act_policy.bats` | fibby slot attesting 9A defaults yields `refused-policy` (phase (c)) |
| §2.5, displayability | `operator_act_text.bats` | empty, oversize, control-character and invalid-UTF-8 texts yield `refused-text` |
| §2.6, prompt carries text and namespace | `operator_act_prompt.bats` | the test askpass banner shows `operator act`, the namespace and the verbatim text |
| §2.7, verifies with `ssh-keygen -Y verify` | `operator_act_sign.bats` | the returned blob, armored, verifies under the slot key and `-n piggy-operator_act-v1` |
| §2.8, proxy forwards unchanged, never prompts | `operator_act_proxy.bats` | a `--proxy-only` front relays request and response byte-for-byte; the prompt fires in the card agent only |
| §3, namespace registry | `operator_act_refusals.bats` | `git`, `file`, `piggy-record-v1` and an unregistered name yield `refused-namespace` |
| §5, attestation bundle shape | `attestation_bundle.bats` | the export has exactly the five parts in order and the three key spellings agree |

## Compatibility

New extension; no existing consumer. An agent that predates phase (a)
answers `SSH_AGENT_EXTENSION_FAILURE`, which §2.2 makes distinguishable
from a refusal. The two markl purposes of §4 are additive to RFC 0011
§6.1 and follow its §6.2 rules; decoders that do not know them carry
them opaquely per RFC 0011 §6.6. A version 2 of the request will change
the `version` field and MUST be a new amendment; version 1 has no
extension point by design.

## References

### Normative

- OpenSSH `PROTOCOL.sshsig` — the sshsig blob and signed-data formats
  (read at `$OpenBSD: PROTOCOL.sshsig,v 1.5 2026/10/10`).
- RFC 9987 — the SSH agent protocol (`SSH_AGENTC_EXTENSION`,
  `SSH_AGENT_EXTENSION_FAILURE`).
- RFC 4251 §5, RFC 4253 §6.6, RFC 5656 §3 — SSH wire types and key and
  signature encodings.
- RFC 2119 — requirement keywords.
- piggy RFC 0011 — markl-id format, the purpose registry (§6) and the
  format table (§5).

### Informative

- spinclass FDR 0032, "Principals, handles, and provenance": D7 (piggy
  owns the seam, the purposes and 9C), D8 (the record grammar), D10
  (operator acts), D11 (9C as the attested escalation slot), D15
  (assurance levels).
- piggy FDR 0006, "fibby as guarded key holder": the design this RFC
  serves; phase (a) is piggy#303, tracking issue piggy#297.
- piggy FDR 0001 — the proxy-only agent front that forwards card
  extensions.
- `piggy-agent(1)`, `piggy-piv-slots(7)`, `piggy-testing(7)`.
- Yubico PIV attestation — the slot attestation certificate and the F9
  intermediate the bundle of §5 carries.
