---
status: accepted
date: 2026-10-12
approved: 2026-10-12
approval-note: >
  Approved by the operator on 2026-10-12 after review through the
  user-stories-and-end-UX tab beside the record: quotes are retrieval from
  the ledger and never introduce words (the quote prompt is a tier-1
  stand-in that disappears when the ledger is signed at observation);
  escalation and certificate prompts are permanent and visibly classed;
  the operator's tty, including a local posh attach, is a privileged
  channel. Implementations conform to this text; the conformance suite
  lands with FDR 0006 phase (a) (piggy#303).
amended: 2026-10-23
amendment-note: >
  2026-10-23 (piggy#332, circus EPIC 0001 D1/D4): the `piggy-escalation-v1`
  text shape names the record the act signs, which is a grant, a profile
  transition or an escalation request record, per the new §3.1 table;
  previously it named an escalation request record only. Docs only: the
  agent does not check text shapes, so no implementation changes.
  Second 2026-10-23 amendment (piggy#332, operator decision): §2.6 gains
  the input hold (at least 2 seconds, every input including cancel, in the
  process that shows the text; a surface that cannot hold fails the
  prompt) and permits emphasis by rendering attributes. Implemented by the
  askpass and the agent's tty route in the same series.
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

- the act's **display class** (§3: `quote`, `escalation` or
  `certificate`), rendered so that the prompt is visibly different from
  a routine PIN prompt and an `escalation` is visibly different from a
  `quote`;
- the card identity and slot (as `piggy health` names them);
- the `namespace`;
- the `text`, verbatim.

On the askpass route the agent carries the text through the existing
`PIGGY_ASKPASS_CONTEXT` mechanism (`crates/piggy/src/card_oracle.rs`,
`run_askpass_of_kind`) and MUST additionally export `PIGGY_ASKPASS_KIND` set to
the display class, so the askpass program can choose a distinct dialog
(title, icon, type, colour) per class; a routine PIN prompt carries no
`PIGGY_ASKPASS_KIND`. On the tty route the class and text are rendered
above the PIN line. The display MUST come from the same process that
computes the signed data (§2.7); a proxy agent MUST NOT display anything
(§2.8). An askpass program MAY reformat but MUST NOT elide or truncate
the text; a program that cannot show it in full MUST fail the prompt,
which the agent reports as `cancelled`.

**The display surface is privileged.** The prompt is only evidence if
nothing in an agent scope can write to the surface the operator reads
it from (FDR 0006, "Scopes: frontend and agent"). The card agent and the
askpass program it spawns MUST run outside every agent scope, and the
operator's terminal write side and graphical session MUST be unwritable
from an agent scope by construction. piggy relies on that property and
does not provide it: the mechanism is clown's (clown#244, the scope
split) and the terminal owner's (posh). Until it exists, the guarantee
rests on the card agent being a user service of the operator's session,
never a descendant of `claude`, and on the askpass being spawned by the
agent, never by the caller.

The PIN MUST be requested for this act regardless of any cached PIN the
agent holds, since the attested policy is PIN-always and the card will
demand it, and the PIN entered for an operator act MUST NOT be cached
for later requests. The agent MUST then perform the sign and MUST give
the operator a visible notice when the touch wait begins (a desktop
notification or a line on the tty; a log line is not a notice). A touch
timeout is `cancelled`.

An askpass program MUST render the text literally: it MUST NOT
interpret markup in it (zenity's Pango markup, for instance, so `<` and
`&` in a text must be escaped or markup disabled), and a program that
cannot show it in full MUST fail the prompt, as stated above. It MAY
emphasize parts of the text, such as the leading characters of a
markl-id, through rendering attributes applied to spans it identifies
itself (Pango attributes, terminal bold), never by interpreting markup in
the text; emphasis changes no character and elides none.

**The input hold.** A prompt for an operator act MUST take no input at
all for at least 2 seconds after the text is first shown: no PIN
keystroke, no approval, and no cancel. Input arriving during the hold MUST
be discarded, not queued for after it, and the hold MUST be visible (a
countdown or an equivalent sign) for as long as it lasts. The hold is kept
by the process that shows the text (§2.6 above: the askpass program, or
the card agent on the tty route), and counts from the first display of
that text: a redraw of the same text does not restart it, and a prompt
whose text changes starts a new hold. A window manager's close control is
outside the prompt's reach and MAY end the prompt during the hold; it ends
it as `cancelled`. A surface that cannot hold input (zenity's dialogs, for
instance) MUST NOT show an operator act: the program fails the prompt,
which the agent reports as `cancelled`, so the act is never shown where
a stray keystroke could approve or answer it.

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

**Operator-act namespaces are reachable only through this extension.**
An ordinary `SSH_AGENTC_SIGN_REQUEST` can carry sshsig signed data too:
`ssh-keygen -Y sign -n piggy-escalation-v1 -f 9c.pub` would otherwise
obtain a valid operator-namespace signature after a routine PIN prompt
and a touch, with the text never shown. An agent MUST therefore refuse
an ordinary sign request whose data begins with the `SSHSIG` preamble
and whose `namespace` field is registered for the `operator-act@piggy`
path (§3), for every key it serves. The check is on the signed-data
prefix only; `file`, `git`, `piggy-record-v1` and non-sshsig data are
untouched. `piggy sign-bytes` and any other piggy signing surface that
reaches a card directly MUST apply the same refusal.

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

Each namespace on the `operator-act@piggy` path carries a **display
class**, which the prompt renders (§2.6), and a **text shape**, which
the agent does not check but a verifier of that act kind MUST.

| Namespace                 | Path                  | Display class | Text shape and meaning |
|---------------------------|-----------------------|---------------|------------------------|
| `piggy-quote-v1`          | `operator-act@piggy`  | `quote`       | A quote of operator input already in the ledger (FDR 0032 D10). The text MUST be the recorded input verbatim, followed by one line `ledger <markl-id>` naming the transcript stanza it was taken from (`piggy-record-digest-v1@…`). A verifier MUST resolve that stanza and MUST fail if its recorded input differs from the quoted text. The quote adds the operator's touch to words the ledger already holds; it never introduces words. |
| `piggy-escalation-v1`     | `operator-act@piggy`  | `escalation`  | An escalation grant (FDR 0032 D11). The text MUST name the record the act signs by markl-id (`piggy-record-digest-v1@…`), which is one of the kinds in §3.1, and state in words what that kind's row says. A first grant to a grantee that holds no rights yet is an escalation too, as is a widening of an existing grant; the namespace does not tell the two apart, so a verifier that needs to know reads it from the named record, or from the text when the requesting system has the text say so. |
| `piggy-certificate-v1`    | `operator-act@piggy`  | `certificate` | A card-signed certificate or enrollment (FDR 0032 D2 root certificate, D15 enrollment blessing). The text MUST name the certified public key and the certificate request record by markl-id. |
| `piggy-record-v1`         | ordinary sign request | none          | A signed record (FDR 0032 D8) signed by a principal's own key through `ssh-keygen -Y sign -n piggy-record-v1` or an equivalent agent sign request; the message is the record's canonical bytes as troupe's RFC defines them. Not an operator act. |

`operator-act@piggy` MUST refuse (`refused-namespace`) any namespace not
registered in this table for the `operator-act@piggy` path. In
particular `file`, `git`, `email`, and `piggy-record-v1` MUST be
refused: the first three are OpenSSH's and git's domains, and the last
is reserved for signatures made without a display, so a verifier can
tell from the namespace alone whether a human saw the bytes, and from
which class of prompt. There is no operator-side override: an act under
an unregistered namespace is refused even if the operator would have
touched.

Other systems MAY have namespaces registered here for the
`operator-act@piggy` path by amendment (troupe is expected to, and FDR
0032 D15's pre-authorization policy records are the first candidate);
each registration names its display class and text shape. A verifier
MUST accept only namespaces its policy names.

#### 3.1. Records an escalation names

The record a `piggy-escalation-v1` text names is the one the act signs.
The kinds below are those FDR 0032 and spinclass FDR 0034 define; their
grammar and canonical bytes are the owning system's, and a verifier of a
kind MUST resolve the named record and MUST fail if the text's words do
not match it.

| Kind | The text names | The text states in words |
|------|----------------|--------------------------|
| grant | the grant record: a card root, or a re-issued root that widens a grant (FDR 0034 `profile-grant`) | the grantee, the profiles and rights granted, and whether the act is a first grant or a widening |
| profile transition | the transition record of a bound profile moving to a new digest (spinclass#407) | the profile and its old and new digests |
| escalation request | the escalation request record, for a right the requester was not granted (a merge escalation, FDR 0032 D11) | the granted right and its bound |

A kind is added to this table by amendment, like a namespace (§3).

### 4. markl-id purposes

Two purposes are registered in RFC 0011 §6.1's sense, owned by piggy
(RFC 0011 §6.1, FDR 0032 D7), to be added to that table and to
`crates/piggy-markl/src/purpose.rs` with phase (a):

| Purpose                 | Owner | Compatible formats            | Description |
|-------------------------|-------|-------------------------------|-------------|
| `piggy-record-digest-v1` | piggy | `sha256`, `blake2b256`        | Digest of a signed record's canonical bytes (FDR 0032 D8). This is the `H(message)` of a `piggy-record-v1` sshsig when the hash algorithm matches, and the value a `prev` set, a `ledger` line in a quote, and an escalation request name. |
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
    namespace      = "piggy-quote-v1"
    hash_algorithm = "sha256"
    text           = "grant swift-elder the right to force its children for six hours\nledger piggy-record-digest-v1@blake2b256-…\n"
    flags          = 0

What the operator sees on the workstation (`PIGGY_ASKPASS_KIND=quote`;
an `escalation` renders in the askpass's strongest style):

    ┌ piggy: QUOTE — sign what you said ─────────────────────────┐
    │ card 5da19c98, slot 9C                                      │
    │ namespace piggy-quote-v1                                    │
    │                                                             │
    │ grant swift-elder the right to force its children for       │
    │ six hours                                                   │
    │ ledger piggy-record-digest-v1@blake2b256-…                  │
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
the guise of a quote. Splitting the operator-act namespaces by display
class means an escalation can never be obtained behind a prompt that
looked like a quote: the namespace in the signature is the class the
operator was shown.

**Quotes never introduce words.** A `piggy-quote-v1` text must match a
ledger stanza (§3), so a session that wants the operator to bless words
the operator never typed fails the verifier's ledger check even if the
operator is tricked into touching. At tier 1 the ledger stanza is not
itself authenticated, which is why the operator must still read the
words; at tier 2 (FDR 0006 phase (d)) the stanza is signed at
observation and a quote needs no act at all. The `ledger` line is a
forward requirement: `clown/quick-cherry/krusty` reported on 2026-10-12
(clown master `814d90a`) that nothing in clown is content-addressed or
markl-identified today, that operator input is recorded only in Claude
Code's own JSONL under a harness-generated uuid, and that the
merkle-stable transcript identity belongs to FDR 0032 D8 / slice 2 in
troupe's transcript seam. Until a resolvable stanza id exists, a
`piggy-quote-v1` text cannot be formed, and operator acts use the
`escalation` and `certificate` classes only.

**The display surface is privileged.** §2.6 states the requirement:
nothing in an agent scope may write to what the operator reads the
prompt from, or the prompt proves nothing. A same-uid process that can
draw on the operator's terminal or graphical session could paint a
convincing fake prompt over the real one, or overwrite the text after
the operator read it. piggy does not and cannot provide that isolation
from inside the agent; it is a property of how clown and posh arrange
the operator's session. posh is a real path to that surface, not a
hypothetical one: a roaming session's pty master is posh's, and posh
can attach to a session on the same host (the operator: it "also
permits local binding", a local attach as a mechanism for tty access),
so the requirement extends to posh refusing an agent-scope attacher,
local or remote. Until it holds, the defence is that the real
prompt comes only from the card agent's own askpass, visibly classed
(`PIGGY_ASKPASS_KIND`), and that the card never signs anything the card
agent did not hash. FDR 0006 ("Scopes: frontend and agent") states the
principle: the operator's tty is privileged in both directions, the
structural twin of the signed XMPP message, and the two together are
what "the operator saw it" and "the operator said it" rest on.

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

**Direct card access.** §2.7's refusal covers every piggy signing
surface, but a process with PC/SC access to the card and knowledge of
the PIN can drive the 9C slot with another PIV tool and have it sign
operator-namespace bytes the operator never saw; the attested policy
still costs the attacker a PIN and the operator a touch, so the attack
needs the operator to touch for a prompt they did not get. The defences
are the ones already named: the operator treats an unexplained touch
request as hostile, direct PC/SC is confined to the card agent's
account where the host arranges it (FDR 0006 tier 2 does so for the
holder), and the ledger check of §3 fails a quote whose words are not
in the ledger regardless of how the signature was made.

**Software keys.** Nothing in this document raises a tier-1 software key
to an operator-act key: §2.4 is satisfied only by a slot that attests
PIN-always and touch-always, which a file key or a stock `ssh-agent`
cannot.

## Conformance Testing

Conformance tests for this specification live in
`zz-tests_bats/conformance/` and run in the fibby-backed agent lanes
(`piggy-testing(7)`). fibby attests keys generated on it
(`crates/fibby/src/attest.rs`) and answers `ATTEST` with `6A80` for a
seeded, imported or empty slot, so both the §2.4 fail-closed path and the
attested-policy rows run against it; the phase (a) hand pass (piggy#303)
repeats them on a real card. *(Corrected 2026-10-24: this paragraph was
written when fibby answered every `ATTEST` with `6A80`.)*

Tests use binary injection via `bats-emo`:

    require_bin PIGGY piggy
    require_bin FIBBY fibby

### Covered Requirements

| Requirement | Test File | Description |
|-------------|-----------|-------------|
| §2.1, MUST reject version ≠ 1, bad hash, flags ≠ 0, trailing bytes | `operator_act_request.bats` | malformed requests answer `bad-request` without prompting |
| §2.3, statuses 2–4 before any prompt | `operator_act_refusals.bats` | the askpass safety net records no prompt on policy, namespace and text refusals |
| §2.4, refuse when attestation unavailable | `operator_act_policy.bats` | a seeded fibby key (`ATTEST` → 6A80) yields `refused-policy` |
| §2.4, refuse a PIN-once/touch-cached slot | `operator_act_policy.bats` | a fibby slot attesting 9A defaults yields `refused-policy` |
| §2.5, displayability | `operator_act_text.bats` | empty, oversize, control-character and invalid-UTF-8 texts yield `refused-text` |
| §2.6, prompt carries class, text and namespace | `operator_act_prompt.bats` | the test askpass sees `PIGGY_ASKPASS_KIND` equal to the namespace's display class and its banner shows the namespace and the verbatim text |
| §2.7, verifies with `ssh-keygen -Y verify` | `operator_act_sign.bats` | the returned blob, armored, verifies under the slot key and `-n piggy-quote-v1` |
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
