---
status: draft
date: 2026-11-18
---

# Holder Mint and Retire Extensions (piggy normative when accepted; FDR 0006 wire RFC part 2)

> **Status of this draft.** Written with FDR 0006 phase (d) (piggy#383)
> on the operator rulings of 2026-11-18 recorded in
> `docs/plans/2026-11-18-fdr0006-phase-d-open-decisions.md` §7. The code
> on the same branch conforms to this text; the text is not accepted,
> and the operator's phase (d) hand pass may send either back.

## Abstract

This document specifies two piggy-private SSH-agent extensions served by
a **holder agent** (`piggy agent --holder`, FDR 0006 tier 2):
`mint@piggy`, by which a caller obtains a fresh signing key held on a
virtual card inside the holder's fibby and bound to a named scope, and
`retire@piggy`, by which the owning scope destroys it. It fixes the
request and response bytes, the status table, what the holder MUST check
about the calling connection, what a scope name is on the wire, and the
teardown rules. It completes the wire RFC FDR 0006 names, part 1 being
RFC 0012.

## Introduction

FDR 0006 puts every key behind the SSH-agent seam and makes the holder a
separate-uid service whose only key store is fibby. Its phase (d) is the
holder's agent mode: a session mints a key over the agent socket, signs
with it from the scope that minted it, is refused from any other scope,
and loses the key when it retires it or when its scope exits. The
operator ruled (2026-11-18) that a minted key lives in slot 9A with a
random holder-kept PIN and PIN and touch policy `never`; that the scope
field is a plain versioned name such as `piggy-mint-v1`, opaque and
optional on the wire, with room for a `@<format>-<data>` payload later;
and that a sibling scope's retire is refused as `not-bound-scope`.

Scope: the two extensions' bytes, statuses and checks; the scope field;
the peer read and the binding rule; teardown. Out of scope: how a host
classifies cgroups into the frontend and agent scopes (clown#244), the
systemd units (FDR 0006 "The holder service"), touch approval (phase (e))
and the provenance of the holder's attestation key (phase (f)).

Terms: **holder** is a `piggy agent --holder`; **card store** is the
fibby it creates cards in (phase (c)); **peer** is the process at the
other end of an agent connection; **scope definition** is a holder
configuration entry naming a rule for the cgroup a mint binds to;
**binding** is the cgroup path a minted key is bound to.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## Specification

### 1. Encoding conventions

As RFC 0012 §1: big-endian integers, the `string` and `uint32` of RFC
4251 §5, and an **ssh public key blob** as returned inside
`SSH_AGENT_IDENTITIES_ANSWER`. Both extensions are `SSH_AGENTC_EXTENSION`
messages (RFC 9987) whose `contents` is one `string`; both responses are
extension responses carrying the same extension name. An agent that is
not a holder answers `SSH_AGENT_EXTENSION_FAILURE`, and a caller MUST
read that as "not a holder", distinct from any refusal below.

### 2. Status codes

One table serves both extensions.

| status | name | meaning |
|-------:|------|---------|
| 0 | `ok` | minted (the response carries the key), or retired |
| 1 | `no-such-key` | the holder minted no key matching `key` |
| 2 | `not-bound-scope` | the caller is not inside the scope the key is, or would be, bound to |
| 3 | `unknown-scope` | `scope` names no definition this holder has |
| 4 | `scope-unbound` | no scope was named, and the holder infers none |
| 5 | `cap-reached` | the holder serves its cap of live cards; retire one first |
| 6 | `refused-key-type` | a key type the holder does not mint |
| 7 | `bad-request` | malformed request |
| 8 | `error` | any other failure; `detail` says what |
| 9 | `peer-unknown` | the holder could not read who is calling |

Statuses 2 to 6 and 9 MUST be decided before any card is created.
Codes above 9 are reserved; a caller MUST treat an unknown non-zero
status as a failure.

### 3. The `mint@piggy` extension

#### 3.1. Request

    byte      SSH_AGENTC_EXTENSION
    string    "mint@piggy"
    string    contents

where `contents` is:

    uint32    version            ; 1
    string    scope              ; §5; empty means absent
    string    key_type           ; "ssh-ed25519" or "ecdsa-sha2-nistp256"
    uint32    flags              ; 0

A receiver MUST answer `bad-request` for a `version` other than 1,
`flags` other than 0, a `scope` or `key_type` that is not UTF-8, or any
trailing byte: version 1 has no extension point. An unknown `key_type`
is `refused-key-type`, not `bad-request`.

#### 3.2. Response

    string    "mint@piggy"
    string    contents

where `contents` is:

    uint32    version            ; 1
    uint32    status             ; §2
    string    key                ; ssh public key blob when status is 0, else empty
    string    card               ; the card's handle (its reader name), else empty
    string    detail             ; UTF-8, MAY be empty

#### 3.3. What the holder does

In this order:

1. Refuse `refused-key-type` for a `key_type` the holder does not mint.
   This is a check of the request alone, so it comes before anything
   about the caller is read. When several refusals apply, the first in
   this order is the one answered: `bad-request` (§3.1),
   `refused-key-type`, `peer-unknown`, the scope refusals,
   `cap-reached`.
2. Read the peer (§6); without one, `peer-unknown`.
3. Resolve `scope` (§5) to a binding, or refuse `scope-unbound`,
   `unknown-scope` or `not-bound-scope`.
4. Refuse `cap-reached` when the holder already serves its cap of live
   cards, mints in progress included. The cap is 16 per holder (FDR
   0006; the pcsc-lite reader table).
5. Ask the card store for a card whose slot **9A** holds a fresh key of
   `key_type` with PIN policy `never` and touch policy `never`. The key
   MUST be generated inside the card store and MUST NOT be exportable.
   No other slot is minted: 9C and 9D MUST NOT be.
6. Read the slot's public key, and replace the card's factory PIN with a
   random PIN of at least 8 characters that the holder keeps in guarded
   memory and never returns. A failure after step 5 MUST destroy the
   card again before answering `error`.
7. Serve the key (it appears in `SSH_AGENT_IDENTITIES_ANSWER`, with a
   comment naming the card), record the binding, and answer `ok` with
   `key` and `card`.

#### 3.4. Using a minted key

A minted key is usable only from inside its binding (§6.3): the holder
MUST refuse an ordinary sign request, an ECDH or attestation extension
and a `retire@piggy` for it from any other peer. A `retire@piggy` is
answered `not-bound-scope` (§4.2). An ordinary sign request is answered
`SSH_AGENT_FAILURE`, which carries no text, so the holder MUST log
`not-bound-scope` with the key and the peer; a caller cannot tell this
refusal from any other failure on the wire. Listing is not gated.
Because the slot's policy is `never`, the holder MUST NOT ask for a PIN
to use the key; more generally an agent SHOULD honour a slot's attested
PIN policy of `never` for any card (piggy#383 item 4).

A minted key's attestation chains to the holder's card store's
attestation key, not to a hardware root (FDR 0006 phase (f)); a verifier
MUST NOT treat it as hardware-held.

### 4. The `retire@piggy` extension

#### 4.1. Request

    byte      SSH_AGENTC_EXTENSION
    string    "retire@piggy"
    string    contents

where `contents` is:

    uint32    version            ; 1
    string    key                ; ssh public key blob of the minted key
    uint32    flags              ; 0

`bad-request` as in §3.1, and for a `key` that is not a public key blob.

#### 4.2. Response

    string    "retire@piggy"
    string    contents

where `contents` is:

    uint32    version            ; 1
    uint32    status             ; §2
    string    detail

#### 4.3. What the holder does

Read the peer (`peer-unknown`); find the binding (`no-such-key`); check
the peer is inside it (`not-bound-scope`); then destroy the card (the
card store wipes it and removes its reader), forget the PIN, drop the key
from the served set and the binding, and answer `ok`. A card store that
fails to destroy the card is `error`, and the binding stays.

### 5. The scope field

`scope` is an opaque UTF-8 string. The operator's ruling gives it the
shape of a plain versioned name, `piggy-mint-v1`, and reserves a later
`piggy-mint-v1@<format>-<data>` payload form. A holder MUST NOT parse the
value: it MUST look it up, whole, among its scope definitions, so that a
plain name keeps its meaning whatever a payload form later adds. The
empty string is "absent" and MUST be answered `scope-unbound` (the holder
infers no scope from the connection until clown#244 defines the scopes;
an amendment will say what inference is then allowed). A value matching
no definition is `unknown-scope`, and the detail SHOULD name the
definitions the holder has.

A scope definition is holder configuration (`--scope NAME=RULE`,
piggy-agent(1)). Version 1 defines two rules:

- `caller`: the binding is the peer's own cgroup.
- `cgroup:<absolute path>`: the binding is that cgroup; the peer MUST be
  inside it, else `not-bound-scope`. The name is a claim; the peer is
  the proof.

Further rules are added by amendment. Nothing about a definition
crosses the wire.

### 6. Peers and bindings

#### 6.1. Reading the peer

A holder MUST read, for every connection it accepts and before serving
any request on it, the peer's credentials (`SO_PEERCRED`: uid, gid, pid)
and the peer's cgroup v2 path. The cgroup MUST be read through a
descriptor on `/proc/<pid>` opened when the connection is accepted, so
that a process exiting and its pid being reused after that point cannot
be read as the peer; implementations MAY use a pidfd for the same
purpose. A peer whose credentials or cgroup v2 line cannot be read is
unknown: every holder operation on that connection is `peer-unknown`.
The window between accept and that open is a known limitation.

#### 6.2. A binding

A binding is a cgroup v2 path, normalized (absolute, no trailing slash,
no empty component). A peer is **inside** a binding when its cgroup is
that path or one below it, compared component by component (`/a/b`
contains `/a/b/c` and not `/a/bc`; the root contains all).

#### 6.3. Who may do what

| operation | permitted from |
|---|---|
| mint under a `caller` scope | any peer (it binds to itself) |
| mint under a `cgroup:` scope | a peer inside that cgroup |
| sign, ECDH, attest with a minted key | a peer inside the key's binding |
| retire a minted key | a peer inside the key's binding |
| list | any peer |

A frontend-scope peer minting for a `cgroup:` scope it is not in is not
in version 1 (FDR 0006 phase (e); FDR 0007 phase (iii)).

#### 6.4. Teardown

A minted card is destroyed, exactly as a retire does, when its binding's
cgroup directory no longer exists under the cgroup2 mount
(`--cgroup-root`), which the holder MUST check at least every few
seconds (`--scope-poll-interval`, default 2). A holder restart loses
every key.

The disappearance of a cgroup directory is the backstop for a scope that
exits, not a guarantee for a service that restarts: a systemd unit's
cgroup can outlive `systemctl restart`, so a key bound to it survives
the restart (observed in the FDR 0007 phase (iii-a) VM lane). A service
that mints under a `cgroup:` scope MUST retire its previous key itself
when it starts (the new instance is inside the same binding, so the
holder permits it).

### 7. Examples

A session minting and using a key (piggy(1) `holder mint`):

    $ piggy holder mint --scope piggy-mint-v1 > id.pub
    piggy holder: minted ssh-ed25519 on card "piggy-holder 1" bound to scope piggy-mint-v1
    $ ssh-keygen -Y sign -f id.pub -U -n file record      # no PIN, no touch
    $ piggy holder retire id.pub
    piggy holder: retired holder:piggy-holder 1

From a sibling scope, the same key:

    $ ssh-keygen -Y sign -f id.pub -U -n file record
    ... agent refused operation          # the agent log: not-bound-scope
    $ piggy holder retire id.pub
    piggy holder: the holder refused the retire (not-bound-scope): ...

## Security Considerations

**The name is a claim.** A scope name selects a definition; it grants
nothing. The peer, read by the holder from the kernel, is what the
binding is checked against, so a caller gains nothing by naming another
scope's definition.

**What a minted key is.** It is software, in the card store's memory,
usable with no PIN and no touch by anything inside its binding that can
reach the holder's socket, until retire or scope exit. That is the
design (FDR 0006 "Plain version"): short-lived, scoped, capped, and
never able to sign an operator act because it is never in an
operator-act slot. The socket's permissions and the cgroup split are
the gates; piggy provides the check, the host provides the split.

**Same-cgroup processes are one scope.** Two processes in one cgroup are
indistinguishable to the holder; whether a session's agent runtime and
its frontend share a cgroup is clown#244's.

**The random PIN protects nothing a minted key needs**, since the slot
is PIN `never`; it keeps the factory PIN from unlocking any PIN-gated
operation on the card.

**A connection's credentials are its origin's, not its user's.**
`SO_PEERCRED` describes the process that connected. A peer inside a
binding can hand its connected socket to a process outside it
(`SCM_RIGHTS`), or proxy requests for one, and the holder will treat the
connection as inside. The binding authenticates where a connection came
from, not who holds it now; whatever is allowed to act inside a scope
can act for others from it. The holder cannot close this; the host's
process and socket hygiene (clown#244) bounds it.

**One cap, shared.** The cap of 16 is one pool for the whole holder, so
a single scope can mint 16 keys and make every other scope's mint
`cap-reached`. The socket's permissions limit who can try. Not closed in
version 1; a per-binding sub-cap, set in the scope definition, is the
follow-up.

**Pid reuse.** §6.1's descriptor closes the reuse window after accept;
the window before it remains and is bounded by how fast a pid space
wraps.

## Conformance Testing

`zz-tests_bats/conformance/piggy_holder_mint_fibby.bats`, run by `just
test-bats-conformance-holder-mint-fibby` over the fibby test double with
a staged cgroup root (piggy-testing(7)); `just explore-fdr0006-d` adds a
real sibling scope under systemd for the hand pass.

| Requirement | Test | Description |
|---|---|---|
| §3.3 steps 5 to 7, §3.4 no PIN | `piggy_holder_mint_fibby.bats` | a minted Ed25519 key is listed with its card comment, signs under `ssh-keygen -Y sign` with no VERIFY reaching fibby, and the factory PIN no longer changes the PIN |
| §3.1 key types | same | a P-256 mint succeeds; `rsa` is a client usage error |
| §2 statuses 3, 4; §5 | same | no scope is `scope-unbound`; an undefined one is `unknown-scope` naming the defined ones; a `cgroup:` scope the caller is outside is `not-bound-scope`; no card is created |
| §4 | same | a retire destroys the card and drops the key; a second retire is `no-such-key` |
| §6.4 | same | removing the bound cgroup directory destroys the card within the poll interval |
| §2 status 5 | same | the 17th mint is `cap-reached`; a retire frees a slot |
| §1 | same | an agent that is not a holder answers extension failure (client exit 3) |
| §3.4, §6.3 sibling | `explore-fdr0006-d` | a sign and a retire from a second transient scope are refused `not-bound-scope` |
| codec, §6.2, §5 rules, cap, teardown | `cargo test -p piggy` (`holder_ext`, `cmd::agent::peer`, `cmd::agent::holder`) | round trips and every cut is `bad-request`; containment by component; `resolve_scope` and `peer_may_use`; the cap counts reservations; a vanished cgroup directory tears down and a failed destroy keeps the binding |

## Compatibility

New extensions; no existing consumer. An agent that is not a holder, or
that predates phase (d), answers `SSH_AGENT_EXTENSION_FAILURE`. A version
2 of either request changes the `version` field and is a new amendment;
version 1 has no extension point. The scope field's payload form, and
any inference for an absent scope, are amendments to §5 that MUST keep a
plain name valid.

## References

### Normative

- RFC 9987 — the SSH agent protocol.
- RFC 4251 §5, RFC 4253 §6.6 — SSH wire types and key encodings.
- RFC 2119 — requirement keywords.
- piggy RFC 0012 — encoding conventions (§1), the operator-act extension
  a minted key can never serve.

### Informative

- piggy FDR 0006 — the holder, the scopes, tier 2; phase (c) (piggy#382)
  for the card store's `create` and `destroy`; phase (d) is piggy#383.
- `docs/plans/2026-11-18-fdr0006-phase-d-open-decisions.md` — the
  operator rulings this text follows; `2026-11-18-fdr0006-phase-d-implementation.md`.
- spinclass FDR 0032 — the principals that mint; clown#244 — the scope
  split.
- `piggy-agent(1)` HOLDER MODE, `piggy(1)` `holder mint` and `holder
  retire`, `piggy-testing(7)`.
