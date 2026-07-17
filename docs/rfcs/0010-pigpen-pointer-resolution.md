---
status: draft
date: 2026-07-16
provenance: |
  Specifies resolution for the pigpen "pointer" face (RFC 0008 §2.2): a
  document that names a resolver plugin by kind + opaque locator instead
  of carrying recipients directly. Motivated by piggy#216 ("piggy-ids
  sourced from a PAPI instance"); scoped as a neutral, papi-agnostic
  primitive per piggy#191 and papi's own
  docs/rfcs/0002-piggy-mgmt-constraints.md, so that piggy never contains
  papi-specific (or any other domain-specific) resolution logic. Reached
  via live cross-repo co-design with the papi/bold-cypress session
  working papi#54 (the publisher half); see
  docs/plans/2026-07-16-pigpen-pointer-resolver-design.md for the design
  rationale this RFC formalizes. Triage: piggy#26.
---

# RFC 0010 — pigpen pointer resolution

## Abstract

RFC 0008 §2.2 defines three faces of a pigpen document: a **recipient
set**, a **sealed document**, and a **pointer** — a document that names a
resolver plugin by `kind` and an opaque `locator` instead of carrying
recipients directly. This RFC specifies how a pointer is turned into a
recipient set: the `pigpen-resolver-<kind>` plugin discovery convention,
the one-shot invocation contract, piggy's caching behavior, and failure
semantics. Piggy performs no evaluation of the resolved bytes or the
locator itself; that trust boundary belongs entirely to the resolver
plugin.

## Status and Provenance

Draft. This RFC is a sibling to RFC 0008 (which it does not modify) and
RFC 0009 (whose §3.2 `piggy-ids` sniff gains a third case — see
[Compatibility](#compatibility)). It specifies protocol and runtime
behavior, not wire format: RFC 0008 §2.2 already fixed the pointer
document's on-disk shape.

The normative referent is:

- piggy RFC 0008 §2.2 — the pointer face's document shape (`kind=`/
  `locator=` tags, `! pigpen-pointer-v1` type line, structural
  disambiguation from the other two faces).

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Motivation

piggy#216 asks for `piggy-ids` to be sourceable from a PAPI instance, so
that an operator's encryption-recipient set has a single source of truth
instead of being manually synced (`pass recipients sync <file>`) into
every store. Read literally, "sourced from a PAPI instance" sounds like
it wants papi-specific logic inside piggy.

That reading is foreclosed by two standing constraints. First, piggy#191
removed the `piggy papi` namespace precisely to keep piggy free of
domain-specific (papi-flavored) logic; piggy's job is signing bytes and
reading cards, not canonicalization, framing, or trust policy for any
particular consumer. Second, papi's own
`docs/rfcs/0002-piggy-mgmt-constraints.md` states this constraint from
the papi side of the boundary: piggy is a neutral substrate, and
higher-level domain logic lives in the systems that consume it, not in
piggy itself.

The resolution is a **neutral primitive**: a pigpen document that points
at a resolver by opaque `kind` + `locator` (RFC 0008 §2.2), plus a
PATH-discovered plugin convention for turning that pointer into an
actual recipient set. Papi (or anything else — a corporate directory, a
static HTTP fetcher, a local script) implements a
`pigpen-resolver-<kind>` binary that knows how to resolve its own
`locator` scheme; piggy never contains a line of papi-specific (or any
other resolver-specific) code. This mirrors piggy#203's longer-term
direction of moving domain policy out of piggy and into the systems that
need it, rather than adding to what piggy has to know.

## 2. Resolver discovery

A pointer document's `kind` tag selects a binary named
**`pigpen-resolver-<kind>`**, discovered on `$PATH` exactly as any other
externally-invoked executable — piggy performs no registry lookup, no
configuration-file mapping, and no built-in list of known kinds. If no
executable named `pigpen-resolver-<kind>` is found on `$PATH`, resolution
fails per §5.

This convention is deliberately modeled on piggy's own existing
`age-plugin-<name>` precedent. `crates/age-plugin-piggy` builds a binary
literally named `age-plugin-piggy`, which `age` locates on `$PATH` and
invokes by name — the same "prefix + variant name → PATH-discovered
binary" shape this RFC reuses for `pigpen-resolver-<kind>`. Using the
same convention piggy already ships (rather than inventing a new
discovery mechanism) keeps the plugin surface predictable for anyone
already used to installing `age-plugin-*` binaries alongside `piggy` and
`age`.

`kind` values are not registered or reserved by this RFC. Anyone MAY mint
a new `kind` simply by publishing a `pigpen-resolver-<kind>` binary;
there is no central authority piggy consults. A `kind` string MUST NOT
contain a path separator (`/`) or a NUL byte, since it is used to
construct an executable name looked up via the process `$PATH` search —
this is the only constraint this RFC places on it.

## 3. Invocation contract

To resolve a pointer with kind `K` and locator `L`, piggy invokes:

```
pigpen-resolver-K resolve L
```

On success, the resolver MUST exit `0` and write a recipient-set-face
pigpen document (RFC 0008 §2.2) to stdout — the same document shape
piggy already parses for any other `piggy-ids` file. On failure, the
resolver MUST exit non-zero and MAY write a human-readable diagnostic to
stderr; piggy surfaces that stderr text verbatim in its own error (§5).
Piggy does not read stdin from the resolver process and does not
interpret anything the resolver writes to stderr beyond including it in
an error message.

This is deliberately a **one-shot** contract: one process invocation, one
argv, one stdout read, one exit code — not the bidirectional
`--age-plugin=recipient-v1` state machine `age-plugin-piggy` and other
age plugins implement (stdin/stdout age-plugin frames, back-and-forth
negotiation, multi-phase identity/recipient handling). Resolution is
inherently fetch-verify-return: given a locator, produce a recipient set
or fail. There is no negotiation to be had — no interactive PIN prompt,
no multi-round confirmation, no state that needs to survive across
calls. Requiring every resolver author to implement a stateful protocol
for what is, in the overwhelming majority of cases, "make one request
and hand back the response" would add real implementation complexity
(a plugin author has to model states most of them will never use) for no
protocol benefit. A resolver that itself needs interactivity (e.g.
prompting for credentials) is free to do so on its own terminal/agent
channel before it writes its final answer to stdout — that is entirely
inside the resolver process's boundary and none of piggy's concern.

Piggy's role in this exchange is pure mechanical dispatch: build the
argv above, run the process, capture stdout on success, and parse the
result with the same parser used for any other `piggy-ids` recipient-set
document. Piggy performs no HTTP, no signature verification, and no
kind-specific interpretation of `L` — see §6.

## 4. Caching (informative)

This section describes piggy's own runtime behavior for reducing
resolver invocations. It is not wire-format-normative and does not
constrain resolver implementations or cross-implementation
interoperability — a different piggy build could cache differently, or
not at all, without breaking compatibility with any resolver or any
other implementation reading pigpen documents.

Resolved recipient-set bytes are cached under `$XDG_CACHE_HOME/piggy/`
(falling back to the platform default when `$XDG_CACHE_HOME` is unset,
matching how the rest of piggy treats XDG base directories — see
`store.rs`'s `$PIGGY_STORE_DIR` / `$XDG_DATA_HOME` precedence for the
sibling convention on the data side). The cache is deliberately **not**
placed inside the store itself: the store is git-synced, and a
resolved-recipients artifact committed there would leak into git history
and go stale or conflict across machines and clones.

A cache entry has a time-to-live (TTL); a fresh entry is used without
invoking the resolver, and a stale or missing entry triggers a
resolution per §3. The TTL is a tuning lever, not a fixed protocol
parameter — it trades propagation delay (how quickly a recipient-set
change at the resolver's source becomes visible to piggy) against
resolver/network load on every `pass` invocation. A candidate default is
on the order of one hour; the exact value MAY be adjusted by
implementation as real usage surfaces either stale-recipient complaints
(lower it) or resolver-load complaints (raise it).

Callers can force a fresh resolution, bypassing the cache entirely, via
the `--no-cache` flag or the `PIGGY_PIGPEN_NO_CACHE` environment variable
(any non-empty value). This is useful when a recipient set is known to
have just changed and the caller does not want to wait out the TTL.

## 5. Failure semantics

Resolution failure is **hard**: there is no fallback to a stale cache
entry when a live resolution fails. This matches piggy's existing
posture of never fabricating a result rather than silently degrading it
(compare `health.rs`'s `SlotProbe::Error` variant, which surfaces an I/O
failure explicitly rather than collapsing it into an empty/negative
result). A resolver that answered correctly yesterday is not evidence
its answer is still correct today, and silently proceeding on stale
recipients is exactly the kind of silent-drift failure a
single-source-of-truth mechanism (piggy#216's whole point) exists to
prevent.

Failure MUST be surfaced as a hard error that aborts the command using
the pointer, and the error message MUST include:

- the pointer's `kind`;
- the pointer's `locator`;
- the underlying failure — the resolver's stderr text when the resolver
  ran and exited non-zero, or a distinguishable message when no
  `pigpen-resolver-<kind>` binary was found on `$PATH` at all (§2).

A missing resolver binary and a resolver that ran but failed are both
hard failures; only the message text distinguishes them, so an operator
can immediately tell "the plugin isn't installed" from "the plugin ran
and rejected the locator."

## 6. Security considerations

Piggy performs **zero trust evaluation** of either the resolved bytes or
the locator. Concretely:

- Piggy does not parse, validate, or restrict `locator` beyond the
  syntactic constraint in §2 (used only to build an argv, never
  interpreted as a URL, path, or anything else). Whatever meaning
  `locator` has — a URL, a directory name, an opaque token — is entirely
  the resolver's convention for its own `kind`.
- Piggy does not verify any signature, checksum, or provenance on the
  recipient-set document a resolver returns. If a resolver's own
  contract includes such verification (for example, verifying a
  self-signature the producer attached before handing bytes back), that
  verification happens *inside* the resolver process, before it ever
  writes to stdout. Piggy trusts the resolver's exit code and stdout
  exactly as it trusts any other producer of a `piggy-ids` file.
- Consequently, a malicious or compromised `pigpen-resolver-<kind>`
  binary on `$PATH` can return an arbitrary recipient set — adding an
  attacker-controlled recipient, dropping a legitimate one, or returning
  a document for a locator different from the one it was asked to
  resolve. This is not a novel trust boundary: it is the same boundary
  every other PATH-discovered plugin piggy already trusts, including
  `age-plugin-*` binaries and `$SSH_ASKPASS`. Operators are responsible
  for the provenance and integrity of everything installed on `$PATH`,
  as they already are for those.
- Because resolution can silently substitute a different recipient set
  on every cache-miss invocation (§4), operators relying on pointer
  resolution SHOULD treat `$PATH` integrity for `pigpen-resolver-*`
  binaries with the same care as they treat the PIV card itself: a
  compromise of either yields the attacker read access to whatever the
  pointer ultimately governs.

## Worked Examples

### A pointer document

```
---
- kind="papi-http"
- locator="https://example.com"
! pigpen-pointer-v1
---
```

### A resolver invocation transcript

Given the pointer above, piggy runs:

```
$ pigpen-resolver-papi-http resolve https://example.com
```

argv: `["pigpen-resolver-papi-http", "resolve", "https://example.com"]`
stdin: closed / not read
exit code: `0`
stdout:

```
---
# recipients for https://example.com, resolved 2026-07-16T18:04:00Z
- piggy-recipient-v1@pivy_ecdh_p256_pub-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd  # alice's yubikey (9D)
- piggy-recipient-v1@age_x25519_pub-<blech32>  # bob's age key
! pigpen-v1
---
```

Piggy parses this stdout exactly as it would parse the equivalent bytes
found directly in a `piggy-ids` file, then proceeds with whatever
operation triggered the resolution (encrypt-template building,
`recipients list`, etc.).

### A failure transcript

The resolver binary is present but the locator cannot be resolved (for
example, the papi instance is unreachable):

```
$ pigpen-resolver-papi-http resolve https://example.com
```

exit code: `1`
stderr:

```
pigpen-resolver-papi-http: GET https://example.com/papi/pigpen: connection refused
```

Piggy surfaces this as a hard failure of the command that needed the
recipient set, with an error along the lines of:

```
error: failed to resolve pigpen pointer (kind="papi-http", locator="https://example.com"):
  pigpen-resolver-papi-http: GET https://example.com/papi/pigpen: connection refused
```

No stale cache entry is substituted (§5), even if one exists from a
previous successful resolution.

## Compatibility

This RFC adds a third case to RFC 0009 §3.2's `piggy-ids` content sniff.
RFC 0009 sniffs a `piggy-ids` file two ways — the RFC 0003 legacy line
format, or a `---`-prefixed payload-less pigpen recipient-set document.
With the pointer face, the sniff becomes three-way: a `---`-prefixed
document is further distinguished by its `! ` type line, `pigpen-v1`
(recipient set) versus `pigpen-pointer-v1` (pointer, resolved per this
RFC before use). The sniff remains exact rather than heuristic, since
the type string is a structural, unambiguous signal (RFC 0008 §2.2). A
piggy build that predates this RFC does not recognize
`pigpen-pointer-v1` and rejects it as an unsupported pigpen type, the
same fail-closed behavior RFC 0009 §12 specifies for any pigpen type it
does not understand — it does not silently fall back to treating the
pointer tags as RFC 0003 recipient lines.

Nothing in this RFC changes RFC 0008's wire format or RFC 0002/0003/0004
in any way. A store that never creates a pointer-face document sees no
behavior change.

## References

### Normative

- piggy RFC 0008 §2.2 — the pointer face's document shape
- RFC 2119 — Key words

### Informative

- piggy RFC 0009 §3.2 — the `piggy-ids` content sniff this RFC extends
  to three cases
- `crates/age-plugin-piggy/` — the existing `age-plugin-<name>`
  PATH-discovery convention this RFC's `pigpen-resolver-<kind>`
  convention is modeled on
- piggy#216 — "piggy-ids sourced from a PAPI instance" (the motivating
  issue), and piggy#191 / piggy#203 — the layering constraints that rule
  out papi-specific logic inside piggy
- papi RFC-0001 §14 — the papi-side producer this pointer/resolver split
  was co-designed against: a self-signed `/papi/pigpen` endpoint and a
  `papi-http` resolver plugin implementing the `pigpen-resolver-<kind>`
  contract of this RFC from the papi side of the boundary
- `docs/plans/2026-07-16-pigpen-pointer-resolver-design.md` — the design
  document this RFC formalizes, including the cross-repo coordination
  log with the papi/bold-cypress session
