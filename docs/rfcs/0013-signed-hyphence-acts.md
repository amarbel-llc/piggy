---
status: accepted
date: 2026-11-10
approved: 2026-11-10
approval-note: >
  Accepted by the operator on 2026-11-10 after review through the
  user-stories-and-end-UX tab beside the record (seven questions answered
  2026-11-08 and 2026-11-09, the three remaining Limitations ruled
  2026-11-10: signer, any ancestor or the card may revoke; card revocations
  have their own display class; a narrow is lifted only by an escalation
  naming it). The acceptance had been deferred until the body grammar
  settled; cutting-garden FDR 0028 (ajour) and the RFC 0014 stencil
  fragment landed on cutting-garden master on 2026-11-09 (bed87cc,
  553815c). Built as of acceptance: the document and canonical form
  (piggy#357), the seal (#358), the producer `piggy act seal` (#359), the
  display rules (#360); the chain walk is #361 and the revocation display
  class #377.
---

# Signed Hyphence Acts: the `piggy-act-v1` document and its certificate chain (piggy normative)

> **Status.** Written on the operator's rulings of 2026-11-08 (Shape C and
> the comments on "Operator acts: Shape C versus Shape A"), reviewed
> through a user-stories tab beside this text, and **accepted 2026-11-10**
> (front matter). The hyphence RFCs this text builds on are themselves
> `proposed`. Evidence labels in the notes: **V** read in
> a named file at piggy master `f7f0db9` or in the sibling repositories
> named; **I** inference; **U** unknown; **R** an operator ruling, dated.
>
> **Amended 2026-11-09** on the operator's rulings in "Operator acts: where
> the permission lives" (the review document): the body is an espalier
> stream and the head may pin a capability profile by digest (Shape E);
> conditions are stacked, never compared, and piggy compares only rights
> and numbers (circus EPIC 0001 decision 3, adopted); `deny` is admitted in
> a body with one spelling. The head consolidation (dropping the derivable
> `issuer`, `issuer-key`, `namespace`, `hash`, `assurance`, `issued-at`)
> was ruled the same day: keep the full head and judge the prompt live
> first; the consolidation is the recorded fallback (Limitations, Tuning
> Levers). The mechanism's plain-words explanation is `piggy-acts(7)`.
>
> **Amended 2026-11-10** on the operator's rulings on the three Limitations
> the acceptance pass left open: a software `revocation` may be signed by
> the key that signed the revoked act or by any ancestor key on that act's
> chain (§4.6); a card `revocation` has its own namespace and display
> class, `piggy-revocation-v1` (§4.8; RFC 0012's fourth amendment, code as
> piggy#377); a self-narrow is lifted only by an escalation that names it,
> kept as written and watched as a Tuning Lever. The body grammar
> (cutting-garden FDR 0028) having settled the day before, the operator
> accepted this RFC the same morning.

## Abstract

This document specifies `piggy-act-v1`, a hyphence document that carries
one signed act: a certificate of a key, a grant or narrowing of rights, an
escalation, an approval, or a revocation. The signature is an SSH
signature (sshsig) over the document's canonical bytes, carried in the
document as its own metadata field, so one artefact is both the thing the
operator saw at the PIN prompt and the thing a verifier checks. Acts form
a chain rooted at the operator's PIV card: a certifying act's power comes
only from a valid path to a card-signed root, rights only shrink along a
path unless the card signs the step, and validity is decided by walking
the path. Trust is structural and mechanical; the document's words carry
no authority. The fine conditions under which rights are used ride beside
the head, as a capability profile pinned by digest (a stencil) or as a
patch of denials in the body, and are stacked along the chain, never
compared: a call is admitted only where every stencil admits it and no
patch denies it.

## Introduction

RFC 0012 made an operator act an sshsig over a text the agent shows at the
PIN prompt, with per-namespace conventions for what that text must say.
Those conventions were linguistic: a verifier had to read words. The
operator ruled on 2026-11-08 (R, in session) that the text becomes a
hyphence document whose metadata is the prompt and carries the whole
permission structurally; that each act is a small certificate under the
card as a CA; that trust is structural and mechanical, not linguistic; that
the language is the adding and dropping of privileges along the chain;
that a producer registers itself for free and is trusted through its
chain, not through a list piggy keeps; and that the signature is its own
metadata field, never the type-line lock.

This RFC is piggy's part: the document (the envelope), what is signed and
how, and the chain rules (who may certify whom, how rights move, how
validity and revocation work, how a verifier walks). The right vocabulary
that rides in the document is the consumer's. The needs of the first
consumers shaped this text; piggy is upstream of them, so nothing below
cites them normatively.

Scope: the `piggy-act-v1` document; its canonical bytes; the seal (key,
namespace, hash, signature); the act digest; two markl purposes; the
chain rules; the verification algorithm; the display rule; the mapping
onto RFC 0012's namespaces. Out of scope: the right vocabularies (the
consumers'); where acts are stored and found (the consumers'); the request
and decision records an act names; the holder that keeps software keys
(FDR 0006).

Terms: **act** is one `piggy-act-v1` document; **head** is its hyphence
metadata section; **body** is its optional hyphence body; **seal** is the
four fields that let a verifier rebuild the sshsig; **certifying act** is
a `root` or `link`, which binds a key to a principal and forms the chain;
**annotating act** is a `grant`, `narrow`, `escalation`, `approval` or
`revocation`, which attaches to the chain by naming acts; **chain** is the
path of certifying acts from one act to a card-signed root; **card act**
is an act signed through `operator-act@piggy` (RFC 0012); **software
act** is an act signed by a principal's own key through an ordinary agent
sign request; **principal** is an identity named by the platform that runs
it, opaque to piggy; **trust anchor** is a card public key a verifier
trusts as a root signer.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### 1. The document

An act is a hyphence document (hyphence RFC 0001, RFC 0002, RFC 0003) whose
type line is `! piggy-act-v1`. Its head carries the act in field lines
(hyphence RFC 0002 field content, `- key = value`). Its body is OPTIONAL;
when present it is an espalier stream of conditions (§4.9).

A head MAY contain only: `#` description lines, `- key = value` field
lines, and the `! piggy-act-v1` type line, plus `%` comments (which are
not signed, §3.1). A bare `-` tag or reference line, a `<` line, an `@`
blob line, a quoted field name, or a type-line lock MUST be refused.

A head-only act is the normal case (R: "the body can be empty entirely").
When a body is present it MUST be shown with the head (§6), it is signed
as its bytes stand (§3.1 step 7), and it is a patch of denials for the
consumer's enforcer (§4.9). piggy's verifier derives no authorization from
it and never evaluates it (R 2026-11-09, Shape E). The whole canonical
form, body included, obeys RFC 0012 §2.5's character rules (UTF-8; no C0
or C1 control character other than LF and TAB).

A field value is a hyphence `FieldValue` (V hyphence
`hyphence-content.peg`: a markl-id, a quoted string, or a bare word). A
markl-id whose purpose slot is bare needs no quoting (V, RFC 0011 §2.2
and the peg's `FieldValue <- MarklTerm / String / Bareword`). A bare word
MUST NOT contain a hyphence reserved rune, so a value that would (a space,
a comma, a quote) MUST be written as a quoted string; the fields below are
chosen so that no value needs quoting.

### 2. Fields

Field names are hyphence identifiers. piggy owns the unprefixed names
below; a consumer MAY add fields whose names carry its own prefix and a
colon (`spinclass:profile = dev`; V the peg admits an interior `:` followed
by an identifier rune). Prefixed fields MUST be carried and signed (§3)
and MUST be ignored by the chain rules (§4). An unprefixed field this
document does not define MUST be refused. A field marked **set** is
repeatable, one line per value, and its values form a set (§3.1 orders
them); every other field MUST appear at most once.

| Field | Values | Required | Meaning |
|---|---|---|---|
| `kind` | `root`, `link`, `grant`, `narrow`, `escalation`, `approval`, `revocation` | yes | the chain operation (§4.1) |
| `producer` | a namespaced identifier, `<domain>:<name>` | yes | the program that built the act, named in its own domain; no piggy registry (§7) |
| `subject` | a principal id (opaque, no reserved runes) | all kinds except `approval`, `revocation` | the principal the act is about |
| `subject-key` | markl-id of a public key, purpose `piggy-principal_pub-v1`, format `ssh_ed25519_pub` or `ssh_ecdsa_nistp256_pub` | `root`, `link` | the key being certified |
| `object` | a markl-id or an opaque id | `grant`; optional on `escalation`, `revocation` | the thing the rights are over, in the consumer's naming |
| `profile` | a hyphence RFC 0003 locked edge, `<name>@<digest>`, naming a capability profile document | optional on `root`, `link`, `grant`, `escalation`, `narrow` | the condition tree the rights are enforced under (§4.9); the digest pins it; piggy never resolves or parses it |
| `issuer` | a principal id, or `operator` | yes | who signs; `operator` iff `key` is a trust anchor (§5.1) |
| `issuer-key` | markl-id of the signing public key: purpose `piggy-piv_sig-v1` for a card act, `piggy-principal_pub-v1` for a software act | yes | equals `key` |
| `issuer-record` | act digest (§3.5) | every software act; MUST be absent on a card act | the certifying act that binds `issuer-key` to `issuer` |
| `right` | a namespaced string, `<domain>:<name>`, which MAY be spelled as a markl-id when the consumer pins a digest (`"roustabout:grammar:x"@blake2b256-…`); **set** | `root`, `link`, `grant`, `narrow`, `escalation` | one right; the vocabulary is the consumer's; piggy checks set relations only, over the parsed value |
| `names` | act digest (§3.5); **set** | `narrow`, `escalation`, `revocation`; optional on `approval` | the **acts** this act modifies, supersedes or revokes (§4) |
| `records` | a markl-id digest of a record that is not an act; **set** | `approval`; `escalation` SHOULD; `root` and `link` SHOULD | the consumer's records this act answers or decides (a request, a decision); opaque to piggy, never resolved by §5 |
| `prev` | record digest; **set** | optional | parents in the consumer's history (a DAG) |
| `not-before` | timestamp (below) | optional | not valid before |
| `not-after` | timestamp (below) | every card certifying act (`root`, card `link`); optional elsewhere | hard expiry (§4.5) |
| `issued-at` | timestamp (below) | yes | when signed, as the issuer claims; informational, never used by §4 or §5 |
| `assurance` | `piggy:hardware`, `piggy:software`, or a consumer's `<domain>:<name>` | yes | how the signing key was exercised (§4.7) |
| `nonce` | a bare word | optional | uniqueness when a consumer needs it |
| `key` | markl-id of the signing public key, spelled exactly as `issuer-key` | yes (seal) | the sshsig `publickey` |
| `namespace` | an RFC 0012 §3 namespace | yes (seal) | the sshsig namespace |
| `hash` | `sha256` or `sha512` | yes (seal) | the sshsig hash algorithm |
| `signature` | markl-id, purpose `piggy-record-sig-v1`, format `ed25519_sig` or `ecdsa_p256_sig` | yes (seal) | the raw signature, SSH framing stripped (RFC 0012 §4) |

`issuer-key` and `key` MUST be equal; both exist so the seal is
self-contained and the chain edge is explicit. For a `narrow`, `issuer`
MUST equal `subject`. A prefixed field MAY repeat; its values form a set.

**The Required column is also the admission list.** A field whose cell
names kinds (as required or as optional) is admitted on those kinds only;
on any other kind its presence MUST be refused (§5.2 step 1). A field whose
cell is `yes`, `optional`, or `optional elsewhere` is admitted on every
kind. So `right` MUST NOT appear on an `approval` or a `revocation`,
`subject-key` only on `root` and `link`, `names` never on `root`, `link`
or `grant`, and `profile` never on `approval` or `revocation`.

**Timestamps** are RFC 3339 in the one spelling
`YYYY-MM-DDThh:mm:ssZ`: UTC, uppercase `T` and `Z`, whole seconds, no
offset. Any other RFC 3339 spelling MUST be refused, so equal instants
have equal bytes.

**Key payloads.** RFC 0011 §5 defines `ssh_ed25519_pub` as the 32-byte
raw public key and `ssh_ecdsa_nistp256_pub` as the 33-byte SEC1
compressed point (V). A verifier rebuilds the sshsig `publickey` blob
(RFC 4253 §6.6) as: for Ed25519, `string "ssh-ed25519"`, `string <32
bytes>`; for P-256, `string "ecdsa-sha2-nistp256"`, `string "nistp256"`,
`string <65-byte uncompressed point>` obtained by decompressing the
payload (RFC 5656 §3.1). A payload that does not decompress MUST be
refused.

### 3. Canonical bytes, the seal and the act digest

#### 3.1. Canonical form

The **canonical form** of an act is the byte string a conforming hyphence
encoder emits (hyphence RFC 0001 "Encoder Behavior", RFC 0002, RFC 0003)
for the document after these normalizations, in order:

1. every `%` comment and every trailing comment is removed;
2. each `#` line is trimmed of leading and trailing ASCII space and TAB,
   empty ones are dropped, and the rest are joined with single spaces into
   one `#` line, placed first; an act with no description has none;
3. the field lines are ordered: piggy's fields in the order of the §2
   table, then every prefixed field sorted by field name as bytes; within
   a **set** field the values are sorted as bytes over their parsed
   (unquoted) values (a text value's text; a markl-id's unquoted purpose,
   `@`, format and data), never over their quoted spelling, and duplicates
   removed;
4. the `signature` line is removed;
5. the type line `! piggy-act-v1`, with no lock, comes last;
6. field lines are written in hyphence's spaced canonical spelling,
   `- key = value` (V hyphence RFC 0003, "canonical emission: spacing").
   A value is bare when hyphence allows it (a valid bare word under the
   strict sigil rule); otherwise it is a double-quoted string with the
   escape set the hyphence canonical encoder applies, which is
   piggy-markl's `quote_purpose` set (`\\`, `\"`, `\n`, `\t`, `\r`, `\a`,
   `\b`, `\f`, `\v`; every other character itself). For an act, which
   admits no control character but TAB (§1), the escapes that can occur
   are `\\`, `\"` and `\t`. A markl-id's purpose slot is bare when RFC
   0011 §2.1's bare purpose charset allows it, else quoted with the join
   after the closing quote. The typed head reader and this canonical
   emission are hyphence's: hyphence RFC 0005 (canonical emission) is the
   normative text, implemented in its Rust crate (`rust/hyphence`,
   `Head::encode`) and Go package (`go/hyphence/head.go`) as of hyphence
   master `7438bdf8` (2026-11-09 ruling); this RFC composes them and adds
   the ordering above;
7. the opening and closing `---` boundaries are included; if a body with
   at least one byte is present, the separator line and the body bytes
   follow unchanged; a separator followed by no bytes is not a body, and
   the document then ends with the closing boundary's line feed.

Two acts whose parsed content is equal MUST have equal canonical form,
whatever order, spacing or comments they arrived with.

#### 3.2. What is signed

The canonical form (§3.1) is the **text** in RFC 0012's sense: what the
agent shows at the PIN prompt and what it hashes. The signed data is
`PROTOCOL.sshsig` §3 over that text with the act's `namespace` and `hash`,
exactly as RFC 0012 §2.7 computes it. Nothing else is signed; the
`signature` field, the comments and the arrival order of lines are not.

A producer MUST send the canonical form as the `operator-act@piggy` text
(card act) or as the message of an ordinary sign request (software act).
The agent does not canonicalize; a producer that sends a non-canonical
document obtains a signature every verifier refuses.

#### 3.3. The seal

After signing, the producer adds the `signature` field: the sshsig blob's
`signature` field with its SSH framing stripped to the fixed-width form
RFC 0011 §5 defines, under `piggy-record-sig-v1` (RFC 0012 §4). The other
three seal fields (`key`, `namespace`, `hash`) are written before signing
and are inside the signed bytes.

**Low-S.** An ECDSA P-256 `signature` MUST be in low-S form (`s ≤ n/2`,
where `n` is the curve order). A producer normalizes a signature it
obtains (from a card, from `ssh-keygen`, from any library) by replacing
`s` with `n − s` when `s > n/2` before writing the seal; the normalized
signature still verifies everywhere. A verifier MUST refuse a `signature`
with `s > n/2` at §5.2 step 2. An Ed25519 `signature` MUST be canonical
(RFC 8032 §5.1.7: `S < L`), which strict verifiers already enforce. Both
rules exist because an act is named by a digest over its sealed bytes
(§3.5): without them, anyone holding a sealed act could re-encode its
signature into a second valid act with a second name, and a revocation or
narrow naming the first would miss the twin.

A sealed act and a detached sshsig blob are equivalent: the blob is
rebuilt from the four seal fields (`PROTOCOL.sshsig` §2: `publickey` from
`key`, `namespace`, empty `reserved`, `hash_algorithm` from `hash`,
`signature` re-framed from the field) and the text is the canonical form.
A verifier MAY verify either way; `ssh-keygen -Y verify` over the rebuilt
blob and the canonical form accepts every signature §5.2 step 2 accepts,
and §5.2 step 2 additionally refuses the high-S and non-canonical
encodings above, which OpenSSH accepts. A verifier given a detached blob
MUST check that the blob's namespace and public key equal the `namespace`
and `key` fields, and MUST apply the low-S rule to its signature.

#### 3.4. Size

The canonical form of a card act MUST NOT exceed RFC 0012 §2.5's 4096
bytes. A producer SHOULD keep it to what one prompt shows without
scrolling (Limitations). A software act has no prompt and no size rule
beyond its carrier's.

#### 3.5. The act digest

An act is named by its **act digest**: a markl-id under
`piggy-record-digest-v1` (RFC 0012 §4) over the **sealed canonical form**,
which is the canonical form of §3.1 with the `signature` line present, in
its table position. Producers MUST emit `blake2b256`; verifiers MUST
accept `blake2b256` and `sha256`. Because the signature is inside the
digested bytes, two signings of one head by a randomized signer (a card,
`ssh-keygen`) are two acts; a deterministic signer (Ed25519, ECDSA under
RFC 6979) re-signing one head with one key yields the same act. With the
low-S and canonical-S rules of §3.3, a given sealed act has exactly one
valid encoding and so one name.

### 4. Chain rules

#### 4.1. Kinds

| `kind` | Class | Signer | Effect |
|---|---|---|---|
| `root` | certifying | the card (`issuer = operator`) | binds `subject-key` to `subject`, grants its `right` set and sets a hard `not-after`; starts a chain |
| `link` | certifying | a certified principal (software) or the card | binds `subject-key` to a child `subject` with a `right` set ⊆ the issuer's effective rights; a **card `link`** is bounded by nothing, MUST carry `not-after`, and starts a chain like a `root` |
| `grant` | annotating | a certified principal or the card | gives `subject` the `right` set over `object`; software: ⊆ the issuer's effective rights |
| `narrow` | annotating | the subject's own key only (`issuer = subject`) | shrinks the effective rights of each act in `names` (all of which MUST have this `subject`) to their intersection with this `right` set |
| `escalation` | annotating | the card | sets the effective rights of the one certifying act or `grant` in `names` whose `subject` is this act's `subject` to this `right` set, which MAY exceed anything in the chain; `names` MAY also hold earlier `escalation` and `narrow` acts on that act, which it supersedes; SHOULD list the request in `records` |
| `approval` | annotating | the card | records a decision that confers no right; MUST list the decision in `records` |
| `revocation` | annotating | the card; or, for a software act, the key that signed the revoked act or any ancestor key on that act's chain (§4.6) | ends the validity of every act in `names` and of every certifying act below a revoked certifying act |

**Card acts have no `issuer-record`.** The card's key is the trust anchor
(§5.1), not a certified key, so a card act's chain edge is the anchor
itself; a card certifying act (a `root`, or a card `link`) is a **chain
start**. **Software acts MUST have one**, and it MUST resolve to a valid
certifying act whose `subject-key` equals this act's `key` and whose
`subject` equals this act's `issuer`.

`names` holds acts only; a verifier resolves every entry and answers
undetermined when it cannot (§5.3). `records` holds the consumer's
records; piggy never resolves them, and a consumer's verifier checks them
by its own rules.

#### 4.2. Rights move down, never up, without the card

A right is an opaque namespaced string; piggy checks set relations only
(byte equality of values). For a software `link`, the `right` set MUST be
a subset of the issuer's **certified rights** at verification time: the
rights of the issuer's certifying act computed by §4.3 with step 4 (the
narrows) omitted at every level of the chain, escalations applied. A
verifier MUST refuse a `link` whose set exceeds them. A narrow that the
issuer, or any ancestor, places on itself does not invalidate a wider
child; §4.3 step 2 intersects the child's rights with the narrowed set
instead (clarified 2026-11-10 with S6: a self-narrow is a promise that
cuts downwards, never a fault in the children). For a software `grant`,
the `right` set MUST be a subset of the issuer's effective rights **over
that `object`**: its certified rights together with the effective rights
of every valid `grant` it holds over the same `object` (§4.3), as a
union. A grant is therefore handed down over its object, which is how a
holder of a card grant narrows it for a child without the card
(spinclass FDR 0034's software grants under a card grant). The rights of
the held grants union for this bound; their conditions stack (§4.9), so
the child is admitted only where every held grant's stencil admits it.
The asymmetry is deliberate: a union of rights is a cheap set check, a
union of conditions would need the comparison §4.9 refuses. A `narrow` MUST be signed by its
subject's own key and can only remove. Only an `escalation`, a card act,
may add. A card `link` or `grant` is bounded by nothing but the
operator's judgement at the prompt.

**Conditions are stacked, never compared** (R 2026-11-09). piggy compares
between a child act and its parent only what is cheap and always
decidable: the `right` set, by subset. A `profile` edge or a body is never
compared by piggy to the one above it; every profile and body on a chain
is a layer, and the consumer's enforcer admits a call only where every
layer admits it (§4.9). A layer can therefore only remove, whatever it
says, and no containment check over conditions is needed anywhere.

#### 4.3. Effective rights

The **effective rights** of a certifying act C are computed from its
chain start down:

1. a chain start (`root`, card `link`): its `right` set.
2. a software `link`: its `right` set ∩ the effective rights of its
   issuer's certifying act.
3. Then the valid `escalation` acts naming C that are not superseded (not
   named by another valid escalation): if there is exactly one, replace
   the set with its `right` set; if there are several, C is
   **invalid** (conflicting escalations) until one supersedes the others.
   The replacement is absolute: an ancestor's narrow, which reached C only
   through step 2, no longer cuts C once the card has set C's rights
   (clarified 2026-11-10 with S6). Only a narrow naming C (step 4) and the
   stacked conditions (§4.9), which an escalation never thins, still cut.
4. Then every valid `narrow` naming C that is not superseded by the
   applied escalation: intersect with its `right` set. Issue order is
   irrelevant: a narrow cuts an escalation that does not name it, so the
   card restores a narrowed right only by an escalation that names the
   narrow.

The effective rights of a `grant` G over its `object` are G's `right` set,
then steps 3 and 4 applied with escalations and narrows naming G. A
`grant`'s rights belong to its `subject` over its `object` only; they
never flow into the subject's certifying chain, and they are handed down
only by a software `grant` over the same `object` (§4.2). An `escalation` or
`narrow` has no effective rights of its own; `approval` and `revocation`
confer none.

Annotating acts are found by what they name, not by walking from them: a
verifier MUST consult its source of acts for every valid `escalation`,
`narrow` and `revocation` naming any act it evaluates (§5.3 when it
cannot).

#### 4.4. Where a principal's key comes from

A software act's `issuer` is a principal, and its `key` MUST be bound to
that principal by the certifying act its `issuer-record` names. A
`grant`'s `subject` and a `narrow`'s `subject` are principals whose keys
are bound by their own certifying chains; a verifier that must act on a
grant finds the grantee's current certifying act by `subject` in its
store and checks that chain too.

#### 4.5. Validity and expiry

An act is **valid** at time T when: its signature verifies (§5.2); its
`not-before`, if any, is not after T; its effective expiry is after T; it
is not revoked; and, for a software act, its `issuer-record` act is valid
at T. The **effective expiry** is: of a card certifying act, its own
`not-after`, which it MUST carry; of a software act (certifying or
annotating), the earliest of its own `not-after` and its issuer's
certifying act's effective expiry; of a card annotating act, its own
`not-after`, and none if it carries none (it then ends only by
revocation or supersession). Renewal is a new chain start; nothing below
needs re-signing unless its own `not-after` has passed.

#### 4.6. Revocation

A `revocation` is an act and is valid under §4.5. It revokes each act in
`names` from the moment a verifier learns of it. A card `revocation` MAY
name any act. A software `revocation` MUST be signed, for each act it
names, by the `key` that signed that act or by an **ancestor key** of it:
the `subject-key` of any certifying act on the path the named act's
`issuer-record` starts (that act, its issuer's certifying act, and so on
to the chain start). A verifier MUST refuse a software revocation whose
`key` is neither, for any act it names. A card act has no ancestor key but
the card. (R 2026-11-10: the signer, any ancestor, or the card; the
operator chose reach over ceremony, since a revocation only removes.)
Revoking is not parentage: an act keeps its one `issuer-record` edge, and
a revocation, like an escalation, hangs off the act it names. A revoked
certifying act invalidates every
certifying act whose chain passes through it and every annotating act
whose `issuer-record` resolves through it. A `revocation` MUST NOT be
named by another `revocation`: revocations are final. Where verifiers
obtain revocations is the consumers' concern; a verifier that cannot
consult any revocation source MUST answer undetermined (§5.3).

#### 4.7. Assurance

`assurance` says how the signing key was exercised. piggy defines two
values and leaves the rest to consumers: `piggy:hardware` MUST be, and
MUST only be, the value of a card act (a key that satisfies RFC 0012 §2.4,
exercised with PIN and touch; the verifier knows this because the act's
`namespace` is a card namespace and its `key` is a trust anchor);
`piggy:software` is the value of an act signed by a principal's held key
with nothing else claimed. Any other value is a consumer's
(`barker:device`), MUST be on a software act, and is opaque to piggy;
what it means and what operations require it are the consumer's rules.

#### 4.8. Namespaces and kinds

The seal's `namespace` MUST be registered in RFC 0012 §3, and the `kind`
MUST be allowed for it:

| `namespace` | Signer | `issuer` | Allowed `kind` |
|---|---|---|---|
| `piggy-certificate-v1` | card | `operator` | `root`, `link` |
| `piggy-escalation-v1` | card | `operator` | `escalation`, `grant` |
| `piggy-approval-v1` | card | `operator` | `approval` |
| `piggy-revocation-v1` | card | `operator` | `revocation` |
| `piggy-record-v1` | a principal's own key, ordinary sign request | a principal | `link`, `grant`, `narrow`, `revocation` |

A card `revocation` has its own namespace and display class so the prompt
says that something is being cancelled, also when it cancels an
`escalation` or an `approval` (R 2026-11-10; RFC 0012's fourth amendment
registers `piggy-revocation-v1`). `piggy-quote-v1` carries no act (a quote
is a retrieval, RFC 0012 §3). A
verifier MUST refuse any pairing this table does not list, an `issuer` the
row does not allow, and an `assurance` inconsistent with the row (§4.7).
This table replaces the per-namespace text shapes of RFC 0012 §3 for every
act (Compatibility).

#### 4.9. Conditions: the profile edge and the body (the stencil stack)

The `right` set is the coarse ceiling. The fine conditions under which a
right is used (which tools, which paths, which recipe groups, which
argument values) ride in two places, both inside the signed bytes:

- **The `profile` edge.** A hyphence RFC 0003 locked edge,
  `<name>@<digest>`, naming a capability profile document. piggy does not
  define that document, resolve it or parse it; the digest pins it and the
  signature covers the pin. The document's shape is the consumer's (the
  first consumers write it as a hyphence document whose body is an
  espalier stream). The first consumers' convention (agreed 2026-11-10
  with cutting-garden, whose RFC registers the purpose, piggy RFC 0011
  §6.1; cutting-garden#414): the edge is a markl id, purpose
  `cutting_garden-stencil-digest-v1`, format `blake2b256`, over the
  canonical nested-espalier bytes of the stencil tree alone (no hyphence
  head, no surrounding document), so any spelling of the profile file
  canonicalizes to one value; an enforcer verifies a layer file against
  the verdict's `profile` edge by recomputing that digest, needing
  neither the act nor piggy. This binds producers and enforcers of
  cutting-garden stencils, not piggy, which still treats the edge as an
  opaque pin.
- **The body.** When present it MUST be a document in the **stencil
  fragment** of trellis (cutting-garden RFC 0014; the fragment is defined
  by cutting-garden FDR 0028, "ajour", and is theirs to change; as ruled
  2026-11-09 17:40: espalier, plus in the id slot the null id `_` (a
  pattern over existing objects) and the temp id `+` (an object that does
  not exist yet: a creation allowance), locked ids, the full field-operator
  set, value lists, `^` negation and the reserved tags `deny` and
  `subtree`; no sigils, closures, reverse edges, version subpaths or
  OR-groups; the PEG production for `_` and `+` is cutting-garden#395). It
  is signed as its bytes stand (§3.1 step 7); no canonical form is defined
  for it and none is needed, so a producer MAY write it in any input
  spelling FDR 0028 defines (the nested canonical form, or the heading
  rendering once the fragment's reader canonicalizes on read), and the
  prompt shows those bytes. piggy's reference verifier checks only that the body obeys RFC
  0012 §2.5's character rules and otherwise treats it as opaque bytes.

Every `profile` edge and every body on a chain is a **layer**, from the
chain start down, together with the layers of every valid `escalation`
and `narrow` naming an act on that chain. For a software `grant` G the
layers are, in this order: those of G's `issuer-record` chain; then, for
every valid `grant` G's issuer holds over the same `object` (the grants
that bound G, §4.2), that grant's own chain layers followed by its layers;
then G's own; then those of G's applied `escalation` and narrows. The
held grants' stencils ride down with the rights they bound, so a software
grant can never escape the profile a card grant pinned (clarified
2026-11-10 with S6). An `escalation` replaces, for
the act it names, that act's own layers of the kinds it carries: its
`profile` edge replaces the act's `profile` edge and its body replaces
the act's body, while a kind the escalation does not carry stays as the
act had it (an escalation with no body leaves the act's patch of denies
in place; to clear one, the escalation carries a body with no leaves).
The layers above remain. A `narrow`'s layer is added. (Clarified
2026-11-10 with S6: the operator reads the escalation's text, not the
act's old body, so a deny the session placed on itself is not lifted
unseen.)

**A `profile` layer is a stencil; a body is a patch.** A stencil admits
only what it names. A patch is transparent where it says nothing, and
every leaf it has carries `deny`: a body MAY only deny, and a tightening
of an allowance is spelled as a deny with a condition; a `+` node appears
in a patch only with `deny`. A body with a leaf that does not carry `deny`
is malformed, and an enforcer MUST treat the act as admitting nothing. A smaller allow-set is a new profile pinned by
`profile`, never a body.

The **stencil stack** is the rule the consumer's enforcer applies to the
layers at call time, and the only meaning piggy assigns them:

1. a call is admitted only where there is at least one stencil, every
   stencil admits it and no layer denies it; a stack with no stencil admits
   nothing;
2. a stencil that says nothing about a value is not an admission of it (a
   patch that says nothing is transparent);
3. a `deny` in any layer refuses, where `deny` is the one trailing tag the
   consumer's node types give it (the first consumers: after the type,
   where `subtree` goes).

Because every layer must admit, a layer can only remove, and a child
cannot widen what its parent allows however it is written. piggy's
verifier therefore never compares one layer with another (§4.2); it
returns them with the verdict (§5.3). What a node, a tag or a condition
means, and which program evaluates them, is the consumer's: the evaluator
sits where the call is dispatched, never in piggy.

The grammar dependency runs piggy → hyphence → trellis (V
`0014-trellis.peg`), so this section cites trellis without piggy's
verifier parsing it; the citation binds the producers that write bodies
and the enforcers that read them. `piggy-acts(7)` explains the stencil
stack in plain words.

### 5. Verification

#### 5.1. Trust anchors

A verifier holds a set of card public keys it trusts as root signers:
keys whose RFC 0012 §5 attestation bundle it has checked, or an
allowed-signers file naming them. piggy defines no distribution for the
set; the verifier's owner does. `issuer = operator` MUST be used, and MUST
only be used, when `key` is in that set.

#### 5.2. Algorithm

Given an act A, a time T and a store S of acts:

1. Parse A; refuse a type other than `piggy-act-v1`, a line kind §1
   forbids, a duplicate non-set field, an unknown unprefixed field, a
   missing required field, a field on a kind that does not admit it (§2,
   the admission list), a value outside §2 (including a P-256 key payload
   that does not decompress to a point on the curve, §2 "Key payloads"),
   or a body outside RFC 0012 §2.5's character rules (§4.9). A
   canonicalizer that does not carry curve arithmetic MAY defer the
   decompression check to step 2, but a verifier MUST refuse such a key
   before step 2 reports a signature result.
2. Compute the canonical form (§3.1) from the parsed document and the
   signed data (§3.2); verify `signature` under `key` with the algorithm
   the key type requires. Refuse on failure.
3. Check `issuer-key = key`; check the `namespace`, `kind`, `issuer` and
   `assurance` rules (§4.7, §4.8); for a `narrow`, check
   `issuer = subject`.
4. If A is a card act: `key` MUST be a trust anchor; `issuer-record` MUST
   be absent; a card certifying act MUST carry `not-after`. Otherwise
   resolve `issuer-record` in S to a certifying act P; refuse if missing,
   if P's `subject-key` is not `key` or P's `subject` is not `issuer`, or
   if P is not valid at T (this algorithm, recursively, depth capped).
5. For a software act, apply the kind's rule (§4.1, §4.2): a `link`
   against P's certified rights; a `grant` against P's certified rights
   together with the effective rights of the issuer's valid grants over
   the same `object`, found in S by `subject` and `object`. A card act is
   bounded by no P (§4.2).
6. Resolve every act in `names`; answer undetermined if one cannot be
   resolved; refuse if an entry is not of a kind the §4.1 row allows, or
   has a `subject` the row requires to match and it does not. Collect
   from S the valid `escalation`, `narrow` and `revocation` acts naming A
   (and, for a certifying A, naming any act on its chain); compute
   effective rights (§4.3) and effective expiry (§4.5); refuse if
   expired, not yet valid, revoked (§4.6), or invalid under §4.3 step 3.
   A `narrow` or `revocation` whose own `issuer-record` chain passes
   through A, or through an act whose evaluation is in progress, is taken
   as valid for that inner check once its own steps 1 to 3 and §4.5 hold:
   both kinds only remove, so this over-applies and never widens
   (clarified 2026-11-10 with S6).
7. Return the verdict.

A verifier MAY memoize a valid act until its effective expiry or until it
learns of a `revocation`, `narrow` or `escalation` naming it or any act
on its chain.

#### 5.3. The result

The answer is one of: **valid**, with the effective expiry, the
`assurance`, the chain start's `key`, and for a certifying act or `grant`
its effective rights (for a `grant`, with its `object`) and its layers
(§4.9: the `profile` edge and body of every act on the chain, for a
software `grant` also of the grants its issuer holds over the object, and
of every applied `escalation` and `narrow`, as given, in the order §4.9
states, each marked stencil or patch); **invalid**,
with the step of §5.2 that failed and the act digest; **undetermined**,
when an act in `names` or `issuer-record` could not be resolved or no
revocation source was reachable. A consumer MUST NOT treat undetermined
as valid. `records` entries and the layers are returned as given and are
the consumer's to check and to enforce.

#### 5.4. The reference verifier

piggy provides the verifier and the canonicalization of §3.1 as a library
and a CLI verb (working name `piggy act verify`), with a pluggable store
interface, so every consumer runs the same rules. Consumers MAY implement
their own against the vectors of Conformance Testing.

### 6. Display

For a card act the canonical form is the text RFC 0012 §2.5 and §2.6
govern: the agent MUST show it verbatim and in full, every head line, with
the class banner, card and slot, and namespace RFC 0012 §2.6 requires (R:
"since metadata IS the prompt, show it"). As RFC 0012 §2.6 allows, the
askpass MAY wrap long lines and MAY emphasize spans (`kind`, `subject`,
`right`, `not-after`, the body); it MUST NOT omit, truncate or reorder
lines. A software act has no display.

### 7. Producers

A producer is any program that builds a canonical act, obtains its
signature and adds the seal. Before requesting a signature a producer
MUST run §5.2 steps 1 and 3 on the unsealed act (the field rules, the
namespace and kind table, `issuer-key = key`, a `narrow`'s
`issuer = subject`) and, for a card act, MUST confirm the agent serves the
key the act names before any PIN prompt, so an operator is never asked to
sign an act every verifier would refuse; after signing it MUST normalize
the signature (§3.3 Low-S) and verify the seal before writing it. The
reference producer is `piggy act seal`. A producer names itself in `producer` with an
identifier in its own domain (`barker:act-v1`, `piggy:operator-sign-v1`),
which is inside the signed bytes. piggy keeps no registry of producers
(R): a domain registers its own names for itself, and a producer's acts
carry authority because the key that signed them is bound by a valid
chain, never because of the name. A verifier MAY apply its own policy to
`producer` (accept only names it knows) and MUST NOT grant anything on its
strength.

### 8. Purposes

Two markl purposes are registered in RFC 0011 §6.1's sense, owned by
piggy, to be added to RFC 0011's table and to `crates/piggy-markl` with
the reference verifier:

| Purpose | Owner | Compatible formats | Description |
|---|---|---|---|
| `piggy-principal_pub-v1` | piggy | `ssh_ed25519_pub`, `ssh_ecdsa_nistp256_pub` | the public key of a principal certified by a `piggy-act-v1` certifying act |

`piggy-record-digest-v1` and `piggy-record-sig-v1` (RFC 0012 §4) are
reused unchanged: the first names an act (§3.5), the second its raw
signature (§3.3).

### 9. Examples

Spelling note: the two card examples are the canonical form (§3.1), which
is what the operator saw; their producers add the `signature` line after
`hash` afterwards. The software example is shown sealed (§3.5), with its
`signature` line.

A card root for a human-started session, blessed at session start; its
`records` line is the enrollment request it answers. The operator saw
exactly these lines under the `certificate` banner, entered the PIN,
touched:

    ---
    # root: operator blesses session 72dca00c
    - kind = root
    - producer = troupe:root-v1
    - subject = clown:72dca00c-1c93-41d1-a2ad-9e530b9e30ee
    - subject-key = piggy-principal_pub-v1@ssh_ed25519_pub-…
    - issuer = operator
    - issuer-key = piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…
    - right = spinclass:check
    - right = spinclass:close
    - right = spinclass:grant
    - right = spinclass:merge
    - right = spinclass:observe
    - right = spinclass:profile:dev
    - records = piggy-record-digest-v1@blake2b256-…
    - not-after = 2026-11-09T23:00:00Z
    - issued-at = 2026-11-08T23:00:00Z
    - assurance = piggy:hardware
    - key = piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…
    - namespace = piggy-certificate-v1
    - hash = sha256
    ! piggy-act-v1
    ---

A narrowing the session performs on itself, no prompt (a software act;
`names` is the root above):

    ---
    # narrow: drop merge for the rest of the day
    - kind = narrow
    - producer = spinclass:narrow-v1
    - subject = clown:72dca00c-1c93-41d1-a2ad-9e530b9e30ee
    - issuer = clown:72dca00c-1c93-41d1-a2ad-9e530b9e30ee
    - issuer-key = piggy-principal_pub-v1@ssh_ed25519_pub-…
    - issuer-record = piggy-record-digest-v1@blake2b256-…
    - right = spinclass:check
    - right = spinclass:close
    - right = spinclass:grant
    - right = spinclass:observe
    - right = spinclass:profile:dev
    - names = piggy-record-digest-v1@blake2b256-…
    - issued-at = 2026-11-08T23:30:00Z
    - assurance = piggy:software
    - key = piggy-principal_pub-v1@ssh_ed25519_pub-…
    - namespace = piggy-record-v1
    - hash = sha256
    - signature = piggy-record-sig-v1@ed25519_sig-…
    ! piggy-act-v1
    ---

An escalation answering a request record, at the card; `names` holds the
worker's `link` (whose rights it replaces) and `records` the request:

    ---
    # escalation: merge for worker 138b6dd2, one run
    - kind = escalation
    - producer = troupe:escalation-v1
    - subject = clown:138b6dd2-5023-4957-b7c2-05e8dc8ee6e5
    - issuer = operator
    - issuer-key = piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…
    - right = spinclass:close
    - right = spinclass:merge
    - right = spinclass:observe
    - names = piggy-record-digest-v1@blake2b256-…
    - records = piggy-record-digest-v1@blake2b256-…
    - not-after = 2026-11-09T01:00:00Z
    - issued-at = 2026-11-08T23:40:00Z
    - assurance = piggy:hardware
    - key = piggy-piv_sig-v1@ssh_ecdsa_nistp256_pub-…
    - namespace = piggy-escalation-v1
    - hash = sha256
    ! piggy-act-v1
    ---

A software `link` under Shape E: the head pins the child's capability
profile by digest and the body adds one layer, a `deny` on a path (its
node types are the consumer's; shown sealed):

    ---
    # link: manager hands the reviewer a read-only tree
    - kind = link
    - producer = spinclass:link-v1
    - subject = clown:a1b2c3d4-…
    - subject-key = piggy-principal_pub-v1@ssh_ed25519_pub-…
    - issuer = clown:72dca00c-1c93-41d1-a2ad-9e530b9e30ee
    - issuer-key = piggy-principal_pub-v1@ssh_ed25519_pub-…
    - issuer-record = piggy-record-digest-v1@blake2b256-…
    - profile = engineer-reviewer@blake2b256-…
    - right = just-us:run:group:test
    - right = moxy:kind:read
    - not-after = 2026-11-10T06:00:00Z
    - issued-at = 2026-11-09T22:15:00Z
    - assurance = piggy:software
    - key = piggy-principal_pub-v1@ssh_ed25519_pub-…
    - namespace = piggy-record-v1
    - hash = sha256
    - signature = piggy-record-sig-v1@ed25519_sig-…
    ! piggy-act-v1
    ---

    [moxy !clown-plugin-v1
      [-> folio !mcp-server-v1
        [-> read !mcp-tool-v1
          [-> file:circus/.worktrees/_/infra/secrets !fs-path-v1 subtree deny]]]]

(`subtree deny`, not `deny` alone: under the fragment's matching rule a
node without `subtree` matches only its exact id, so a bare `deny` on the
folder would leave every file under it admitted by the parent's
allowance. Caught by cutting-garden's writing probe, 2026-11-09.)

Verifying a signature by hand on any host: rebuild the sshsig from the
seal, write the canonical form (the sealed act minus its `signature`
line) to a file, and

    ssh-keygen -Y verify -f allowed_signers -I operator \
      -n piggy-escalation-v1 -s act.sig < act.canonical

The chain walk (§5.2 steps 4 to 6) is the reference verifier's.

## Security Considerations

- **The words carry nothing.** Authorization comes from `kind`, the
  `right` set, the chain and the seal; a description, however persuasive,
  is ignored by §5, and a body is a layer that can only remove (§4.9). An
  attacker who gets the operator to sign a head obtains the power the head
  says, which is why the head is shown in full (§6) and why a right is a
  short opaque token the operator can read.
- **Layers cannot widen.** Under the stencil stack every layer must admit
  a call, so a body or profile written by a child, however it is written,
  removes and never adds; the containment comparison that a per-link
  check would need (and that is undecidable for some predicates) is
  never performed.
- **Canonicalization is in the trust path.** A divergence between
  producer and verifier makes a good act fail (safe). A verifier that
  accepted arrival bytes without recomputing could let two documents
  share a signature; §5.2 step 2 always recomputes from the parsed
  document.
- **Signature malleability would forge act names.** ECDSA accepts both
  `(r, s)` and `(r, n − s)`; since an act's name digests its signature,
  a second encoding is a second name for the same authority, which a
  revocation or narrow naming the first would miss. §3.3's low-S rule and
  Ed25519's canonical-S rule leave one encoding per sealed act. Found by
  the #358 implementation's review, 2026-11-09.
- **Namespace and kind are both inside the signed bytes**, and the
  namespace is bound a second time by `PROTOCOL.sshsig`. A signature for
  one kind cannot be replayed as another (§4.8).
- **The ordinary sign path can only narrow.** A software act is an
  ordinary sign request under `piggy-record-v1`, which RFC 0012 §2.7
  leaves unguarded by design; under §4.2 such an act can give away a
  subset of what its signer holds and nothing more, so a compromised
  principal cannot raise itself or its children.
- **Expiry rests on the chain start.** Verifiers' clocks decide validity;
  `issued-at` is a claim and is used by nothing. Every card certifying act
  carries a hard expiry; a long-lived software link is bounded by the card
  act above it.
- **Revocation reach.** A verifier that cannot reach a revocation source
  answers undetermined (§5.3); consumers that treat undetermined as valid
  defeat revocation, and §5.3 forbids it.
- **Prefixed fields are signed but ignored by the chain rules**, so a
  consumer field cannot widen rights by being misread, and it cannot be
  stripped without breaking the signature.
- **Prompt size.** A head too long for one screen invites skimming; §3.4
  and the Limitations bound it.

## Conformance Testing

Conformance tests for this specification live in
`zz-tests_bats/conformance/` and `docs/rfcs/0013-vectors.txt` (written
with the reference verifier). Tests use binary injection via `bats-emo`:

    require_bin PIGGY piggy
    require_bin FIBBY fibby

### Covered Requirements

| Requirement | Test File | Description |
|-------------|-----------|-------------|
| §1, §5.2 step 1, line and field rules | `act_refusals.bats` | a bare `-` line, an `@` line, a type-line lock, a duplicate `kind`, an unknown unprefixed field, a missing `issuer-key`, a card act with `issuer-record`, are refused |
| §2, set fields | `act_canonical.bats` | repeated `right` and `names` values arriving in any order and with duplicates canonicalize to one sorted set |
| §3.1, canonical form is order-, spacing- and comment-insensitive | `act_canonical.bats` | the same act in three line orders, unspaced, with comments, yields one canonical form and one digest |
| §3.2, §3.3, seal equivalence | `act_seal.bats` | a sealed act rebuilt as a detached sshsig verifies under `ssh-keygen -Y verify`, and vice versa; a blob whose namespace, key or hash differs from the field is refused, naming which; a high-S `ssh-keygen` signature is normalized to low-S before sealing (exercised on every ECDSA run). The `(r, n − s)` twin is pinned in Rust (`act::seal::tests::the_high_s_twin_of_a_p256_seal_is_refused`: the twin's digest differs, verify refuses it, attaching its blob normalizes back to the original act), since building `n − s` in bats would need a test-only verb |
| §3.4, size | `act_refusals.bats` | a canonical form over 4096 bytes is refused by the agent as `refused-text` |
| §3.5, act digest | `act_canonical.bats` | the digest covers the signature; re-signing yields a new digest |
| §4.1, §5.2 step 4, chain edge | `act_chain.bats` | a software act whose `issuer-record` names an act with another `subject-key` or `subject` is refused; a card act with a non-anchor key is refused |
| §4.2, rights never widen without the card | `act_chain.bats` | a software `link` with a right outside its issuer's certified rights is refused; a `link` wider only than its issuer's later self-narrow is valid with the intersection; a software `grant` is bounded by the issuer's certified rights plus its valid grants over the same `object`, and one that exceeds them is refused; a `narrow` signed by another key is refused |
| §4.3, effective rights | `act_chain.bats` | an `escalation` naming a `link` replaces its set; a `narrow` intersects it whatever the issue order; two unsuperseded escalations on one act make it invalid; an escalation naming the narrow lifts it |
| §4.1, §5.2 step 6, `names` and `records` | `act_chain.bats` | an escalation whose `names` entry is not an act, or has another subject, is refused; an unresolvable `names` entry answers undetermined; a `records` entry is never resolved |
| §4.5, effective expiry | `act_chain.bats` | a child whose root has expired is invalid; a child with no `not-after` inherits the root's |
| §4.6, revocation | `act_chain.bats` | an act below a revoked `link` is invalid; a software revocation by a key that is neither the signer nor an ancestor on the named act's chain is refused, and one by the parent's key is accepted; a revocation naming a revocation is refused |
| §4.7, §4.8, namespace, kind, issuer, assurance | `act_chain.bats` | an `escalation` under `piggy-record-v1`, a `narrow` under a card namespace, a `revocation` under `piggy-certificate-v1`, `piggy:hardware` on a software act, are refused (by `verify`, which applies the pairing; `canon` does not) |
| §5.3, undetermined | `act_chain.bats` | an unresolvable `issuer-record` and an unreachable revocation source answer undetermined, never valid |
| §6, the prompt shows the whole head | `operator_act_prompt.bats` | the test askpass receives every head line verbatim in canonical order |
| §4.9, the body is signed verbatim and returned opaque | `act_body.bats` | an act with a body verifies; one byte changed in the body fails; the verdict returns the `profile` edge and body bytes unchanged; a body with a C0 control character is refused |
| §4.9, an escalation replaces only the layer kinds it carries | `act_chain.bats` | an escalation with a `profile` and no body leaves the named act's body in the layers; one with a body replaces it; one with a body of no leaves clears it |

## Compatibility

- **RFC 0012** stays the wire RFC for card acts: the extension, status
  codes, display rules and namespace registry are unchanged. These parts
  of its text are amended when this RFC is accepted:
  - §3's per-namespace text shapes for `piggy-certificate-v1`,
    `piggy-escalation-v1` and `piggy-approval-v1` become "the text is a
    `piggy-act-v1` document (RFC 0013) whose `kind` RFC 0013 §4.8 allows";
    the `piggy-quote-v1` row is unchanged.
  - §3's `piggy-record-v1` row, "the message is the record's canonical
    bytes as troupe's RFC defines them", gains: "or a `piggy-act-v1`
    software act (RFC 0013)".
  - §3.1 (the kinds an escalation names) is read through §4.1 here: a
    grant or widening is an `escalation` naming the act it replaces; a
    profile transition, which confers no right, is an `approval` naming
    the transition record.
  - §1 Scope's "the signed-record grammar and canonicalization" stays out
    of RFC 0012's scope; this RFC defines the grammar for acts only.
  - §4's note that the carrier of a record's signature is the consumer's
    decision stands for records that are not acts.
  - Already made, 2026-11-10 (the fourth amendment): §2.6 and §3 gain a
    fifth display class, `revocation`, with the namespace
    `piggy-revocation-v1`, which §4.8 here requires of a card `revocation`;
    the agent, the askpass dialogs and the conformance rows follow as
    piggy#377.
- **RFC 0011** gains the purpose of §8 by amendment to its §6.1.
- **RFC 0008 (pigpen)** carries its header MAC in the type-line lock, which
  the operator's ruling disallows for signatures. A MAC is not a
  signature and this RFC does not amend RFC 0008; whether pigpen should
  move its MAC to a field, and whether a pigpen document may carry an act's
  signature over its sealed header, is an open question for the operator.
  Until ruled, a sealed record that must be acted on is named from an act
  by digest, not signed in place.
- **Consumers' existing records.** A consumer whose records are not
  hyphence documents keeps them and names them from acts by digest.
  Whether a consumer moves its own records onto `piggy-act-v1` is its
  decision.
- **The 2026-11-09 amendment** adds the optional `profile` field and gives
  the body a meaning (§4.9) where it had none. No act with a body had been
  produced; `piggy-act-v1` is unchanged.
- **Version.** A change to the canonical form, the seal, the digest, or a
  non-additive change to the field set is `piggy-act-v2`; adding an
  optional unprefixed field is an amendment to §2.

## Limitations and deviations from the rulings

- **Nesting is by reference, and the body is the one tree.** The
  operator's comment asked for the head to carry the permission "through
  nested hyphence documents". A hyphence head cannot contain another
  document (a metadata line cannot contain a line feed, V hyphence RFC
  0001), so the head holds references by digest (`names`, `prev`,
  `object`, `profile`) that a verifier or enforcer resolves from the
  consumers' store, and the one tree an act carries inline is its espalier
  body (§4.9, R 2026-11-09).
- **The head is a set algebra; the conditions are stacked.** The head
  gives opaque rights, subset on the way down, replacement by escalation,
  intersection by narrowing, an `object` on grants. Everything finer is a
  layer (a pinned profile, a body) that the consumer's enforcer stacks
  (§4.9). piggy evaluates no condition. Ruled 2026-11-09, replacing the
  deviation this item recorded.
- **Head size and the derivable fields.** Six fields (`issuer`,
  `issuer-key`, `namespace`, `hash`, `assurance`, `issued-at`) can be
  derived from `kind`, `key` and the signature's format or are
  informational. Dropping them takes a card root from fifteen fixed lines
  to nine. Ruled 2026-11-09 (R): start with the full head as this table
  stands and judge the prompt live, then improve from what is observed;
  the consolidation (fold `hash` into the signature's markl format, derive
  `namespace`, `issuer` and the piggy `assurance` values from `kind` and
  `key`, drop `issuer-key` and `issued-at`) is the recorded fallback and a
  Tuning Lever below.
- **One prompt.** A card act's head must fit a prompt (4096 bytes hard,
  about fifteen lines comfortable). A large right set is the consumer's
  to compress (a profile right instead of a list).
- **piggy does not distribute.** Where acts, revocations and trust
  anchors are stored and found is the consumers'.
- **Who may revoke** (R 2026-11-10): the card, the key that signed the
  act, or any ancestor key on the act's chain (§4.6). The two software
  cases need no touch; the operator chose reach over ceremony because a
  revocation only removes. The draft had allowed the signer alone.
- **Banner for card revocations** (R 2026-11-10): a card `revocation` has
  its own class and namespace, `piggy-revocation-v1` (§4.8), so the prompt
  says that something is being cancelled; RFC 0012's fourth amendment
  registers it and the agent, the askpass dialogs and the conformance rows
  follow as piggy#377. The draft had signed it under
  `piggy-certificate-v1`.
- **A narrow outlives a later escalation unless named** (R 2026-11-10):
  kept as §4.3 step 4 states it; the card always wins but has to say
  which promise it lifts. The operator expects toil at escalation
  boundaries (naming narrows at every escalation, or children re-narrowing
  after each one) and asked that it be watched: a Tuning Lever below.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| chain depth cap | 32 | a stack never needs more; bounds a verifier's work | a legitimate tree exceeds it |
| card-act head size | 4096 bytes hard (RFC 0012); about 1200 characters recommended | one screen, no scrolling | operators report skimming, or producers hit the cap |
| derivable head fields written out | all six present (`issuer`, `issuer-key`, `namespace`, `hash`, `assurance`, `issued-at`) | the operator sees the whole signed text and nothing is derived behind the prompt; judged live first (R 2026-11-09) | the operator reports skimming or crowding at the prompt; then drop them per Limitations |
| time precision | seconds, UTC | enough for expiry; no sub-second clocks across hosts | a consumer needs finer |
| memoization | until effective expiry or an annotating act on the chain is learned | verifiers are called often | a revocation is observed to be missed |
| a narrow is lifted only by an escalation that names it | §4.3 step 4 as written (R 2026-11-10) | the card always wins, but says at the prompt which promise it lifts | toil at escalation boundaries: the operator naming narrows at every escalation, or children re-narrowing after each one; the operator expects this and asked that it be watched |
| digest format emitted | `blake2b256` | matches the record purposes' existing use | a consumer needs sha256 only |

## References

### Normative

- OpenSSH `PROTOCOL.sshsig` §2 and §3 — the sshsig blob and signed data.
- RFC 4253 §6.6 — SSH public key blob encoding.
- piggy RFC 0012 — the `operator-act@piggy` extension, display rules, the
  namespace registry (§3), the record purposes (§4), the attestation
  bundle (§5).
- piggy RFC 0011 — markl-id format and the purpose and format registries;
  §2.2 for embedding a purposed id in a host grammar.
- hyphence RFC 0001 (the document), RFC 0002 (content grammar), RFC 0003
  (markl atomic locks), RFC 0005 (canonical emission: spacing, quoting,
  bareness, prefix order; the typed head model) and `hyphence-content.peg`
  — the carrier and its canonical emission. All are `proposed` at the time
  of writing; RFC 0005 landed with hyphence master `7438bdf8` on
  2026-11-09.
- cutting-garden RFC 0014 (trellis) and `0014-trellis.peg`, with
  cutting-garden FDR 0028 (ajour) defining the stencil fragment — the
  body's grammar (§4.9). Both `proposed` or in draft at the time of
  writing. piggy's verifier never parses a body; the citation binds body
  producers and enforcers.
- RFC 2119 — requirement keywords. RFC 3339 — timestamps.

### Informative

- piggy FDR 0007, decision 5 (the rulings this RFC implements); piggy FDR
  0006 (the holder behind software keys).
- piggy RFC 0008 — pigpen, for the MAC-in-lock construction this RFC does
  not follow.
- The needs of the first consumers (spinclass's principal, handle and
  profile records; barker's acts from the phone; circus EPIC 0001's
  capability profiles and its "narrowing is stacking" decision, which §4.9
  adopts) informed the field set and the chain rules; piggy is upstream of
  them and does not cite them normatively.
- `piggy-acts(7)`, the plain-words explanation of the chain and the
  stencil stack.
