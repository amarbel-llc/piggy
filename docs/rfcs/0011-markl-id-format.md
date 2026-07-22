---
status: proposed
date: 2026-05-10
authors: Sasha F (with Clown), drafted from amarbel-llc/madder#150
revisions:
  - 2026-05-09: initial draft (amarbel-llc/madder#150)
  - 2026-05-10: revert combined-HRP checksum rule to split-HRP form (amarbel-llc/madder#159)
  - 2026-06-09: add ssh_ecdsa_nistp256_pub format (§5) and piggy-piv_*/piggy-recipient-v1 purposes (§6.1), promoted to the normative cross-language subset
  - 2026-07-18: expand the purpose grammar from the `system-domain-role-version` registry convention to general identifiers (§2.1, §6); add the embedding-grammar quoting-split section (§2.2) (linenisgreat/madder#270)
  - 2026-07-20: move from madder RFC 0002 to piggy RFC 0011, completing the piggy#183 markl-ownership inversion; narrow the purpose charset from the 2026-07-18 open-Unicode form to a bare-ident-plus-quoted-String model, restrict blech32 to a single separator and lower-case only, define blech32 by reference to bech32, make checksum verification normative for decoders, mark the legacy combined-HRP form historical (§9.1), and add the identifier conformance-vector corpus and divergence register (§7.3, §7.4) (linenisgreat/madder#273)
---

# RFC 0011 — Markl ID Format

## Status

Proposed. Will move to `accepted` upon merge of this RFC.

**This document was formerly madder RFC 0002
(`docs/rfcs/0002-markl-id-format.md` in the madder repository).** It was
moved into piggy on 2026-07-20 to complete the piggy#183 markl-ownership
inversion: piggy owns the markl-id registry and codec, so piggy owns the
markl-id specification. Cross-repo references to "madder RFC 0002" for
the markl-id format now resolve here, to piggy RFC 0011. The number
changed because piggy's RFC 0002 slot is already occupied by
`docs/rfcs/0002-piv-ecdh-box.md`; internal section numbers (§2, §2.1,
§3, …) are unchanged from the madder original, so existing
section-granular citations remain accurate.

Madder's copy MUST be removed or replaced with a redirect stub pointing
here. That is a downstream change in the madder repository; piggy cannot
make it. Until that pass lands, the madder copy is stale and this
document is authoritative.

This RFC pins the wire format the Go reference implementation already
produces and consumes, plus the 2026-07-20 narrowing amendments recorded
at [linenisgreat/madder#273](https://code.linenisgreat.com/linenisgreat/madder/issues/273).
No on-disk bytes change for data written in the currently shipping form;
§9.1 records the one accepted regression. The reference implementation
lives in this repository's `go/` module
(`code.linenisgreat.com/piggy/go`), alongside piggy's Rust
`piggy-markl` crate. A normative spec plus portable test vectors are the
precondition for cross-language compatibility without silent drift.
Repository-relative paths below are this repository's unless qualified
as madder's, dodder's, or another repository's.

## Abstract

A markl ID is a self-describing, checksummed, human-readable identifier
for binary data in the dodder/madder/piggy ecosystem. It encodes
cryptographic digests, signatures, and keys using *blech32*, a modified
bech32 encoding. This RFC specifies the wire format normatively,
registers the canonical format-ID and purpose-ID values, and pins test
vectors so independent implementations can verify byte-exact
compatibility.

The markl-id text form is a **human-readable, self-describing typed
payload — deliberately broader than multihash**. Multihash is hash-only
and binary; markl format-ids span hashes (`blake2b256`), signatures
(`ecdsa_p256_sig`), and public keys (`pivy_ecdh_p256_pub`,
`ssh_ecdsa_nistp256_pub`) in a form a human can read aloud, paste into a
commit message, and eyeball for transcription errors. The closest
comparison in the wider ecosystem is a human-readable
multiformat/multicodec, not a multihash.

## Notational Conventions

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
**MAY** in this document are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) when, and only when,
they appear in all capitals.

References of the form *(test: TestX in path/to/file.go)* point to the
Go reference implementation's executing test that pins the claim. Every
normative requirement in this RFC has such a reference, except where a
2026-07-20 amendment (see the revision history) has outrun its test — in
those places the reference is marked *pending*, and no test name is
invented.

## 1. Motivation

Markl IDs are used as content-addressable blob digests in object
metadata, as signatures in inventory lists, as type locks in hyphence
documents, and as repository public keys. The Go reference
implementation (`go/internal/bravo/markl/`) is the de-facto behaviour;
this RFC formalises it.

The design goal that shapes every ruling below is **legibility under a
typed payload**. A markl ID must survive being read by a human — in a
terminal, in a diff, in an issue comment — and still be
machine-decodable back to `(purpose, format, bytes)` with a
transcription-error check. That is why the format identifier is spelled
out in full rather than encoded as a varint (as multicodec does), why
the charset excludes visually ambiguous characters, why the separator
was changed from bech32's `1` (§3.2), and why the 2026-07-20 amendment
narrowed the charset rules rather than widening them: every rune that
can appear in a markl ID is a rune a reader has to disambiguate.

### 1.1. Terminology: markl-id vs `piggy-ids`

Three near-identical names denote three different things, pinned here
once (piggy#234; the markl-id → piggy-id rename that would have made
this worse was closed won't-do as piggy#184):

- **markl-id** — the ID *type* this RFC specifies: `[purpose@]format-data`.
- **`piggy-ids` file** — a store's recipients file (RFC 0003). The
  relationship is containment: a `piggy-ids` file is a file *of*
  markl-ids, one per line per RFC 0003's line grammar, including its
  non-encryption 9A SSH-auth line type.
- **`piggy-ids` crate/binary** — the helper that reads and writes those
  files. It is named after the *file* it manages, not the ID type.

The `markl` name is permanent ecosystem vocabulary: it is deliberately
neutral (these IDs are dodder's digests, madder's blob URIs, and
trellis's terms, not piggy-branded values), collision-free, and greps to
exactly one concept in every consuming repository.

## 2. Structure

A markl ID has the text form:

    [purpose@]format-data

The three parts are:

- **purpose** (OPTIONAL) — a semantic-context label. When present it
  MUST be followed by a literal `@` separator. Its grammar admits two
  overlapping classes — **registered** purposes, validated against the
  format-compatibility registry, and **general** purposes, opaque
  identifiers resolved by the consumer's own type system — given in
  §6. Its charset is given in §2.1. §2.2 covers how a markl ID, and its
  purpose slot specifically, embeds into larger textual grammars.
- **format** — the format identifier (e.g. `sha256`,
  `pivy_ecdh_p256_pub`). It is *structurally* open (§2.1) and
  *semantically* closed: it MUST resolve, at decode time, to one of the
  registered format IDs in §5, or to a registered purpose-id alias
  resolving to one (§6.4).
- **data** — the blech32-encoded binary payload, including its
  6-character blech32 checksum (§3).

The blech32 separator (literal `-`) sits between `format` and `data`,
and is the ONLY `-` in the blech32 body (§3.2). The checksum is computed
over `format` only. The purpose, when present, is textual decoration
prepended to the blech32 string after encoding — it is **not** part of
the checksum input. Encoding the same `(format, data)` under two
different purposes therefore produces identical blech32 bodies,
differing only in their `<purpose>@` prefixes.

The digest slot retains this two-part `format "-" data` structure by
deliberate ruling: a proposal to replace it with a single generic bare
token was rejected. The structure is the only thing that rejects
`blake2b256` (a format with no data), `blake2b256-9bt3…` (`b` is
outside the blech32 alphabet), and truncated payloads. A generic token
would accept all three and defer every one of those failures to a
semantic layer that may not run.

A markl ID with empty `data` and unset `format` is the *null* state;
its canonical text form is the empty string. Implementations MUST NOT
produce a markl ID whose `data` portion is non-empty without an
accompanying format. *(test:
`TestInvariant_ZeroValueIdIsNullState`,
`TestIdNullAndEqual` in `go/internal/bravo/markl/`.)*

### 2.1. ABNF Grammar

```abnf
markl-id      = [ purpose "@" ] format-data
purpose       = ident / quoted-string          ; see §6, §2.2
format-data   = bare-digest / quoted-string    ; quoted form: see §2.3
bare-digest   = format "-" data
ident         = 1*ident-char
ident-char    = ALPHA / DIGIT / "-" / "_" / "/"
format        = 1*( ALPHA / DIGIT / "_" )      ; HRP component; see §5
data          = 7*charset-char                 ; >= 7: 1+ payload + 6 checksum
charset-char  = "q" / "p" / "z" / "r" / "y" / "9" / "x" / "8" / "g" / "f" /
                "2" / "t" / "v" / "d" / "w" / "0" / "s" / "3" / "j" / "n" /
                "5" / "4" / "k" / "h" / "c" / "e" / "6" / "m" / "u" / "a" /
                "7" / "l"
               ; charset string "qpzry9x8gf2tvdw0s3jn54khce6mua7l" — see §3
quoted-string = DQUOTE *( qchar / escape ) DQUOTE
qchar         = %x20-21 / %x23-5B / %x5D-10FFFF ; any rune but " and \
escape        = "\" ( DQUOTE / "\" / "n" / "r" / "t" )
```

Unlike the pre-2026-07-20 form, the `data` charset is **lower-case
only** (§3.5). Uppercase forms are no longer legal anywhere in a markl
ID.

**Purpose charset (2026-07-20 amendment).** The bare purpose is the
trellis `Ident` model: alphanumerics plus `-`, `_`, and `/`, excluding
reserved runes. Anything outside that set — a space, a rune an
embedding grammar reserves, a non-ASCII code point — is reached through
the **quoted `String`** escape hatch, with escaping inside the quotes.

This **SUPERSEDES** the purpose-charset expansion landed on 2026-07-18
by linenisgreat/madder#270 and linenisgreat/piggy#219, which read "any
Unicode code point except `@` and whitespace" and framed an *open*
charset as forced rather than stylistic. That framing rested on a real
requirement — a purpose is the spelling of a pinned reference's
*target*, so a Unicode-named object must remain pinnable, and an
ASCII-only purpose charset would make it unpinnable. **That requirement
is preserved; only its mechanism changes.** The Unicode superset is now
served by the quoted-`String` escape hatch, which can carry any rune
sequence at all, rather than by leaving the bare charset open. The
result is strictly more expressive at the extremes (a purpose
containing a space, or a rune the bare grammar excludes, now has a
representation where before it had none) and strictly more legible in
the common case (an unquoted purpose is a small, closed, eyeballable
rune set rather than "everything except two things").

`/` remains explicitly legal unquoted, so object-id-shaped purposes such
as `one/uno` need no quoting. `-` remains legal in a purpose (the
registered purposes of §6.1 are full of it); it is unambiguous because
the purpose is delimited by `@`, not by `-`, and because the blech32
body that follows contains exactly one `-` (§3.2).

A purpose MUST NOT contain the literal `@` code point in its **bare**
form — `@` is outside `ident-char`, and it is markl's own purpose/digest
join. A **quoted** purpose MAY contain it; see §2.2.

*(test: pending. The purpose-charset narrowing is specified here ahead
of its conformance corpus; §7.3 defines the corpus that will pin it. The
pre-amendment claim was pinned by the `InvalidPurposeCharset` invalid
vector in `go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json`,
which remains valid but no longer covers the full rule.)*

**Sync obligation.** `go/internal/bravo/markl/marklid.peg` is the
executable structural grammar for this section and carries a sync
obligation to it. As of this amendment that file still encodes the
superseded open-Unicode `PurposeChar <- !'@' !Space .` rule and the
either-case `DataChar` class; bringing it into line with the ABNF above
is part of implementing this amendment. The PEG's stated scope limit
still holds and is now normative in the other direction too: see §4.1.

### 2.2. Embedding and the Quoting Split

A markl ID's own text form (§2, §2.1) is bare apart from the quoting
mechanism §2.1 defines for its two slots, and it MUST NOT contain
unquoted whitespace.

Larger textual grammars that embed a markl ID as a lexeme — trellis
(cutting-garden `docs/rfcs/0014-trellis.peg`'s `MarklTerm` production,
`MarklTerm <- (String / Ident) '@' Ident`: a dedicated two-slot
production, not an identifier-interior `@`) and hyphence (its RFC 0002
content grammar, and RFC 0003's lock-supersession, madder's
`docs/rfcs/0003-markl-atomic-locks.md` in the hyphence repository)
among them — MAY need to represent a purpose containing runes their own
grammar reserves (a space, or a rune in that grammar's own `Reserved`
set). When they do, the embedding grammar MUST quote **the purpose slot
only**:

    "my thing"@blake2b256-...

never the markl ID as a whole. Trellis's `MarklTerm` agrees with this
split by construction, not by convention: its purpose slot is
`(String / Ident)` — a bare `Ident`, or, when reserved runes require
it, a quoted `String` — joined by a literal `@` to a digest `Ident`
that is never itself an alternative inside `String`. §2.1's purpose
production is the same shape, imported (§7.4 records why that import is
of the *shape* and not of the rune classes).

The digest slot (`format-data`) MUST remain outside any *embedding
grammar's* quoting — unquoted and structurally intact — so tooling that
operates on the digest independently of the purpose (prefix elision,
trie-abbreviation, diffing, the mother→child digest-extraction paths of
§9) can locate it without first parsing or undoing the embedding
grammar's quoting. §2.3's markl-level quoted digest form is a distinct
thing: an extension point in markl's own grammar, not a licence for an
embedding grammar to wrap the digest.

Where an embedding grammar defines its own quoting mechanism — which
runes trigger it, what escape sequences it supports — that mechanism is
defined by the embedding grammar, not by this RFC; markl only requires
that whatever mechanism is chosen quotes the purpose slot in isolation,
leaving the digest slot bare.

A **bare** purpose MUST NOT contain the literal `@` character: it is
outside §2.1's `ident-char` set, and it is markl's own purpose/digest
join, so the first `@` in an unquoted slot ends the slot rather than
becoming content.

A **quoted** purpose MAY contain `@`, and `"a@b"@blake2b256-…` is a
well-formed markl ID whose purpose is the three-character value `a@b`.
Decoders MUST therefore locate the join with a **quote-aware scan** —
when the slot opens with a quote rune, find its matching close honouring
escapes, and expect the join immediately after — and MUST NOT split on
the first `@`. In the example above the join is the *second* `@`. This
is the most likely point of divergence for an independent
implementation, so §7.3's corpus pins every spelling of it.

This **supersedes** the pre-2026-07-21 rule, which banned `@` in a
purpose "under any circumstance, quoted or not" on the grounds that
admitting it would reintroduce the ambiguity the first-`@` decode rule
exists to avoid. That reasoning does not survive §2.1's narrowing. Two
things changed. First, the bare charset became an *inclusion* set, so
`@` is already impossible unquoted by construction — leaving the ban's
only remaining effect to forbid the quoted spelling, which is precisely
the spelling that *resolves* the ambiguity rather than creating it.
Second, the old rule also cited the split-HRP checksum rule (§3.3);
that citation was simply wrong. §3.3 makes the HRP the format alone and
excludes the purpose from the checksum entirely, so whether a purpose
contains `@` cannot affect it. The ambiguity §3.3 guards against is
combined `<purpose>@<format>` HRPs (§9.1), a different concern.

The deeper reason is consistency with §2.1's own bargain. Ruling 1
narrowed the bare charset and ruling 2 added quoting *so that nothing
lost expressiveness* — that is the trade that answers madder#270's
pinnability requirement. Quoting is an escape mechanism; an escape
mechanism that cannot carry the one character most in need of escaping
is not discharging that bargain. An embedding grammar whose identifiers
can contain `@` — trellis's can, via its own `String` production — must
be able to pin such an object, and now can.

*(Ruled 2026-07-18: linenisgreat/hyphence#6, linenisgreat/piggy#219,
cutting-garden `docs/rfcs/0014-trellis.peg` `MarklTerm` production.
Amended 2026-07-20: linenisgreat/madder#273. Amended 2026-07-21:
linenisgreat/piggy#227, resolving this section's disagreement with
`0014-trellis.peg`'s `MarklTerm` comment in trellis's favour — the two
specs now agree.)*

### 2.3. Quoting on the Digest Slot

Quoting is permitted on **both** slots — purpose and format-data — for
future flexibility. §2.1's `format-data` production therefore admits a
`quoted-string` alternative alongside `bare-digest`.

A quoted format-data slot **parses** into a dedicated value and is
**REFUSED at validation**. Decoders MUST parse it (so the shape is
reserved and a future concrete form does not require a grammar change
that breaks existing parsers) and MUST reject it (so no unvalidated
payload form is usable today). Implementations MUST NOT assign it a
meaning until a concrete form is specified by amendment to this RFC.

The precedent is trellis's `~=` operator and its typed closure
`-[p]->>`: the shape parses, and validation says no. This preserves
§2.1's quoting symmetry without opening an unvalidated hole, and keeps
§2's structural guarantees intact for every digest form usable today —
every markl ID that validates still has the `format "-" data` structure
that rejects a missing payload, an out-of-alphabet rune, and a truncated
body.

*(test: pending.)*

## 3. Blech32 Encoding

**Blech32 is defined by reference to BIP173 bech32.** It is bech32 with
exactly two changes:

1. The separator between the HRP and the data portion is the ASCII
   hyphen `-` (0x2D) instead of `1`.
2. The HRP charset is restricted to `[a-zA-Z0-9_]`, narrower than
   bech32's printable-ASCII 33–126.

Everything else is bech32's and is incorporated by reference:
the 32-character data charset (§3.1), the checksum construction —
polymod over HRP-expand concatenated with the 5-bit data values, with
the bech32 (not bech32m) XOR target `1` (§3.3) — the generator
polynomial, and the 8-to-5-bit conversion with zero-padding (§3.4).
Blech32's length rule is bech32's rule minus the 90-character cap
(§3.6), and its case rule is a *narrowing* of bech32's (§3.5). The
subsections below restate these for readability; where a restatement
and BIP173 disagree, BIP173 governs except for the two changes above
and the two explicit divergences in §3.5 and §3.6.

The two changes are interlocking. The separator swap is motivated by
**readability**: with digit-bearing HRPs like `blake2b256`, a `1`
separator leaves a reader unable to see where the HRP ends —
`blake2b2561qqq…` has no visual join, and `sha2561qqq…` is worse. The
hyphen makes the join obvious at a glance, which is the whole point of a
human-readable typed payload (§1). Restricting the HRP charset to
`[a-zA-Z0-9_]` is what makes the hyphen unambiguous: because `-` cannot
occur inside an HRP, the separator is the single `-` in the body (§3.2),
and a reader (or a `strings.Split`) needs no backtracking to find it.

*(test: `TestBlech32` in `go/internal/alfa/blech32/main_test.go`, plus
`TestRFC0002VectorsRoundTrip` in
`go/internal/charlie/markl_registrations/`.)*

### 3.1. Charset

The 32-character charset is bech32's, unchanged:

    qpzry9x8gf2tvdw0s3jn54khce6mua7l

The alphabet excludes the visually ambiguous characters `1` (one),
`b` (bee), `i` (eye), and `o` (oh).

### 3.2. Separator

The separator is the ASCII hyphen `-`, and there is exactly one of them
in a blech32 body.

**This CHANGES the pre-2026-07-20 rule, which said implementations MUST
locate the separator as the *last* `-` in the string.** Decoders MUST
split the body on its single `-`, and MUST reject a body containing
more than one `-`.

The evidence for the narrowing: every format ID in the ecosystem uses
`_`, never `-`, as its intra-word separator. Across piggy (the sixteen
of §5 — the `ed25519_*` family, the `ecdsa_p256_*` family, the `ssh_*`
family, `pivy_ecdh_p256_pub`, `sha256`, `blake2b256`, and `nonce`, the
last three carrying no intra-word separator at all), madder
(`blake2b256`, `sha256`), and dodder (which defines no formats of its
own), not one
format ID contains a hyphen. §2.1's `format` production has never
admitted one. A blech32 body in the currently shipping form therefore
contains exactly one `-`, always, and the last-`-` rule was scanning
for an ambiguity that cannot arise.

Correspondingly, `validateHRP` narrows from bech32's printable-ASCII
33–126 range to `[a-zA-Z0-9_]`. An HRP containing `-` is now invalid
rather than merely unusual.

The accepted risk of this narrowing, and the out-of-band repair path
for data that predates it, are recorded in §9.1.

### 3.3. Checksum

The checksum is a 6-character BCH code over the HRP-expansion
concatenated with the 5-bit data values. The generator polynomial is
bech32's:

    [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

The polymod XOR target is `1` (bech32's, not bech32m's `0x2bc830a3`).
The HRP expansion is identical to BIP173: each HRP byte contributes its
top-3 bits, then a single zero byte, then each HRP byte's low-5 bits.

For purpose-bearing markl IDs the HRP MUST be just `<format>` — the
purpose is **not** part of the HRP and does **not** contribute to the
checksum input. The purpose's role is identity decoration around the
digest, not part of the cryptographic content; binding the checksum to
the purpose would break legitimate digest-extraction paths (e.g.
mother→child signature lineage, audit references) that copy the same
digest bytes between purposes. *(test:
`TestRFC0002CrossPurposeBlech32Equal` in
`go/internal/charlie/markl_registrations/`.)*

**Decoders MUST verify the checksum.** This is normative and belongs to
the decoder, not to any grammar: see §4.1.

### 3.4. Bit Conversion

Encoding converts the binary payload from 8-bit groups to 5-bit groups,
left-padding the final group with zero bits. Decoding converts 5-bit
groups back to 8-bit groups; padding bytes MUST be zero, and any
non-zero padding or unconsumed bits MUST cause the decode to fail.

### 3.5. Case

**Markl IDs are lower-case only.** Any uppercase character anywhere in a
markl ID — purpose, format, or data — MUST cause the decode to fail.

**This CHANGES the pre-2026-07-20 rule**, which inherited bech32's
all-upper-or-all-lower uniform-case rule and treated the all-upper form
as equivalent to its lowercased counterpart. It is a deliberate
narrowing of bech32, and one of only two places (with §3.6) where
blech32 diverges from bech32 beyond the two changes in §3.

The rationale for bech32's uppercase allowance does not transfer.
BIP173 permits uppercase specifically so an address can be encoded in a
QR code's **alphanumeric mode**, which is denser than byte mode. But QR
alphanumeric mode's charset is `0-9`, `A-Z`, space, and `$%*+-./:` —
it contains no lowercase letters, no `@`, and no `_`. A markl ID's
format slot admits `_` (and the shipping registry is full of it), and a
purpose-bearing markl ID contains `@` by construction. So a markl ID can
**never** be QR-alphanumeric-encoded regardless of what case its payload
is in. The uppercase allowance buys markl IDs nothing at all; it only
buys them a second spelling of every identifier, which costs
canonicalisation logic at every comparison site.

Mixed-case strings remain rejected, now as a special case of the
lower-case-only rule rather than as a rule of their own.

The canonical form pinned by this RFC's vectors (§7) is, as before,
**lower-case**.

**Implementation precondition (checked 2026-07-20).** A survey of this
repository found the only uppercase markl ID present anywhere is inside
the `mixed_case` INVALID vector in
`go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json`
(`sha256-QQQSYQCYQ5RQ…`, expected error `MixedCase`). No valid fixture
vector and no persisted datum is uppercase, so this narrowing required
no data migration. The `mixed_case` vector's expectation — rejection —
is unchanged by the amendment; only its *reason* generalises.

*(test: `TestRFC0002InvalidVectorsRejected/mixed_case` in
`go/internal/charlie/markl_registrations/` — this test's assertion
remains correct under the amendment, but its name now understates the
rule it guards: an all-uppercase vector would also be rejected, and a
dedicated invalid vector for that case is pending.)*

### 3.6. Length

The 90-character total-length limit from BIP173 §5 is **not**
enforced. Implementations MUST accept arbitrary-length markl IDs
subject to the data-portion-minimum of 7 characters (1+ payload byte +
6 checksum bytes). *(test: long-vector cases in `TestBlech32`.)*

## 4. Decoding Algorithm

Given an input string `S`:

1. Locate the purpose/digest join in `S`, **quote-aware** (§2.2):

   a. If `S` begins with a quote rune (`"` or `'`), scan forward for the
      matching closing quote, honouring backslash escapes so an escaped
      quote does not terminate the slot. The join is the `@` immediately
      following that closing quote. If the slot does not close, or the
      character after it is not `@`, fail with `UnterminatedQuotedPurpose`.

   b. Otherwise the join is the *first* `@` in `S`.

   If a join was found, split into `purpose-slot` (before it) and `body`
   (after). Otherwise set `purpose-slot = ""` and `body = S`.

   Splitting on the first `@` unconditionally is **non-conformant**: a
   quoted purpose may contain `@` (§2.2), and `"a@b"@blake2b256-…` would
   be sliced in half, leaving a `body` that is not a decodable digest.

1b. Unquote `purpose-slot` into `purpose`. A slot that opens with a quote
   is unescaped per §2.1's `quoted-string`; a slot that does not MUST
   satisfy `ident-char`, failing with `InvalidPurposeCharset` otherwise.
   The unquoted `purpose` is subject to no further charset constraint.
2. Validate `body` contains no uppercase characters per §3.5. If it
   does, fail with `MixedCase` (retained as the error name for
   continuity; the condition it now covers is any uppercase, not only
   mixed case).
3. Locate the `-` in `body`. If absent, fail with `SeparatorMissing`.
   If the `-` is `body`'s **first** character, fail with `EmptyHrp` —
   the separator is present but the HRP is empty, a different
   malformation deserving a different name: a leading `-` means the
   format identifier was lost, and reporting it as a missing separator
   sends the reader hunting for the wrong defect. If `body` contains
   more than one `-`, fail with `SeparatorMissing` — the body is not a
   well-formed blech32 string (§3.2).

   (`EmptyHrp` was pinned as normative on 2026-07-22, piggy#228. The
   two reference decoders had diverged: Rust distinguished it — a
   distinction whose diagnostic value was established by a real
   piggy-ids typo incident — while Go folded it into
   `SeparatorMissing`. Go converged; folding the categories together
   destroys information, splitting them adds it.)
4. Split `body` into `hrp` (before the `-`) and `data` (after). The
   `hrp` is `formatId`; it MUST match `[a-zA-Z0-9_]+` (§3.2), which
   implies it contains neither `@` nor `-`.
5. Validate `len(data) >= 7`. If not, fail with `DataPortionTooShort`.
6. Validate every byte in `data` is in the charset of §3.1. If not,
   fail with `InvalidCharacter`.
7. Verify the blech32 checksum over (HRP-expand(hrp) || data-as-5-bit).
   If the polymod ≠ 1, fail with `InvalidChecksum`. The HRP here is
   `formatId` only; the purpose is **not** part of the checksum input.
   This step is MANDATORY (§3.3, §4.1).
8. Convert the first `len(data)-6` 5-bit values to 8-bit bytes per
   §3.4. Reject non-zero padding.
9. Resolve `formatId` against the format registry (§5), applying the
   purpose-id alias table (§6.4) if present. If unresolvable, fail
   with `UnknownFormat`.
10. If `purpose != ""` and `purpose` is present in the decoder's
    purpose registry (§6), validate `formatId` is among that purpose's
    compatible formats. If not, fail with
    `IncompatiblePurposeAndFormat`. If `purpose` is absent from the
    registry, accept the ID and carry the purpose opaquely (§6.6).
11. Validate `len(payload)` matches the resolved format's declared size
    (§5). If not, fail with `WrongSize`.

Step 3 changed on 2026-07-20 from "locate the *last* `-`" to the
single-separator rule; see §3.2 for the evidence and §9.1 for the
accepted risk.

The order of step 1 (`@`-split) before step 7 (checksum) is
deliberate: the checksum MUST be verified over the `formatId` substring
only, not over a combined `<purpose>@<format>` string. Binding the
checksum to the purpose would change a digest's encoded form when its
identity decoration changes, breaking digest-extraction and
mother→child signature paths. *(test:
`TestRFC0002InvalidVectorsRejected` covers each terminal failure
category; `TestRFC0002CrossPurposeBlech32Equal` covers the
purpose-independent checksum rule.)*

### 4.1. Division of Labour: Grammar vs Decoder

A structural grammar (`go/internal/bravo/markl/marklid.peg`, and any
port of it) owns **shape and charset**: the presence and position of
`@` and `-`, the rune classes of each slot, the minimum data length.
Everything in §4 that requires computation over the decoded bits or a
lookup in a mutable registry is the **decoder's** contract and is not
expressible in a PEG:

- **Checksum verification** (step 7). A PEG structurally CANNOT compute
  a BCH polymod. Its absence from the grammar is not a licence to skip
  it: decoders MUST verify it. A grammar-valid markl ID with a corrupt
  checksum MUST be rejected.
- **Payload size matches format** (step 11) — a registry lookup (§5).
- **Purpose/format compatibility** (step 10) — a registry lookup (§6.1).

A grammar-valid string can therefore still be semantically rejected
downstream. That is expected and matches trellis's own "groundness is
semantic, not grammar" precedent.

## 5. Format ID Registry

Format IDs are **structurally open and semantically registered**. Any
`[a-zA-Z0-9_]+` token parses as a format ID (§2.1); the registry
decides, at decode time, whether it is *valid*. This split is
deliberate: adding a format never touches the grammar, never invalidates
a downstream parser, and never forces a downstream re-import of a
grammar file. An unregistered format ID fails at step 9 with
`UnknownFormat`, not at parse time.

**A registered format ID implies its payload length.** Naming a format
is naming a known payload size; a payload of the wrong length is a
*semantic* error for the decoder (step 11, `WrongSize`), never a
structural one. Implementations MUST reject markl IDs whose decoded
payload does not equal the registered size for the named format. *(test:
`TestInvariant_SetMarklId_WrongSize_Errors`,
`TestInvariant_SetHexBytes_WrongSize_Errors` in
`go/internal/bravo/markl/`.)*

| Format ID            | Size (bytes) | Description                                  |
|----------------------|--------------|----------------------------------------------|
| `sha256`             | 32           | SHA-256 digest                               |
| `blake2b256`         | 32           | BLAKE2b-256 digest                           |
| `ed25519_pub`        | 32           | Ed25519 public key                           |
| `ed25519_sec`        | 64           | Ed25519 private key (RFC 8032 §5.1.5 form)   |
| `ed25519_sig`        | 64           | Ed25519 signature                            |
| `ed25519_ssh`        | 32           | Ed25519 public key surfaced via SSH agent    |
| `ecdsa_p256_pub`     | 33           | ECDSA P-256 compressed public key (SEC 1)    |
| `ecdsa_p256_sig`     | 64           | ECDSA P-256 signature (r ‖ s, fixed-width)   |
| `ecdsa_p256_ssh`     | 33           | ECDSA P-256 public key via SSH agent         |
| `age_x25519_pub`     | 32           | age X25519 public key                        |
| `age_x25519_sec`     | 32           | age X25519 secret key                        |
| `pivy_ecdh_p256_pub` | 33           | PIV ECDH P-256 compressed public key (SEC 1) |
| `ssh_ecdsa_nistp256_pub` | 33       | SSH-suitable ECDSA P-256 public key, SEC1-compressed |
| `ssh_ed25519_pub`    | 32           | SSH-suitable Ed25519 public key               |
| `ssh_ecdsa_nistp384_pub` | 49       | SSH-suitable ECDSA P-384 public key, SEC1-compressed |
| `nonce`              | 32           | Random nonce                                 |

The `*_ssh` formats carry a bare public-key payload (32 or 33 bytes);
the SSH-agent integration that produces signatures with these keys is
implementation-internal and not part of the wire format. Earlier
informal documentation described these formats as "variable size" —
that was incorrect, and is now excluded by construction: §5's
registry-implies-length rule leaves no room for a variable-size format.

`ssh_ecdsa_nistp256_pub` is byte-identical in shape to `ecdsa_p256_pub`
(both are 33-byte SEC1-compressed P-256 points). The distinct format ID
exists so a purpose (§6.1) can distinguish a PIV slot's SSH-suitable
authentication/signature key (`piggy-piv_*-v1`) from a repository or
recipient public key of the same shape, preventing the format-confusion
attack described in §8 item 3. This format is owned by this repository
and mirrored in its `piggy-markl` Rust crate.

### 5.1. Registering New Formats

A new format ID MUST be added to this RFC by amendment. The format ID
MUST conform to the lexical rule in §2.1 (`format`), MUST declare a
fixed payload size (§5), and MUST NOT collide with any prefix that would
change a previously valid markl ID's interpretation.

Because format IDs are structurally open (§5), such an amendment is a
registry change only: no grammar changes, and no downstream parser needs
to be re-generated or re-imported. Only decoders that need to *resolve*
the new format need updating.

## 6. Purpose ID Registry

A purpose is either **registered** — validated against a
(purpose, compatible-format) entry in this section, and named per the
`system-domain-role-version` convention (§6.2) — or **general**: an
opaque identifier from a consumer's own type system (a hyphence type
name, a zettel id, a typed-edge field name), unconstrained beyond
§2.1's wire-form charset and carried opaquely per §6.6. Both classes
share the same `purpose@format-data` text form and nothing in the wire
syntax distinguishes them; classification is entirely a registry
lookup at decode time (present → registered semantics apply; absent →
general/opaque). The purpose appears textually *before* the `@`
separator in a markl ID; it is **not** part of the blech32 HRP (§3.3)
and does not contribute to the checksum.

Purpose-full markl IDs are the canonical spelling for pinned/locked
references across the ecosystem: a type pinned to its definition
(`md@blake2b256-...`), an object pinned to a version
(`one/uno@blake2b256-...`), a typed edge pinned to a target
(`blocks=task/other@blake2b256-...`) — alongside the existing
registered-purpose uses (`piggy-piv_auth-v1@ssh_...`). This dual role
is what motivated the 2026-07-18 general-identifier expansion
(linenisgreat/hyphence#6, linenisgreat/piggy#219,
linenisgreat/madder#270): the purpose slot needed to carry not just
registry-scheme names but arbitrary consumer-side identifiers. The
2026-07-20 amendment (§2.1) preserves that capability while narrowing
the *bare* charset and routing the remainder through quoting.

### 6.1. Registered Purposes

Purpose IDs are **owned by the system named by their prefix**: piggy
owns the registration *mechanism* (§6.3) and the `piggy-*` namespace;
madder owns `madder-*`; every other purpose is owned by its consumer
system (`dodder-*` by dodder, `papi-*` by papi). The table below is the
consumer-owned registry snapshot mirrored by the Go reference
implementation; each row's semantics are authoritative in the owning
system's documentation.

This subsection pins the **stable cross-language subset** of purpose
IDs. Independent implementations MUST support these. IDs bearing any
other purpose MUST NOT be rejected merely for being unknown — they
decode opaquely per §6.6.

| Purpose                          | Owner  | Compatible Formats                              | Description              |
|----------------------------------|--------|-------------------------------------------------|--------------------------|
| `dodder-blob-digest-sha256-v1`   | dodder | `sha256`, `blake2b256`                          | Blob content hash        |
| `dodder-object-digest-v2`        | dodder | `sha256`, `blake2b256`                          | Object metadata hash     |
| `dodder-object-digest-v3`        | dodder | `sha256`, `blake2b256`                          | Object metadata hash (covers typed blob references) |
| `dodder-object-sig-v2`           | dodder | `ed25519_sig`, `ecdsa_p256_sig`                 | Object signature         |
| `dodder-object-sig-v3`           | dodder | `ed25519_sig`, `ecdsa_p256_sig`                 | Object signature (over the v3 digest) |
| `dodder-object-mother-sig-v3`    | dodder | `ed25519_sig`                                   | Object mother signature (v3 lineage) |
| `dodder-repo-public_key-v1`      | dodder | `ed25519_pub`, `ecdsa_p256_pub`                 | Repository public key    |
| `dodder-repo-private_key-v1`     | dodder | `ed25519_sec`, `ed25519_ssh`, `ecdsa_p256_ssh`  | Repository private key   |
| `piggy-piv_auth-v1`              | piggy  | `ssh_ecdsa_nistp256_pub`                        | PIV slot 9A public key (Authentication) |
| `piggy-piv_sig-v1`               | piggy  | `ssh_ecdsa_nistp256_pub`                        | PIV slot 9C public key (Digital Signature) |
| `piggy-piv_card_auth-v1`         | piggy  | `ssh_ecdsa_nistp256_pub`                        | PIV slot 9E public key (Card Authentication) |
| `piggy-recipient-v1`             | piggy  | `pivy_ecdh_p256_pub`, `age_x25519_pub`          | Encryption recipient (PIV slot 9D ECDH key, or age recipient) |
| `papi-doc-sig-v1`                | papi   | `ecdsa_p256_sig`                                | PAPI document signature (slot-9A SSH sig over JCS bytes) |

The `piggy-*` purposes are owned by this repository and mirrored in its
`piggy-markl` Rust crate
(`crates/piggy-markl/src/{format,purpose}.rs`). They are surfaced by
`piggy list` and consumed by madder wherever a piggy-issued key appears
in a markl-id slot.

The `papi-doc-sig-v1` purpose is owned jointly with
[`amarbel-llc/papi`](https://github.com/amarbel-llc/papi) and mirrored in
the `piggy-markl` Rust crate for the producer side. Its payload is the
64-byte `ecdsa_p256_sig` (r ‖ s, fixed-width) produced by a YubiKey PIV
slot-9A `ecdsa-sha2-nistp256` key signing a PAPI document's
canonicalized (JCS) bytes, with the SSH-wire signature framing stripped.
It spans only `ecdsa_p256_sig`: PAPI's slot-9A co-sign model is P-256
throughout, and widening a purpose's compatible-format set is a
backward-compatible amendment (existing IDs still validate), so the
registration starts narrow.

*(test: `TestRFC0002VectorsRoundTrip/purpose/...` in
`go/internal/charlie/markl_registrations/`, plus
`TestAllPurposes_Registered`,
`TestAllPurposes_RelatedRoundTrip` in madder's
`go/internal/charlie/markl_registrations/`.)*

The owning systems register additional purposes outside this table
(dodder: `dodder-object-{digest-sha256,sig,mother-sig}-v1`,
`dodder-object-metadata-digest-without_tai-v1`, `dodder-repo-sig-v1`,
`dodder-request_auth-{challenge,response,repo-sig}-v1`; madder:
`madder-public_key-v1`, `madder-private_key-{v0,v1}`,
`madder-blob_store-config-digest-v1`). These are **out of scope** for
this RFC: they remain valid wire-format markl IDs, but their
semantics are not pinned cross-language. Future RFCs MAY promote any
of them into §6.1.

### 6.2. Registering New Purposes

The rules in this subsection govern purposes seeking *registration*:
validation against a fixed list of compatible format IDs (plus §6.5
Related-role support). That validated compatible-format list is a
purpose's **format constraints** (linenisgreat/piggy#219's term for
§6/§6.1's compatible-format validation). It is a distinct thing from
rule 1's `system-domain-role-version` naming convention below: the
naming convention is a registration-time naming *policy*, not a format
constraint, and not a wire-level constraint on purposes in general
(§2.1). A general/unregistered purpose (§6, §6.6) need not conform to
rule 1's naming convention — its charset is governed only by §2.1.

A new purpose ID MUST be added by amendment. The purpose ID MUST:

1. Conform to `system-domain-role-version`, with `version` as `v`
   followed by one or more digits.
2. Enumerate its compatible format IDs.
3. Document the semantic role of the data so independent
   implementations can verify they're using the right key in the right
   context.

A registered purpose MUST be expressible as a bare `ident` (§2.1) —
i.e. it MUST NOT require quoting. Rule 1's naming convention already
guarantees this; the requirement is stated explicitly so that a future
relaxation of rule 1 does not accidentally admit a registered purpose
that only has a quoted spelling.

Implementations MUST reject markl IDs whose purpose is registered but
whose `formatId` is not among that purpose's compatible formats
(`IncompatiblePurposeAndFormat`). IDs bearing a purpose absent from
the registry MUST be accepted and carried opaquely (§6.6).

### 6.3. Per-Binary Registration

The framework code (`go/internal/bravo/markl/`) does not contain the
purpose registrations; each consumer installs its own on init. This
repository's module registers the formats and the `piggy-*` purposes
(`go/internal/charlie/markl_registrations/`); madder registers
the `madder-*` and (transitionally) `papi-doc-sig-v1` purposes plus
the legacy purpose-id aliases (madder's
`go/internal/charlie/markl_registrations/`); dodder registers the
`dodder-*` purposes in its own tree. Any consumer MAY register
additional purposes via `markl.RegisterPurpose` without forking the
framework. See madder's
`docs/decisions/0006-markl-registration-api-shape.md`. This property is
normative for the registration API, not the wire format — the wire
format only sees a flat map of purposeId → compatible formatIds at
decode time.

### 6.4. Purpose-ID Aliases

Pre-RFC dodder data wrote markl IDs whose HRP was a *purpose-id-shaped*
string (no `@` separator) — i.e. the purpose ID sat in the format-id
slot. The current parser resolves such an HRP through an **alias
table** that maps purposeId-shaped strings to canonical format IDs.

Implementations supporting legacy-data interop MUST honour this alias
table. Implementations targeting only forward-compatible data MAY omit
it, in which case those IDs decode as `UnknownFormat`. The currently
registered aliases are:

| Alias purposeId               | Resolved formatId   |
|-------------------------------|---------------------|
| `dodder-repo-private_key-v1`  | `ed25519_sec`       |
| `zit-repo-private_key-v1`     | `ed25519_sec`       |

Note that both alias keys contain `-` and therefore no longer satisfy
§3.2's HRP charset. An alias-bearing legacy ID is consequently reachable
only through the out-of-band path of §9.1, not through the normal decode
path. This is a direct consequence of the single-separator narrowing and
is part of its accepted risk.

**This repository registers no aliases and has no alias test.** The
alias table is installed by madder
(`go/internal/charlie/markl_registrations/`, per §6.3's per-binary
registration), so the `-`-bearing HRP decode path this subsection
describes does not exist in piggy's tree. That is why the §3.2 narrowing
landed here without breaking any test, and it is precisely why the
breakage surfaces DOWNSTREAM instead: when madder picks up the
single-separator split, `dodder-repo-private_key-v1-<data>` will split at
the first `-` and yield an HRP of `dodder` rather than resolving through
the alias table. Migrating those reads onto §9.1's out-of-band path is
downstream work that this document specifies but cannot perform.

*(test: `TestAllAliases_ResolveViaGetFormatOrError` in madder's
`go/internal/charlie/markl_registrations/` — predates the §3.2
narrowing; re-siting it onto the §9.1 path is pending in that
repository.)*

Note that the alias table and the §6.1 purpose registry are separate
namespaces that happen to share the `dodder-repo-private_key-v1`
identifier. New data MUST use the modern form
(`<purpose>@<format>-<data>`) where the format-id slot carries an
actual format ID.

### 6.5. Related Roles

Purposes MAY carry a free-form `Related` map of role-name →
purposeId-string pairs, used by signing and key-derivation paths to
walk between paired purposes (e.g. a sig purpose's `digest` role
points at the corresponding digest purpose). The role names used by
madder's own purposes are `digest`, `mother_sig`, and `public_key`.
Other consumers MAY define additional role names; markl itself stays
role-agnostic.

The `Related` map is part of the registration API, not the wire
format. *(test: `TestAllPurposes_RelatedRoundTrip`,
`TestPurposeRepoPrivateKeyV1_RelatedPublicKey` in madder's
`go/internal/charlie/markl_registrations/`.)*

### 6.6. Unknown Purposes

A decoder MUST accept a syntactically valid markl ID whose purpose is
absent from its registry, carrying the purpose as an opaque string:
round-tripping the ID MUST preserve the purpose byte-for-byte, and the
§4 structural validations (checksum, charset, payload size) still
apply in full. Purpose-format compatibility (§4 step 10) is only
enforceable for registered purposes.

This rule is what decouples consumers: an owning system may mint IDs
under a newly registered purpose (§6.2, §6.3) without requiring every
other implementation to upgrade in lockstep. Opacity licenses
transport and storage, not interpretation — contexts that need the
purpose's *semantics* (signature verification, key derivation,
Related-role walks per §6.5) MUST still fail on an unknown purpose.

Since 2026-07-18 (linenisgreat/madder#270), this rule also covers
**general identifiers used as purposes by design**, not only purposes
awaiting registration: a hyphence type name, a zettel id
(`one/uno`), or a typed-edge field name used as a purpose (§6 —
`md@...`, `one/uno@...`, `blocks=task/other@...`) is never expected
to appear in this registry; resolving it is the consuming type
system's job, exactly as resolving any other identifier is
(linenisgreat/hyphence#6). Decoders MUST NOT treat "purpose absent
from registry" as an error condition or a sign of stale data.

Opacity is about the *registry*, not the *grammar*: an unregistered
purpose still MUST satisfy §2.1's charset, either bare or quoted. A
decoder MUST NOT accept a purpose it cannot spell.

*(test: `TestSetMarklId_UnknownPurposeAcceptedOpaquely` in
`go/internal/bravo/markl/`; fixture vector
`purpose/example-unregistered-purpose-v1/sha256`.)*

## 7. Test Vectors

Independent implementations MUST round-trip the conformance fixture at
`go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json`
(canonical home since the piggy#183 ownership inversion; madder's copy
was retired with the cutover). The fixture is the canonical artifact;
this section documents only its schema. The file lives under Go's
`testdata/` convention so it travels with the Go module's build
sandbox; it is otherwise readable as plain JSON by any consumer.

The fixture's filename retains its `0002-` prefix, which now refers to
this RFC's former number. Renaming it is a mechanical follow-up, not a
normative requirement.

§7.3 defines a second, complementary corpus scoped to the *identifier*
grammar alone.

### 7.1. Vector File Schema

```json
{
  "vectors": [
    {
      "name": "format/blake2b256/non_trivial",
      "purpose": "",
      "format": "blake2b256",
      "payload_hex": "000102…",
      "encoded": "blake2b256-…"
    }
  ],
  "invalid": [
    {
      "name": "mixed_case",
      "encoded": "sha256-QQQ…",
      "error": "MixedCase"
    }
  ]
}
```

A round-trip implementation:

1. Reads `payload_hex`, decodes to bytes.
2. Encodes via the implementation under test with `format` and (if
   non-empty) `purpose`.
3. Asserts the result equals `encoded` (canonical lowercase form).
4. Decodes `encoded` and asserts it produces `(purpose, format,
   bytes)`, applying the §4 validations.

For invalid vectors, the implementation MUST reject `encoded`. The
`error` field names a structural failure category from §4 — the exact
error type is implementation-specific.

### 7.2. Concrete Vectors

The Go reference implementation generates the fixture
deterministically via a build-tag-gated test
(`TestGenerateRFC0002Vectors`, gated by `rfc0002_generate`) and
verifies it on every CI run via `TestRFC0002VectorsRoundTrip` /
`TestRFC0002InvalidVectorsRejected`. Three of the invalid vectors
(`mixed_case`, `wrong_size_for_format`,
`incompatible_purpose_format`) double as **poison vectors** that fail
when the corresponding decoder validation is removed; this RFC's
preparation involved demonstrating each one against a deliberately
de-validated decoder before re-applying the fixes.

The fixture covers, at minimum:

- One round-trip vector per registered format (§5) with payload bytes
  `[0x00, 0x01, …, size-1]`.
- An additional all-zeros vector for each hash format (the format's
  canonical null state).
- One round-trip vector per `(purpose, compatible-format)` pair from
  §6.1.
- One round-trip vector bearing a purpose absent from every registry,
  pinning the §6.6 opaque-carry rule.
- Invalid vectors covering: uppercase/mixed case, missing separator,
  a body bearing more than one `-` (§3.2), wrong checksum, charset
  violation, wrong payload size, incompatible `(purpose, format)` pair,
  and a purpose-charset violation.

To regenerate after a registry change:

```sh
cd go && go test -tags 'test rfc0002_generate' \
  -run TestGenerateRFC0002Vectors \
  ./internal/charlie/markl_registrations/...
```

### 7.3. Identifier Conformance Vectors

The fixture of §7 exercises whole markl IDs against a decoder. It does
not, and cannot, exercise an *embedding grammar's* identifier
production, because an embedding grammar has no markl decoder in it.
§7.4 explains why that gap matters. This subsection defines the corpus
that closes it.

This repository publishes an **identifier conformance-vector corpus** at
`docs/rfcs/0011-identifier-vectors.txt`. Its scope is the purpose slot
alone (§2.1's `purpose` production), not the digest slot and not the
checksum.

Each line of the corpus is a purpose slot paired with a verdict:

- **`parse`** — the string is a well-formed purpose under §2.1, either
  as a bare `ident` or as a `quoted-string`, and is valid.
- **`reject`** — the string is not a well-formed purpose under §2.1. A
  conformant grammar MUST fail to parse it.
- **`parse-invalid`** — the string is well-formed under §2.1, so a
  conformant grammar MUST parse it, but a decoder refuses it at
  validation (§2.2's unconditional `@` ban, §2.3's quoted digest). A
  consumer testing only a grammar treats this exactly like `parse`; a
  consumer testing a full decoder expects the parse to succeed and the
  validation to fail.

The third verdict is load-bearing rather than a convenience.
Grammar-validity and decoder-validity are genuinely different questions
in this specification — §2.3 makes that split a deliberate design
feature — and collapsing them into a binary would make the corpus
unrunnable against a bare grammar, which is precisely the consumer it
exists to serve.

The corpus MUST cover, at minimum: bare idents using each admitted rune
class (ALPHA, DIGIT, `-`, `_`, `/`); registered-purpose spellings from
§6.1; object-id-shaped purposes such as `one/uno`; strings requiring the
quoted escape hatch (embedded space, embedded reserved rune, non-ASCII
rune); malformed quoting (unterminated, bad escape); and the
unconditional `@` rejection of §2.2, both bare and inside quotes.

Downstream grammars that embed a markl ID as a lexeme (§2.2) — trellis
foremost — SHOULD run this **same corpus** against their own identifier
production and assert the same verdicts. Any verdict mismatch that is
not recorded in §7.4's divergence register MUST fail a gate in the
downstream repository.

The corpus is executed in this repository too, not merely published for
downstream's benefit. Shipping a corpus that nobody runs would reproduce
the same zero-power trap (piggy#220, hyphence#9) one level up: a drift
guard that cannot fail is not a guard.

*(test: `TestIdentifierVectors` in
`go/internal/charlie/markl_registrations/identifier_vectors_test.go`,
run by `just test-grammar-vectors`, which executes every corpus line
against `go/internal/bravo/markl/marklid.peg` via langlang. Downstream
tests are pending in each consumer. The precedent for the mechanism is
hyphence's `rfc_vectors.txt`, kept byte-identical between its Go and
Rust implementations by a `checks.vectors-equality` flake check.)*

### 7.4. The Divergence Register

**Why detection instead of coupling.** §2.2 imports trellis's `MarklTerm`
*shape* — a two-slot `(String / Ident) '@' Ident` — and nothing more.
Trellis keeps its own `Ident` and `IdentRune`; this RFC keeps its own
`ident-char`. piggy owns "what a markl purpose may contain"; trellis
owns "what a trellis identifier may contain". The two are deliberately
not the same definition, because trellis's `Ident` also names object
ids, tags, and field names, and will therefore evolve for reasons that
have nothing to do with markl. Coupling the definitions would turn every
trellis identifier decision into a cross-repo negotiation, and would
give markl a veto over a grammar it does not own.

The cost of that decoupling is silent drift: two grammars that agree
today can disagree tomorrow with nothing to notice. The mitigation is
**detection, not coupling** — §7.3's shared corpus, run on both sides.

**The invariant is a subset relation, not equality.** The two grammars
do not agree today and are not expected to: this RFC's `ident-char` is
an ASCII-closed *inclusion* set, while trellis's `IdentRune` is a
Unicode-open *exclusion* set (any rune that is neither `Reserved` nor
whitespace). Every bare markl purpose is therefore a valid trellis
identifier, but not conversely —

> **markl `purpose` ⊂ trellis `Ident`**

— and it is that containment, not verdict-for-verdict equality, that the
corpus asserts. A downstream consumer runs the corpus and checks that
everything this RFC marks `parse` also parses on its side; a string this
RFC marks `reject` MAY still parse downstream, and entry 1 below records
why that is expected rather than alarming.

Stating the invariant this way matters because the alternative reading
was briefly taken and was wrong. The ruling that produced §2.1's
inclusion set (linenisgreat/madder#273 ruling 1) described it as "the
trellis `Ident` model", which reads as equality; trellis's actual
production is exclusion-based, so an equality invariant would have
failed on its first run against any non-ASCII input. The containment
statement is what the two grammars actually satisfy.

Where a divergence is **intentional**, it is recorded in the register
below with its reason, and the gate treats the recorded mismatch as
expected: the corpus run returns green. An *unrecorded* mismatch is a
failure. The register is therefore the single place where "these two
grammars differ, on purpose" is written down, and adding an entry is a
deliberate act with a stated rationale rather than a silently relaxed
assertion.

| # | Divergent grammar | Input | markl verdict | Downstream verdict | Status | Reason |
|---|-------------------|-------|---------------|--------------------|--------|--------|
| 1 | trellis `Ident` | any non-ASCII rune, and any ASCII punctuation outside `-` `_` `/` that trellis does not reserve — `café`, `a.b`, `a+b`, `a:b`, `a(b)` | `reject` bare; reachable only quoted (§2.1) | parses as a bare `Ident` | **real — holds from day one** | Structural and intentional. This RFC narrowed the bare purpose to an ASCII inclusion set so a bare markl ID stays safe to paste into shell, URL, and log contexts, and so both slots share one charset shape; trellis stays exclusion-based because its `Ident` also names object ids, tags, and field names, where Unicode content is ordinary. The containment direction is preserved — everything markl accepts bare, trellis accepts — so this widens trellis relative to markl and never the reverse. Purposes in this class remain fully expressible in markl via the quoted form (§2.1, ruling 2). |
| 2 | trellis `Ident` | `a->b` used as a purpose | parses as one bare `ident` (`-` is ordinary `ident` content per §2.1) | anticipated to split at the combinator | **anticipated — not yet real** | If trellis adopts token-granular `-` limiting so that combinators such as `->` self-delimit, a purpose containing `->` will tokenize differently in trellis than in a markl ID. The divergence would be intentional on trellis's side: a query language needs its combinators to bind tighter than identifier content. Recorded ahead of time so that, if it lands, it lands as a register entry rather than as a corpus failure. Note this one runs the OPPOSITE direction to entry 1 — it would make trellis *narrower* than markl on those inputs, and so is the entry that could actually break containment. |

Entry 1 is real and holds today; it is the direct consequence of §2.1's
narrowing and is why the invariant above is containment rather than
equality. Entry 2 is anticipated, not observed.

The two entries are worth contrasting. Entry 1 widens trellis relative
to markl, which containment permits and which the quoted form makes
harmless. Entry 2, if it lands, would narrow trellis on inputs markl
accepts — the direction that would actually violate `purpose ⊂ Ident`.
That asymmetry is the thing to watch: a future divergence in entry 1's
direction is routine, while one in entry 2's direction warrants
re-examining whether the shape-only import (§2.2) still holds.

## 8. Security Considerations

1. **Checksum is detection-only.** The 6-character BCH checksum
   detects transcription errors; it provides **no** protection against
   deliberate tampering. Implementations MUST NOT treat checksum
   validity as evidence of authenticity. Authenticity is provided by
   the cryptographic content identified by the markl ID (digests,
   signatures, key bindings). Note that this is a limit on what the
   checksum *proves*, not a licence to skip verifying it — §3.3 and §4
   step 7 make verification mandatory.

2. **Length unbounded.** Because §3.6 lifts BIP173's 90-character cap,
   decode implementations MUST tolerate long inputs but SHOULD enforce
   a per-application maximum to prevent resource-exhaustion. A
   practical maximum for non-`*_ssh` formats is 130 characters
   (sufficient for a 64-byte payload plus the longest registered
   format/purpose names). A quoted purpose (§2.1) has no inherent
   length bound at all, which makes a per-application cap more, not
   less, important.

3. **Format ID is not authenticated.** The format ID is part of the
   HRP and so part of the checksum input, making it tamper-evident,
   but it is not authenticated by any signature. Implementations MUST
   validate the decoded payload size against the format's registered
   size (§5) and MUST validate `(purpose, format)` compatibility
   (§6.1), to prevent format-confusion attacks where a 33-byte
   `pivy_ecdh_p256_pub` is reinterpreted as some other 33-byte
   format.

4. **One spelling per identifier.** As of the 2026-07-20 amendment
   (§3.5) a markl ID has exactly one canonical spelling: lower-case.
   The pre-amendment rule admitted an all-upper form as an equivalent
   encoding of the same bytes, which required every store and dedup
   path to canonicalise before content-addressed comparison, and made
   "these two strings differ" a weaker statement than "these two IDs
   differ". Under the current rule an uppercase ID is not a variant
   spelling but an invalid one, and byte equality of two valid markl
   IDs is identity. Implementations MUST reject rather than
   canonicalise. Existing canonicalise-then-compare paths remain safe
   (they are now no-ops on valid input) but MUST NOT be relied on to
   *accept* uppercase input.

## 9. Backwards Compatibility

Existing dodder/madder data on disk uses lower-case markl IDs —
without purposes for blob digests, with purposes for object metadata,
signatures, and repository keys, and with bare purpose-id-shaped HRPs
for legacy private-key references (resolved via §6.4). This RFC does
not change any wire byte for data in the currently shipping form; it
pins the behaviour already implemented by the Go reference
implementation (`go/internal/bravo/markl/`). Existing data remains
valid, with the one exception recorded in §9.1.

The conformance work in
[madder#150](https://github.com/amarbel-llc/madder/issues/150) tightened
two decoders to match this spec where they previously diverged:

- `markl.Id.UnmarshalText` now runs the §4 size and (purpose, format)
  compatibility checks (previously skipped).
- `blech32.Decode` now validates case across the whole input
  (previously checked only the data portion).

These tightenings reject inputs the prior implementation silently
accepted. No prior input that was actually valid per this RFC is
affected.

The 2026-07-20 amendments add three further tightenings: lower-case
only (§3.5), single-separator (§3.2), and a narrowed bare purpose
charset (§2.1). The first required no migration (§3.5's implementation
precondition). The third is a narrowing of a rule that shipped only two
days earlier and whose widest reaches had no producer. The second is the
one with a real cost, recorded next.

### 9.1. Superseded: the Combined-HRP Form (Historical)

**This subsection is historical. The behaviour it describes is
superseded and MUST NOT be implemented on any normal decode path.**

Two related legacy forms are gathered here.

**The combined `<purpose>@<format>` HRP.** A tightening that bound the
blech32 checksum to `<purpose>@<format>` rather than just `<format>`
was incorrect and was **reverted** under
[madder#159](https://github.com/amarbel-llc/madder/issues/159). The
combined-HRP rule shipped briefly between commit `8dc78c7` and the
issue-#159 revert. The current spec (§3.3) restores the property that
the same `(format, data)` under different purposes encodes to identical
blech32 bodies — load-bearing for dodder's mother→child signature
lineage and any digest-extraction path that re-attaches a digest under
a different purpose. Existing pre-`8dc78c7` on-disk data is
checksum-verifiable again under the restored rule; downstream consumers
coordinating on this spec MUST use the split-HRP form.

**HRPs containing `-`.** §3.2's single-separator rule means an HRP
containing `-` no longer decodes at all through the normal path. Two
classes of data are affected: any datum written under the combined-HRP
rule whose purpose contained a hyphen (which every registered purpose
of §6.1 does), and the purpose-id-shaped legacy HRPs of §6.4
(`dodder-repo-private_key-v1`, `zit-repo-private_key-v1`).

**Accepted risk.** A persisted markl ID whose HRP contains `-` no longer
decodes through the normal path. This was accepted deliberately on
2026-07-20: the readability and unambiguity of a single-separator body
(§3.2) outweigh continued normal-path support for a form that shipped
briefly, was reverted, and whose alias survivors are a closed,
enumerable set.

**Out-of-band repair only.** The reference implementation RETAINS
`DecodeWithHRPOverride` and `VerifyChecksumWithHRPOverride` as the
out-of-band repair path for such data: a caller who already knows the
intended HRP can supply it explicitly and recover the payload. These are
explicitly **NOT a general decode path**. Normal decoding MUST NOT reach
them, MUST NOT fall back to them on `SeparatorMissing`, and MUST NOT
guess an HRP. They exist for migration tooling that is told, out of
band, which HRP to assume.

## 10. References

### 10.1. Normative

- BIP 173 — Base32 address format for native v0-16 witness outputs (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
  Blech32 is defined by reference to this document (§3).
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- RFC 4253 — The Secure Shell (SSH) Transport Layer Protocol
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
- SEC 1 — Elliptic Curve Cryptography (compressed point format)

### 10.2. Informative

- BIP 350 — Bech32m format for v1+ witness addresses (cited only to
  clarify that blech32 uses bech32's polymod-XOR target `1`, not
  bech32m's `0x2bc830a3`)
- ISO/IEC 18004 — QR Code symbology, whose alphanumeric mode charset
  (`0-9`, `A-Z`, space, `$%*+-./:`) is the basis for §3.5's finding
  that bech32's uppercase allowance cannot benefit a markl ID
- `go/internal/bravo/markl/` — Go reference implementation
- `go/internal/bravo/markl/marklid.peg` — executable structural grammar
  for §2.1, under the sync obligation stated there and in §4.1
- `go/internal/alfa/blech32/` — Go reference blech32 implementation
- `go/internal/charlie/markl_registrations/` — format and `piggy-*`
  purpose registrations; madder's
  `go/internal/charlie/markl_registrations/` — `madder-*`,
  transitional `dodder-*`, and papi purpose/alias registrations
- `go/internal/charlie/markl_registrations/testdata/0002-markl-id-format-vectors.json` —
  conformance fixture (this RFC §7)
- `docs/rfcs/0011-identifier-vectors.txt` — identifier conformance-vector
  corpus (this RFC §7.3); pending
- madder `docs/man.7/markl-id.md` — informal manual page; this RFC
  supersedes it for normative purposes
- madder `docs/decisions/0006-markl-registration-api-shape.md` — ADR for
  `RegisterPurpose` API shape
- amarbel-llc/piggy issue #68 — original motivation for pinning the
  spec
- amarbel-llc/piggy issue #183 — markl-ownership inversion; the reason
  this document lives in piggy
- [linenisgreat/hyphence#6](https://code.linenisgreat.com/linenisgreat/hyphence/issues/6) —
  ruling that markl-id form is canonical for pinned/locked references
  ecosystem-wide; motivates the §2.2 embedding-grammar quoting split
- [linenisgreat/piggy#219](https://code.linenisgreat.com/linenisgreat/piggy/issues/219) —
  implementation sibling of the 2026-07-18 purpose grammar/parser
  expansion, whose charset half is superseded by §2.1
- [linenisgreat/madder#270](https://code.linenisgreat.com/linenisgreat/madder/issues/270) —
  the 2026-07-18 purpose-charset expansion, superseded by §2.1
- [linenisgreat/madder#273](https://code.linenisgreat.com/linenisgreat/madder/issues/273) —
  **the durable record of the 2026-07-20 rulings** amended into this
  document: the move to piggy, the purpose-charset narrowing, quoting on
  both slots, the retained digest structure, structurally-open
  format-ids, registry-implied length, lower-case only, mandatory
  checksum verification, blech32-by-reference, the single-separator
  rule, the superseded combined HRP, the validation-rejected quoted
  digest, the trellis shape-only import, and the drift guard
- cutting-garden `docs/rfcs/0014-trellis.peg` — `MarklTerm`
  production (`(String / Ident) '@' Ident`), the structured two-slot
  form §2.2 imports, and the `Ident`/`IdentRune`/`Reserved`
  productions §7.4 deliberately does not
- hyphence RFC 0003 — Markl-Atomic Locks
  (hyphence `docs/rfcs/0003-markl-atomic-locks.md`, merged at commit
  `60d2ff9`) — supersedes hyphence RFC 0002's spaced `Lock` form with
  the purpose-full markl-id spelling this RFC supports
- hyphence `rfc_vectors.txt` and its `checks.vectors-equality` flake
  check — the precedent for §7.3's shared-corpus drift guard

## Appendix A. Differences from BIP173 bech32

Blech32 is bech32 by reference (§3). The table below enumerates every
divergence; anything not listed is bech32's, unchanged.

| Property                | BIP173 bech32           | Blech32                            |
|-------------------------|-------------------------|------------------------------------|
| Separator               | `1`                     | `-`                                |
| Separator location      | last `1` in the string  | the single `-` in the body (§3.2)  |
| HRP charset             | printable ASCII 33–126  | `[a-zA-Z0-9_]` (§3.2)              |
| 90-char length limit    | enforced                | not enforced (§3.6)                |
| Case rules              | all-upper or all-lower  | lower-case only (§3.5)             |
| Polymod XOR target      | `1`                     | `1` (same)                         |
| Data charset            | bech32 alphabet         | bech32 alphabet (same)             |
| Generator polynomial    | bech32 generator        | bech32 generator (same)            |
| Checksum construction   | polymod over hrp-expand ‖ data | same                        |
| 8-to-5-bit conversion   | zero-padded             | same                               |

The separator change is the substantive one, and it is motivated by
readability rather than by branding: with digit-bearing HRPs like
`blake2b256`, a `1` separator gives a reader no visual join, whereas
`-` does (§3). The HRP-charset restriction is what makes that separator
unambiguous, and the separator-location and case rules follow from it.
The separator change also makes blech32 visually distinct from bitcoin
addresses while preserving the checksum's detection properties.
