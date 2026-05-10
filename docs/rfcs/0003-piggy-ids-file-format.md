---
status: draft (piggy 2.x; companion to #69 cutover umbrella)
date: 2026-05-09
provenance: |
  Authored alongside the Phase 2 work of piggy#69 / piggy#72 — the
  hard cutover from `.pivy-id` (pivy's binary tpl format) to
  `.piggy-ids` (piggy-owned text format). References madder#150 for
  the markl ID wire format the recipient lines depend on; once that
  RFC settles, this file pins down only the line/file grammar
  specific to piggy.
---

# `.piggy-ids` File Format (piggy normative)

## Abstract

This RFC specifies the `.piggy-ids` text file format used by piggy 2.x
to declare the recipient set for a password store. A `.piggy-ids`
file carries one recipient per line, each identified by a markl ID of
format `pivy_ecdh_p256_pub` tagged with the piggy-owned purpose
`piggy-recipient-v1`. The format is hand-editable, version-controlled,
and round-trips cleanly through tooling so that
config-as-code-driven recipient management is idempotent.

## Status and Provenance

This document is the normative spec for `.piggy-ids` files in
piggy 2.x. It replaces the binary `.pivy-id` template that piggy 1.x
inherited from pivy.

The normative referent for the markl ID wire format used in each
recipient line is amarbel-llc/madder RFC 0002 (madder#150, patched
by madder#159 to restore the split-HRP checksum binding — purpose is
textually prepended after blech32, never folded into the HRP).
piggy's `crates/piggy-markl` crate mirrors the post-#159 form.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## Specification

### Overview

A `.piggy-ids` file lives at the root of a piggy password store (and
optionally inside any subdirectory, scoping a recipient set to that
subtree, mirroring the placement rules `.pivy-id` enjoyed in piggy 1.x).
It declares the set of recipient public keys that the entries below
it are encrypted to.

Each recipient is the public key of slot 9D (PIV Key Management,
ECDH) on a PIV smart card, encoded as a markl ID per madder RFC 0002.
The piggy-owned `piggy-recipient-v1` purpose constrains the format
to `pivy_ecdh_p256_pub` (33 bytes, SEC 1 compressed-point form).

### File-level Properties

A `.piggy-ids` file:

- MUST be encoded in UTF-8.
- SHOULD use LF line terminators. CRLF MAY be tolerated by readers
  but MUST NOT be produced by writers.
- SHOULD end with a final newline. Readers MUST accept files that do
  not end with a final newline; writers SHOULD always emit one.
- Has no maximum or minimum line count. An empty file (zero
  recipients) is syntactically valid but represents an unusable
  store — readers MAY warn.

### Line Grammar

Each line of a `.piggy-ids` file is exactly one of the following
forms:

```text
blank-line     = *WSP LF
comment-line   = *WSP "#" *VCHAR LF
recipient-line = *WSP markl-id [comment-suffix] LF
comment-suffix = 1*WSP "#" [WSP *VCHAR]
markl-id       = piggy-purpose-tagged / bare-pivy-format
piggy-purpose-tagged = "piggy-recipient-v1" "@" pivy-blech32
bare-pivy-format     = pivy-blech32
pivy-blech32   = "pivy_ecdh_p256_pub" "-" 1*charset
charset        = %x71 / %x70 / ...   ; bech32 alphabet, see madder RFC 0002 §3.1
```

Notes:

- `WSP` is any ASCII space or horizontal tab.
- The `#` of `comment-suffix` MUST be preceded by at least one
  whitespace character. (This avoids ambiguity with a `#` that
  could otherwise be inside a future markl-id grammar extension.)
- The literal text after `#` is the recipient's inline comment.
  Leading and trailing whitespace inside the comment SHOULD be
  trimmed by readers; arbitrary printable content otherwise.

### Recipient Constraint

For every recipient line:

- The markl ID's format MUST be `pivy_ecdh_p256_pub`.
- The markl ID's purpose, if present, MUST be `piggy-recipient-v1`.
  Bare-format markl IDs (no purpose) MUST be accepted as input
  syntactic sugar; writers MUST canonicalise them to the
  purpose-tagged form on rewrite.
- Readers MUST reject recipient lines whose markl ID violates either
  rule, with an error that names the offending line number.

### Equality

Two recipient lines are equal **iff** their markl IDs are equal —
i.e. their `(purpose, format, payload-bytes)` tuples match. The
inline comment does not participate in equality.

This rule is load-bearing for the `piggy pass recipients sync`
command (#75): re-running `sync` against an unchanged set of
recipients but with a renamed `# comment` MUST be a no-op (no
re-encryption, no git commit).

### Order

Recipient order in a `.piggy-ids` file is preserved by writers but
NOT semantically significant. Piggy MUST encrypt to all recipients in
the file regardless of order. Tools that rewrite the file (the
`recipients add/remove/sync` family in #75) MUST preserve input order
for retained recipients and SHOULD append newly-added recipients at
the end.

### Canonical Form

The canonical form of a `.piggy-ids` file is what `piggy pass
recipients` writes, which is:

- Each recipient line carries the `piggy-recipient-v1@` purpose
  prefix, even if the input was bare-format.
- Inline comments are preserved verbatim, with exactly two ASCII
  spaces separating the markl ID from the `#`.
- Blank lines and comment-only lines that appeared in the input are
  NOT preserved across rewrites. (Piggy's tooling does not preserve
  arbitrary user formatting; it preserves recipient lines and their
  comments only.)
- LF line endings, trailing newline.

A file that already matches its canonical form is unchanged by a
rewrite. Combined with the equality rule, this means
`piggy pass recipients sync <file>` over an already-synced store is
truly a no-op: the recipient set is unchanged, the on-disk
`.piggy-ids` byte representation is unchanged, no git commit is made.

### Example

```
# .piggy-ids — recipients for ~/.local/share/piggy
piggy-recipient-v1@pivy_ecdh_p256_pub-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd  # primary yubikey
piggy-recipient-v1@pivy_ecdh_p256_pub-qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw7n8w8c0ydp7s8jtgqnxa  # backup
```

## Security Considerations

1. **Recipient pubkey is not authenticated by the file format.** The
   markl ID's blech32 checksum detects transcription errors but
   provides no protection against deliberate substitution. A
   `.piggy-ids` file under attacker control can be rewritten to
   redirect future `piggy pass insert`/`generate` calls to an
   attacker-controlled card. Piggy SHOULD treat `.piggy-ids` as
   sensitive configuration, store it in a version-controlled and
   reviewed location, and surface visible diffs when it changes
   (the existing `git_add_file` pattern in `src/piggy.sh` provides
   this).

2. **No private key material on disk.** A `.piggy-ids` file carries
   only public keys. Loss of the file does not expose secrets;
   however, recreating it from scratch requires re-collecting every
   recipient's pubkey.

3. **Format-confusion across markl ID formats is prevented at parse
   time.** Per madder RFC 0002 §8.3, the `(purpose, format)` pair is
   validated. piggy's reader additionally rejects any markl ID whose
   format is not `pivy_ecdh_p256_pub` or whose purpose is not
   `piggy-recipient-v1` (or absent).

## Backwards Compatibility

`.piggy-ids` is a new file. Existing piggy 1.x stores carry
`.pivy-id` (binary). piggy 2.x performs a hard cutover (#76):
encountering a `.pivy-id` with no neighbouring `.piggy-ids` produces a
clear error directing the user to re-init. There is no in-place
migration tool. See piggy#69 for the cutover umbrella.

## Implementation

The reference implementation lives at `crates/piggy-ids` in this
repository. It depends on `crates/piggy-markl` for the markl ID
codec.

## References

### Normative

- amarbel-llc/madder RFC 0002 — Markl ID Format (draft, tracked at
  amarbel-llc/madder#150)
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- RFC 3629 — UTF-8

### Informative

- piggy#69 — v2.0 cutover umbrella
- piggy#72 — `.piggy-ids` reader/writer phase
- piggy#75 — `piggy pass recipients` verb family
- `vendor/pivy/docs/rfcs/0003-box-ebox-formats.adoc` — pivy's binary
  template format (the artifact this RFC's text format replaces)
