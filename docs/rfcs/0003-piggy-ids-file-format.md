---
status: draft (piggy 2.x; companion to #69 cutover umbrella)
date: 2026-05-09
provenance: |
  Authored alongside the Phase 2 work of piggy#69 / piggy#72 — the
  hard cutover from `.pivy-id` (pivy's binary tpl format) to
  `piggy-ids` (piggy-owned text format). References madder#150 for
  the markl ID wire format the recipient lines depend on; once that
  RFC settles, this file pins down only the line/file grammar
  specific to piggy. The original draft used a leading dot
  (`.piggy-ids`); this revision drops it (see "Filename" below).
---

# `piggy-ids` File Format (piggy normative)

## Abstract

This RFC specifies the `piggy-ids` text file format used by piggy 2.x
to declare the recipient set for a password store. A `piggy-ids`
file carries one recipient per line, each identified by a markl ID
tagged with the piggy-owned purpose `piggy-recipient-v1`. Two
recipient formats are accepted under that purpose:

- `pivy_ecdh_p256_pub` — PIV slot 9D (Key Management, ECDH over NIST
  P-256). The piggy 1.x → 2.x cutover format.
- `age_x25519_pub` — age v1 X25519 recipient. Markl-level parsing
  accepts these so `piggy-ids` files declaring age recipients
  validate, canonicalise, and diff cleanly; encrypt-pipeline support
  for producing ebox files with `AgeBox` parts ships under piggy
  RFC 0004 (in progress).

A `piggy-ids` file MAY additionally carry **SSH-authentication
entries** — PIV slot 9A public keys tagged with the
`piggy-piv_auth-v1` purpose and an `ssh_*_pub` format
(`ssh_ecdsa_nistp256_pub`, `ssh_ecdsa_nistp384_pub`, or
`ssh_ed25519_pub`). These
are *not* encryption recipients: they declare the SSH-login keys of the
same identities, are excluded from the encrypt pipeline and the
re-encryption comparison, and are consumed by `piggy ssh-copy-id`. See
[SSH-Authentication Entries](#ssh-authentication-entries-slot-9a) below.

The format is hand-editable, version-controlled, and round-trips
cleanly through tooling so that config-as-code-driven recipient
management is idempotent.

## Status and Provenance

This document is the normative spec for `piggy-ids` files in
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

A `piggy-ids` file lives at the root of a piggy password store (and
optionally inside any subdirectory, scoping a recipient set to that
subtree, mirroring the placement rules `.pivy-id` enjoyed in piggy 1.x).
It declares the set of recipient public keys that the entries below
it are encrypted to.

Each recipient is encoded as a markl ID per madder RFC 0002. The
piggy-owned `piggy-recipient-v1` purpose accepts two formats:

- `pivy_ecdh_p256_pub` (33 bytes, SEC 1 compressed-point form) — the
  public key of slot 9D (PIV Key Management, ECDH) on a PIV smart
  card.
- `age_x25519_pub` (32 bytes) — an age v1 X25519 recipient. The
  payload bytes are the raw X25519 pubkey; the equivalent `age1…`
  string from native age tooling and this markl form encode the same
  32 bytes under two different envelopes (bech32 vs blech32). Files
  containing only age recipients, or a mix of age and pivy
  recipients, parse and validate at the markl layer today; the
  encrypt pipeline gains an `AgeBox` part variant under piggy RFC
  0004 (`crates/piggy-box::age_part_from_markl` currently surfaces a
  `BoxError::UnsupportedRecipientFormat` for age inputs).

### Filename

The file MUST be named `piggy-ids` (no leading dot). The store
directory (`$PIGGY_STORE_DIR`, default `$XDG_DATA_HOME/piggy`) is
already a hidden location on POSIX systems; hiding the recipient file
inside it would obscure the most-edited operational artifact in the
store for no defensive benefit.

### File-level Properties

A `piggy-ids` file:

- MUST be encoded in UTF-8.
- SHOULD use LF line terminators. CRLF MAY be tolerated by readers
  but MUST NOT be produced by writers.
- SHOULD end with a final newline. Readers MUST accept files that do
  not end with a final newline; writers SHOULD always emit one.
- Has no maximum or minimum line count. An empty file (zero
  recipients) is syntactically valid but represents an unusable
  store — readers MAY warn.

### Line Grammar

Each line of a `piggy-ids` file is exactly one of the following
forms:

```text
blank-line     = *WSP LF
comment-line   = *WSP "#" *VCHAR LF
recipient-line = *WSP markl-id [comment-suffix] LF
comment-suffix = 1*WSP "#" [WSP *VCHAR]
markl-id       = recipient-entry / ssh-auth-entry
recipient-entry = piggy-purpose-tagged / bare-format
piggy-purpose-tagged = "piggy-recipient-v1" "@" recipient-blech32
bare-format    = recipient-blech32
recipient-blech32 = pivy-blech32 / age-blech32
pivy-blech32   = "pivy_ecdh_p256_pub" "-" 1*charset
age-blech32    = "age_x25519_pub"    "-" 1*charset
ssh-auth-entry = "piggy-piv_auth-v1" "@" ssh-blech32
ssh-blech32    = ("ssh_ecdsa_nistp256_pub" / "ssh_ecdsa_nistp384_pub" / "ssh_ed25519_pub") "-" 1*charset
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

- The markl ID's format MUST be one of `pivy_ecdh_p256_pub` or
  `age_x25519_pub`. Other formats MUST be rejected at the
  markl/piggy-ids layer.
- The markl ID's purpose, if present, MUST be `piggy-recipient-v1`.
  Bare-format markl IDs (no purpose) MUST be accepted as input
  syntactic sugar; writers MUST canonicalise them to the
  purpose-tagged form on rewrite.
- A `piggy-ids` file MAY mix `pivy_ecdh_p256_pub` and
  `age_x25519_pub` recipients in any order; the encrypt pipeline
  produces a single ebox whose Primary config carries one part per
  recipient, with `n=1` (any one recipient can decrypt). Producing
  age parts requires piggy RFC 0004; until that lands the encrypt
  pipeline raises `BoxError::UnsupportedRecipientFormat` on any age
  recipient. Markl-level parsing, validation, canonicalisation, and
  diffing remain available for age recipients regardless.
- Readers MUST reject recipient lines whose markl ID violates the
  format-or-purpose rule above, with an error that names the
  offending line number.

### SSH-Authentication Entries (slot 9A)

A `piggy-ids` file MAY also contain SSH-authentication entries: a markl
ID with purpose `piggy-piv_auth-v1` and one of the SSH pubkey formats —
`ssh_ecdsa_nistp256_pub` (33-byte SEC1-compressed P-256 point),
`ssh_ecdsa_nistp384_pub` (49-byte SEC1-compressed P-384 point), or
`ssh_ed25519_pub` (32-byte raw Ed25519 key) — carrying the public key
of PIV slot 9A (PIV Authentication). These describe the SSH-login keys
of the identities in the file; they are kept alongside the 9D decrypt
keys so a single file answers both "who can decrypt this store" and
"who may log in".

Constraints, distinct from recipient lines:

- **Not encryption recipients.** SSH-auth entries MUST NOT be treated
  as encryption recipients. The encrypt pipeline (`piggy-ids encrypt`,
  and `pass insert`/`generate`/`edit` through it) and the
  re-encryption SKIP comparison MUST filter them out — a secret is
  never wrapped to a 9A key, and a 9A line MUST NOT force or suppress
  re-encryption. A file containing only SSH-auth entries (no encryption
  recipients) is not encryptable and MUST be rejected by the encrypt
  path with the existing "at least one recipient is required" error.
- **Purpose-tagged only.** Unlike recipient formats, there is no
  bare-format sugar for SSH-auth entries: a bare
  `ssh_*_pub-…` (no `piggy-piv_auth-v1@` prefix) MUST be
  rejected. This keeps canonicalisation total — a bare format is only
  ever promoted to `piggy-recipient-v1@`, a pairing the SSH formats
  cannot form.
- **9A only (v1).** Only the 9A authentication slot
  (`piggy-piv_auth-v1`) is accepted. The 9C (`piggy-piv_sig-v1`) and 9E
  (`piggy-piv_card_auth-v1`) SSH purposes, though defined in the markl
  registry, are NOT accepted in a `piggy-ids` file in this revision.
- **Equality and ordering** follow the same rules as recipient lines
  (equality by markl ID; comments excluded; input order preserved).

SSH-auth entries are consumed by `piggy ssh-copy-id`, which renders
each as an OpenSSH `authorized_keys` line
(`<keytype> <base64> <comment>`, where `<keytype>` is
`ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, or `ssh-ed25519` per the
entry's format) and installs the set on a remote host. The rendering is
offline — the key payload is read directly from the markl ID, no card
access — and uses the same encoder as `piggy list --format=ssh`.

### Equality

Two recipient lines are equal **iff** their markl IDs are equal —
i.e. their `(purpose, format, payload-bytes)` tuples match. The
inline comment does not participate in equality.

This rule is load-bearing for the `piggy pass recipients sync`
command (#75): re-running `sync` against an unchanged set of
recipients but with a renamed `# comment` MUST be a no-op (no
re-encryption, no git commit).

### Order

Recipient order in a `piggy-ids` file is preserved by writers but
NOT semantically significant. Piggy MUST encrypt to all recipients in
the file regardless of order. Tools that rewrite the file (the
`recipients add/remove/sync` family in #75) MUST preserve input order
for retained recipients and SHOULD append newly-added recipients at
the end.

### Canonical Form

The canonical form of a `piggy-ids` file is what `piggy pass
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
`piggy-ids` byte representation is unchanged, no git commit is made.

### Example

```
# piggy-ids — recipients for ~/.local/share/piggy
piggy-recipient-v1@pivy_ecdh_p256_pub-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd  # primary yubikey (9D)
piggy-recipient-v1@pivy_ecdh_p256_pub-qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw7n8w8c0ydp7s8jtgqnxa  # backup yubikey (9D)
piggy-recipient-v1@age_x25519_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu     # age identity (laptop, RFC 0004)
```

## Security Considerations

1. **Recipient pubkey is not authenticated by the file format.** The
   markl ID's blech32 checksum detects transcription errors but
   provides no protection against deliberate substitution. A
   `piggy-ids` file under attacker control can be rewritten to
   redirect future `piggy pass insert`/`generate` calls to an
   attacker-controlled card. Piggy SHOULD treat `piggy-ids` as
   sensitive configuration, store it in a version-controlled and
   reviewed location, and surface visible diffs when it changes
   (the existing `git_add_file` pattern in `src/piggy.sh` provides
   this).

2. **No private key material on disk.** A `piggy-ids` file carries
   only public keys. Loss of the file does not expose secrets;
   however, recreating it from scratch requires re-collecting every
   recipient's pubkey.

3. **Format-confusion across markl ID formats is prevented at parse
   time.** Per madder RFC 0002 §8.3, the `(purpose, format)` pair is
   validated. piggy's reader additionally rejects any markl ID whose
   format is not one of `pivy_ecdh_p256_pub` or `age_x25519_pub`, or
   whose purpose is not `piggy-recipient-v1` (or absent). The
   `piggy-recipient-v1` purpose binds equally to both recipient
   formats; the cryptographic family is determined entirely by the
   markl `format` field, never by purpose-string inspection.

4. **Mixing recipient families does not weaken individual shares.**
   When `piggy-ids` lists both pivy and age recipients, the produced
   ebox carries one independently-wrapped share per recipient in a
   single Primary config with `n=1`. Compromise of one identity
   (e.g. an exfiltrated age secret) exposes that secret's share but
   does not affect the PIV-card-protected shares, and vice versa.
   The threat model is identical to the all-pivy case: any one held
   identity is sufficient and necessary to decrypt.

## Backwards Compatibility

`piggy-ids` is a new file. Existing piggy 1.x stores carry
`.pivy-id` (binary). piggy 2.x performs a hard cutover (#76):
encountering a `.pivy-id` with no neighbouring `piggy-ids` produces a
clear error directing the user to re-init. There is no in-place
migration tool. See piggy#69 for the cutover umbrella.

Stores produced by a pre-rename revision of this RFC carry the file
under its original dotted name (`.piggy-ids`). piggy 2.x rejects them
the same way it rejects a `.pivy-id`: re-init under the new filename.
No in-place migration tool is provided.

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
- piggy#72 — `piggy-ids` reader/writer phase
- piggy#75 — `piggy pass recipients` verb family
- `vendor/pivy/docs/rfcs/0003-box-ebox-formats.adoc` — pivy's binary
  template format (the artifact this RFC's text format replaces)
