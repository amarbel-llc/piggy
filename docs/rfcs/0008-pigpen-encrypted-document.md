---
status: draft
date: 2026-06-24
provenance: |
  Scopes a new piggy-owned encrypted-document format, "pigpen", that is
  a hyphence document (madder RFC 0001) carrying a markl-ID recipient
  set in its metadata section and an optional ciphertext payload in its
  body. The design combines the file-key indirection, STREAM payload,
  and header-MAC of the age v1 format with the PIV/P-256 hardware
  recipient model of the piggy-box ebox (RFC 0002), unifying both under
  markl IDs (RFC 0003 / madder RFC 0002). A payload-less pigpen document
  subsumes the `piggy-ids` recipient file (RFC 0003). Prototypes land in
  Go (`go/markl/pigpen`) and Rust (`crates/piggy-pigpen`), both shaped so
  a WASM build is a first-class output. Tracks the "pigpen" umbrella.
---

# RFC 0008 — `pigpen`: a hyphence-framed encrypted document and recipient set

## Abstract

This RFC specifies **pigpen**, a piggy-owned document format for
encrypting a payload to a set of recipients and, in its degenerate
payload-less form, for declaring a recipient set. A pigpen document is a
**hyphence document** (madder [RFC 0001](https://github.com/amarbel-llc/madder/blob/main/docs/rfcs/0001-hyphence.md))
with the type identifier `pigpen-v1`. Its metadata section carries the
recipient set as **markl IDs** ([RFC 0003](0003-piggy-ids-file-format.md),
madder RFC 0002); its body carries the ciphertext, either inline or as
an `@`-referenced content-addressed blob.

Cryptographically, pigpen takes:

- **from age v1** — a single random *file key* encrypts the payload
  once; the file key is independently *wrapped* to each recipient, so
  re-keying the recipient set costs N cheap wraps rather than a full
  re-encryption; a chunked STREAM payload; and a header MAC binding the
  recipient set to the payload (best of [age](https://age-encryption.org/v1));
- **from the ebox** — recipients are PIV hardware keys (slot 9D, NIST
  P-256 ECDH), wrapped with the same ephemeral-static ECDH → HKDF →
  AEAD construction the ebox and `age-plugin-piggy` already use, so
  decryption delegates to a card via piggy-agent and the private key
  never materializes (best of [RFC 0002](0002-piv-ecdh-box.md));
- **from markl IDs** — every recipient, every wrapped key, the header
  MAC, and the payload digest is a self-describing, checksummed markl
  ID, and the whole document is plain hyphence (best of RFC 0003).

A pigpen document with recipient lines but no wrapped keys and no body
is byte-for-byte expressible as, and semantically equivalent to, a
`piggy-ids` file's recipient set; pigpen is therefore a strict superset
of `piggy-ids` and is intended to subsume it.

## Status and Provenance

Draft. This RFC scopes the format and pins the wire model; the
reference prototypes (`go/markl/pigpen`, `crates/piggy-pigpen`)
accompany it but are explicitly marked **prototype** and are not yet on
any user-facing dispatch path. Nothing in piggy reads or writes
`pigpen-v1` documents in production until a follow-up cutover RFC
promotes it (see [Compatibility](#compatibility)).

The normative referents are:

- madder RFC 0001 — the hyphence envelope this format is framed in.
- madder RFC 0002 / piggy RFC 0003 — the markl ID wire format every
  recipient line, wrapped key, MAC, and digest is encoded in.
- piggy RFC 0002 — the ebox ECDH box whose P-256 wrap construction
  pigpen reuses.
- piggy RFC 0004 — age recipients in piggy (the X25519 family).
- the age v1 specification — the file-key / STREAM / header-MAC model.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## 1. Motivation

Piggy today carries three artifacts with overlapping concerns:

1. **`.ebox` files** (RFC 0002) — a self-contained binary container.
   Strong PIV hardware story, but re-encrypting on every recipient
   change is O(payload), the format is opaque binary, and recipients
   are raw EC points rather than self-describing IDs.
2. **`piggy-ids` files** (RFC 0003) — a text recipient set as markl
   IDs. Hand-editable and diffable, but a *separate* artifact from the
   ciphertext, with its own ad-hoc line grammar.
3. **age files** (via `age-plugin-piggy`, RFC 0004) — the file-key
   model and a standard payload format, but no native notion of a
   piggy recipient *set*, no markl IDs, and no hyphence framing.

Pigpen collapses these into one versioned hyphence type:

- A **sealed** pigpen is the ebox's job, but with age's cheap re-keying,
  a transparent text header, and markl-ID recipients.
- A **payload-less** pigpen is the `piggy-ids` file's job, expressed in
  the same grammar, so "who can read this store" and "here is an
  encrypted secret" are the same document type at different fill levels.
- Because it is hyphence, a pigpen document composes with the rest of
  the madder/hyphence tooling (`hyphence validate|meta|body|format`)
  and with content-addressed blob storage.

## 2. Document Model

### 2.1 Hyphence framing

A pigpen document is a hyphence document per madder RFC 0001. It uses
**only** the existing hyphence metadata prefixes — `!`, `@`, `#`, `-`,
`<`, `%` — and adds no new wire-format prefix. (Adding a prefix would be
a hyphence wire change requiring a madder RFC; pigpen deliberately
avoids that.) The pigpen-specific structure lives entirely in *how the
existing lines are populated*, which is the latitude RFC 0001 §"Out of
scope" grants the type identified by the `!` line.

```
---
# <optional human description>            (hyphence '#')
- <recipient-markl-id> [< <wrap-markl-id>]   (hyphence '-' tag, optional '<' lock)
- <recipient-markl-id> [< <wrap-markl-id>]
...
@ <ciphertext-blob-markl-id>              (hyphence '@'; XOR with an inline body)
! pigpen-v1[@<header-mac-markl-id>]       (hyphence '!' type, optional lock)
---

<ciphertext bytes>                        (hyphence body; XOR with the '@' line)
```

### 2.2 The two faces of a pigpen document

| Face | Metadata | Body / `@` | Equivalent to |
|------|----------|------------|---------------|
| **Recipient set** | `-` recipient lines, **no** `<` wrap locks; `! pigpen-v1` with **no** MAC lock | absent | a `piggy-ids` file (RFC 0003) |
| **Sealed document** | `-` recipient lines **each** with a `<` wrap lock; `! pigpen-v1@<mac>` | inline ciphertext body **or** `@` ciphertext blob | an `.ebox` (RFC 0002) |

A reader distinguishes the two faces structurally: a document whose
recipient lines carry wrap locks and whose type line carries a MAC lock
is sealed; one with neither is a recipient set. A document that mixes
the two states (some recipients wrapped, some not; a body but no MAC;
etc.) is malformed and MUST be rejected.

### 2.3 Recipient lines

Each recipient is one hyphence `-` line whose value is a recipient
markl ID, exactly as in a `piggy-ids` file:

```
- piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>
- piggy-recipient-v1@age_x25519_pub-<blech32>
```

The accepted `(purpose, format)` pairs are precisely those of RFC 0003
§"Recipient Constraint":

| Family | markl format | Purpose | Wrap (sealed mode) |
|--------|--------------|---------|--------------------|
| PIV slot 9D | `pivy_ecdh_p256_pub` (33 B) | `piggy-recipient-v1` | §4.3 P-256 |
| age v1 | `age_x25519_pub` (32 B) | `piggy-recipient-v1` | §4.4 X25519 |

As in RFC 0003, bare-format recipient IDs (no purpose) MUST be accepted
on input and canonicalised to the `piggy-recipient-v1@` form on rewrite.
Recipient *order* is preserved by writers but is NOT semantically
significant.

SSH-authentication entries (`piggy-piv_auth-v1@ssh_*_pub`, RFC 0003
§"SSH-Authentication Entries") MAY also appear as `-` lines. They are
**not** encryption recipients: they MUST carry no wrap lock, MUST be
excluded from the file-key wrap and from the recipient-set diff used for
re-keying, and are consumed only by `piggy ssh-copy-id`. This preserves
RFC 0003's "one file answers both 'who can decrypt' and 'who may log
in'" property.

### 2.4 Wrap locks (sealed mode)

In sealed mode, each *encryption* recipient line carries a hyphence
lock whose markl ID is the per-recipient wrapped file key:

```
- piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32> < pigpen-wrap-v1@pigpen_wrap_p256-<blech32>
- piggy-recipient-v1@age_x25519_pub-<blech32>      < pigpen-wrap-v1@pigpen_wrap_x25519-<blech32>
```

The lock grammar is hyphence's existing `- value < markl-id` form
(RFC 0001 §"Metadata Lines"). Semantically the recipient is *locked to*
the wrapped key that only that recipient can open — exactly the meaning
hyphence locks already carry. The wrap markl ID encodes the recipient's
ephemeral public key and the AEAD-wrapped file key; see §4.

### 2.5 Payload

The ciphertext payload is either:

- **inline** — the hyphence body, which is the pigpen STREAM payload of
  §4.5. In this case there MUST be no `@` line (RFC 0001 forbids an `@`
  reference together with an inline body); or
- **referenced** — an `@` line whose markl ID is a content-addressed
  digest (`blake2b256-<blech32>`) of the STREAM payload stored as a blob
  in a blob store. In this case the body MUST be empty.

The `@`-referenced form lets large encrypted payloads live in
content-addressed storage while the pigpen document stays a small,
diffable header — a property inherited directly from hyphence.

### 2.6 Header MAC

In sealed mode the `!` type line carries a lock whose markl ID is the
header MAC (§4.6):

```
! pigpen-v1@pigpen_header_mac-<blech32>
```

The MAC binds the entire recipient set, the payload reference, and the
suite version to the file key, preventing recipient-stripping and
payload-substitution attacks (§6). A recipient-set (payload-less) pigpen
has no file key and therefore no MAC: its type line is the bare
`! pigpen-v1`.

### 2.7 Descriptions and comments

The optional document description (`#` line) and the optional per-recipient
comment are free UTF-8 text. To keep them unambiguous within the single-line
hyphence framing, the following rules are normative:

- **Comment delimiter.** A recipient comment is separated from its markl ID by
  the exact four-byte sequence `  # ` (two spaces, `#`, one space). A reader
  MUST look for this comment delimiter **before** the ` < ` wrap delimiter, and
  MUST take the entire remainder of the line as the comment **verbatim** (no
  trimming of leading `#` or space). This lets a comment contain a ` < ` or a
  leading `#` without being mistaken for a wrap lock or having characters
  eaten. Because a recipient markl ID and a blech32 wrap value never contain
  `  # `, the delimiter is unambiguous. A recipient line is EITHER wrapped
  (sealed mode) OR carries a comment — never both.

- **Empty is absent.** A description or comment whose text is empty is
  equivalent to its absence and MUST NOT be serialized as a line. In
  particular a writer MUST NOT emit a bare `# ` description line, and a reader
  MUST treat an empty `# ` line as no description. (An empty description that
  was serialized by one implementation but dropped by another would desync the
  §4.6 header MAC, making the sealed document undecryptable across
  implementations.)

- **Single-line only.** A description or comment MUST NOT contain a
  line-breaking control character (`\n` or `\r`); a writer MUST reject such
  input rather than emit it, since an embedded newline would break the
  metadata framing and silently corrupt the document on re-parse.

- **UTF-8 only.** Every metadata line body MUST be valid UTF-8. A reader MUST
  reject a metadata line whose body is not valid UTF-8 rather than lossily
  decoding it, so all implementations agree on the same input (a reader that
  keeps raw bytes and one that replaces invalid bytes with U+FFFD would
  otherwise diverge, including in the §4.6 header MAC). Valid pigpen content —
  markl IDs, blech32 blobs, and human text — is always UTF-8.

Comments are excluded from recipient-set identity (§5, reusing RFC 0003
§"Equality").

## 3. Versioning

Pigpen is versioned the way every hyphence type is: by the type string.
`pigpen-v1` pins the *entire* cryptographic suite (curves, KDF, AEAD,
STREAM chunking, MAC) — there is no in-document algorithm negotiation,
mirroring age v1's fixed suite and RFC 0001's "evolution is carried by
type strings" rule. A future suite (e.g. adding N-of-M recovery groups,
post-quantum recipients, or a different AEAD) is a new type string
`pigpen-v2`, specified by a superseding RFC; decoders MUST retain
support for `pigpen-v1` indefinitely.

## 4. Cryptographic Construction (`pigpen-v1`)

`pigpen-v1` fixes the following primitives:

| Role | Primitive |
|------|-----------|
| KDF | HKDF-SHA256 |
| Payload AEAD | ChaCha20-Poly1305 (RFC 8439), STREAM chunking à la age |
| Wrap AEAD | ChaCha20-Poly1305 (RFC 8439), single block |
| P-256 recipient | ephemeral-static ECDH over NIST P-256 (SEC1 compressed points) |
| X25519 recipient | ephemeral-static X25519 |
| Header MAC | HMAC-SHA256 |
| Payload digest (`@` form) | BLAKE2b-256 |
| File key | 16 random bytes |

### 4.1 File key

A pigpen file key is 16 random bytes, generated with a CSPRNG. It is the
sole secret the payload encryption depends on, and the only secret each
recipient wrap protects. Implementations MUST zeroize the file key and
all derived keys promptly after use.

### 4.2 Key derivation

All key derivation uses HKDF-SHA256 with the form
`HKDF(salt, info, ikm) → L bytes`. The `info` strings are pigpen-scoped
and version-tagged so the same recipient key reused across formats can
never collide:

| Derivation | salt | info | ikm | L |
|------------|------|------|-----|---|
| payload STREAM key | 16-byte payload nonce | `"pigpen-v1 payload"` | file key | 32 |
| header MAC key | empty | `"pigpen-v1 header"` | file key | 32 |
| P-256 wrap key | `epk‖recipient` (66 B) | `"pigpen-v1 piv-p256"` | ECDH X-coord (32 B) | 32 |
| X25519 wrap key | `epk‖recipient` (64 B) | `"pigpen-v1 x25519"` | X25519 shared (32 B) | 32 |

### 4.3 P-256 wrap (PIV slot 9D)

This is the ebox / `age-plugin-piggy` `piv-p256` construction. To wrap
file key `FK` to a recipient compressed P-256 public key `Qr`:

1. Generate an ephemeral P-256 keypair `(esk, Epk)`; `Epk` is the SEC1
   **compressed** point (33 bytes).
2. Compute the ECDH shared secret `S = X-coordinate(esk · Qr)` (32 bytes).
3. `Kw = HKDF(salt = Epk‖Qr, info = "pigpen-v1 piv-p256", ikm = S, 32)`.
4. `C = ChaCha20-Poly1305(key = Kw, nonce = 0¹², aad = ∅, plaintext = FK)`
   — 16-byte ciphertext + 16-byte tag = 32 bytes. (The nonce is the
   all-zero nonce: `Kw` is unique per wrap because `Epk` is fresh, so the
   key is never reused with a second nonce. This is the age stanza
   convention.)
5. The wrap blob is `Epk(33) ‖ C(32)` = 65 bytes, encoded as the markl
   ID `pigpen-wrap-v1@pigpen_wrap_p256-<blech32>`.

To **unwrap** with the card: parse `Epk` and `C` from the wrap blob,
obtain `S` by asking piggy-agent (the `ecdh@joyent.com` extension) to
compute the ECDH of the card's slot-9D key against `Epk` — the private
scalar never leaves the card — then re-derive `Kw` and AEAD-decrypt `C`.
This is exactly the path `age-plugin-piggy` already exercises against
real hardware (RFC 0004).

### 4.4 X25519 wrap (age recipients)

This is age v1's native X25519 stanza, re-homed onto markl IDs. To wrap
`FK` to a 32-byte X25519 recipient public key `Qr`:

1. Generate an ephemeral X25519 keypair `(esk, Epk)` (`Epk` 32 bytes).
2. `S = X25519(esk, Qr)` (32 bytes).
3. `Kw = HKDF(salt = Epk‖Qr, info = "pigpen-v1 x25519", ikm = S, 32)`.
4. `C = ChaCha20-Poly1305(Kw, 0¹², ∅, FK)` — 32 bytes.
5. The wrap blob is `Epk(32) ‖ C(32)` = 64 bytes, encoded as
   `pigpen-wrap-v1@pigpen_wrap_x25519-<blech32>`.

Both directions are pure software (no card), which is what makes the
encrypt path and the X25519 decrypt path WASM-able (§7).

### 4.5 Payload (STREAM)

The payload is encrypted exactly as age v1 encrypts its payload:

1. Derive the STREAM key `Ks = HKDF(salt = N, info = "pigpen-v1 payload",
   ikm = FK, 32)`, where `N` is a fresh 16-byte payload nonce.
2. Split the plaintext into 64 KiB chunks. Encrypt each chunk with
   ChaCha20-Poly1305 under `Ks`, using the age STREAM nonce: an 11-byte
   big-endian chunk counter followed by a 1-byte "last chunk" flag
   (`0x01` for the final chunk, `0x00` otherwise). Each chunk emits a
   16-byte tag.
3. The payload bytes are `N(16) ‖ ⟨encrypted chunks⟩`. These bytes are
   the hyphence body (inline form) or the content hashed into the `@`
   digest (referenced form).

A zero-length plaintext yields a single final chunk of empty plaintext
(16-byte tag), matching age.

### 4.6 Header MAC

1. `Km = HKDF(salt = ∅, info = "pigpen-v1 header", ikm = FK, 32)`.
2. The **canonical header bytes** are the hyphence metadata section
   serialized in canonical order (RFC 0001 §"Encoder Behavior") with the
   type line written as the bare `! pigpen-v1\n` (i.e. **without** its
   MAC lock — the MAC cannot cover itself), the opening and closing
   `---\n` boundaries included, and the wrap locks present. Concretely:
   the exact bytes a conforming encoder would emit for the metadata
   section if the MAC were the empty string, minus the `@<mac>` suffix on
   the type line.
3. `MAC = HMAC-SHA256(Km, canonical-header-bytes)` (32 bytes), encoded as
   `pigpen_header_mac-<blech32>` and placed in the type-line lock.

A decoder MUST recompute and verify the MAC after recovering `FK` from
any wrap, and MUST refuse to release plaintext if it does not match.
Verifying after unwrap (rather than before) is required because `Km`
depends on `FK`; this matches age's header-authentication ordering.

## 5. markl Registrations

`pigpen-v1` introduces the following markl formats and purposes. They
MUST be registered in both the Go (`go/markl`) and Rust
(`crates/piggy-markl`) registries; the cross-domain RFC-0002 fixture is
unaffected (these are piggy-native, like `piggy-recipient-v1`).

| Kind | Identifier | Size / type | Notes |
|------|-----------|-------------|-------|
| format | `pigpen_wrap_p256` | 65 bytes | `Epk_compressed(33) ‖ AEAD(32)` |
| format | `pigpen_wrap_x25519` | 64 bytes | `Epk(32) ‖ AEAD(32)` |
| format | `pigpen_header_mac` | 32 bytes | HMAC-SHA256 output |
| purpose | `pigpen-wrap-v1` | — | accepts `pigpen_wrap_p256`, `pigpen_wrap_x25519` |
| purpose | `pigpen-doc-v1` | — | accepts `pigpen_header_mac`, `blake2b256` (payload digest) |

The recipient formats (`pivy_ecdh_p256_pub`, `age_x25519_pub`) and the
`piggy-recipient-v1` / `piggy-piv_auth-v1` purposes are reused unchanged
from RFC 0003.

## 6. Security Considerations

1. **Header MAC binds the recipient set to the payload.** Because the
   MAC keys off the file key and covers every recipient and wrap line,
   an attacker cannot add, drop, or swap a recipient, alter a wrap, or
   repoint the `@` payload digest without invalidating the MAC. This is
   the property the ebox gets from its self-contained binary structure
   and that a bare `piggy-ids` file (RFC 0003 §"Security Considerations"
   item 1) explicitly lacks. A *payload-less* pigpen has no MAC and
   inherits RFC 0003's caveat: treat it as sensitive, reviewed config.

2. **Forward secrecy on recipient removal requires re-keying.** Adding a
   recipient is a cheap re-wrap of the *existing* file key (§8). But a
   removed recipient who previously saw the file key can still decrypt
   the *old* ciphertext. Therefore removing a recipient MUST rotate the
   file key and re-encrypt the payload (§8), matching the ebox
   `recipients remove` semantics. Implementations MUST NOT "remove" a
   recipient by merely deleting its wrap line.

3. **Per-wrap key uniqueness; zero nonce is safe.** Each wrap derives a
   fresh `Kw` from a fresh ephemeral key, so the all-zero AEAD nonce in
   §4.3/§4.4 is never reused under the same key. This is the same
   argument age makes for its stanzas. Implementations MUST generate a
   fresh ephemeral key per wrap and MUST NOT cache or reuse it across
   recipients.

4. **Card-bound decryption.** P-256 recipients decrypt only via
   piggy-agent's `ecdh@joyent.com` extension; the slot-9D private scalar
   never leaves the card. A pigpen document encrypted to only P-256
   recipients cannot be decrypted in a pure-software (e.g. WASM) context
   without an injected ECDH oracle backed by a card (§7).

5. **Recipient confusion is prevented at the markl layer.** The
   `(purpose, format)` validation of madder RFC 0002 §8.3 and RFC 0003
   §"Recipient Constraint" applies unchanged; the cryptographic family
   is selected by the markl `format`, never by string inspection.

6. **No sender authentication.** Like age and the ebox, pigpen provides
   confidentiality and integrity to recipients but does not authenticate
   the sender. Any party holding the recipient public keys can produce a
   valid pigpen document. Sender authentication, if required, is a
   higher layer (e.g. a papi signature over the document).

7. **Metadata is cleartext.** Recipient IDs, the description, and the
   payload length (modulo chunk padding) are visible to anyone with the
   file, exactly as in `piggy-ids` and age. Pigpen is not a metadata-
   private format.

## 7. WASM as a build target

The prototypes are structured so a WASM module is a first-class output,
which constrains the crypto dependency choices:

- **Pure-software paths are WASM-native.** Parsing/serialization, the
  header MAC, the payload STREAM, the X25519 wrap/unwrap, and the P-256
  *encrypt-side* wrap are all pure software and compile to WASM with no
  host calls.
- **Card-bound decryption uses an injected oracle.** P-256 *decrypt*
  needs the card. The WASM module MUST NOT attempt PCSC/agent I/O;
  instead it calls out to a host-provided **ECDH oracle** — a JS
  callback (Rust: a `wasm-bindgen` import or trait object; Go: a
  `syscall/js` function) that takes `(self_pubkey, partner_epk)` and
  returns the 32-byte ECDH X-coordinate. The host wires that callback to
  piggy-agent / a WebAuthn-PIV bridge / a remote signer. This mirrors
  how `age-plugin-piggy` already abstracts ECDH behind
  `AgentEcdhOracle`.
- **Dependency constraint (Rust).** `crates/piggy-box` uses OpenSSL,
  which does not target `wasm32-unknown-unknown`. The pigpen crate
  therefore uses the pure-Rust RustCrypto stack (`x25519-dalek`, `p256`,
  `chacha20poly1305`, `hkdf`, `sha2`, `hmac`) and `blech32` from
  `piggy-markl` (already pure Rust). It does **not** depend on
  `piggy-box`. The prototype builds for both `x86_64` and
  `wasm32-unknown-unknown`.
- **Dependency constraint (Go).** The Go prototype uses only
  `crypto/ecdh`, `crypto/hkdf`, `crypto/hmac`, `crypto/sha256` (stdlib)
  and `golang.org/x/crypto/chacha20poly1305`, all of which build under
  `GOOS=js GOARCH=wasm` and tinygo. It imports the dep-light `go/markl`
  core only (not the `agent`/`age` heavy sub-packages).

See `docs/plans/2026-06-24-pigpen-wasm.md` for the concrete build
invocations and the host-oracle interface sketch.

## 8. Re-keying semantics (informative)

| Operation | Cost | File key | Payload |
|-----------|------|----------|---------|
| **add recipient** | O(1) per add | unchanged | unchanged — only a new wrap line is appended, then the MAC is recomputed |
| **remove recipient** | O(payload) | rotated | re-encrypted under the new file key; all wraps regenerated |
| **rotate (paranoia)** | O(payload) | rotated | re-encrypted |

The asymmetry is the whole point of the file-key model: routine "add a
teammate" is cheap, while "revoke a teammate" pays for forward secrecy.
A `pigpen recipients sync`-style command computes the recipient-set diff
(reusing RFC 0003 §"Equality": markl-ID identity, comments excluded) and
chooses the cheap or expensive path accordingly.

## 9. Worked Example (illustrative)

A sealed pigpen with one PIV recipient and an inline payload:

```
---
# release signing key
- piggy-recipient-v1@pivy_ecdh_p256_pub-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd < pigpen-wrap-v1@pigpen_wrap_p256-<blech32-65B>
! pigpen-v1@pigpen_header_mac-<blech32-32B>
---

<16-byte payload nonce><ChaCha20-Poly1305 STREAM chunks>
```

The same recipient as a payload-less recipient set (a drop-in for a
`piggy-ids` file):

```
---
# recipients for ~/.local/share/piggy
- piggy-recipient-v1@pivy_ecdh_p256_pub-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd  # primary yubikey (9D)
! pigpen-v1
---
```

## 10. Conformance

A conforming `pigpen-v1` implementation MUST:

- Frame documents as conforming hyphence (RFC 0001) using only the
  existing prefixes.
- Encode every recipient, wrap, MAC, and payload digest as a markl ID
  with the `(purpose, format)` pairs of §2.3 and §5.
- Implement the §4 construction bit-exactly, including the `info`
  strings, the STREAM nonce layout, the all-zero wrap nonce, and the
  MAC-after-unwrap ordering.
- Reject mixed-state documents (§2.2), `@`-with-body documents
  (RFC 0001), unknown formats/purposes, and MAC mismatches.
- Round-trip: a payload-less pigpen MUST carry exactly the recipient-set
  information of the equivalent `piggy-ids` file and convert losslessly
  to and from it.

A normative test-vector file (analogous to RFC 0002 Appendix A and the
hyphence `rfc_vectors.txt`) is **deferred to the cutover RFC**; the
prototypes ship round-trip and known-answer unit tests in the interim
(`go/markl/pigpen/*_test.go`, `crates/piggy-pigpen/src/**` `#[test]`s).

## Compatibility

Pigpen is a **new** format. It does not change the ebox (RFC 0002),
`piggy-ids` (RFC 0003), or age (RFC 0004) formats, and nothing in piggy
emits or consumes `pigpen-v1` in production at this revision. The
**cutover RFC 0009** specifies:

- the `.pigpen` file extension and store layout;
- the `piggy pass`-level commands (seal / open / `recipients`) and
  whether pigpen supersedes `.ebox` + `piggy-ids` or coexists;
- a `piggy-ids ⇄ pigpen` converter and migration story;
- the normative test-vector set and its CI drift gate;
- the markl registrations of §5 promoted from the prototype registry
  shims into `go/markl` and `crates/piggy-markl` proper.

The hyphence dependency raises a **layering** question recorded here for
the cutover: the canonical hyphence implementation lives in *madder*,
but the `dewey → piggy → madder` layering forbids piggy from importing
madder. The prototypes therefore carry a minimal in-tree hyphence
framing encoder/decoder (the envelope is ~50 lines). The cutover RFC
must choose between (a) piggy keeping its own conforming hyphence
framing, or (b) extracting a shared hyphence framing library to a
neutral layer (e.g. dewey) that both madder and piggy consume. This RFC
recommends (a) for the prototype and flags (b) as the cleaner long-term
factoring.

## References

### Normative

- madder RFC 0001 — Hyphence (the document envelope)
- madder RFC 0002 / piggy RFC 0003 — Markl ID format & `piggy-ids`
- piggy RFC 0002 — PIV ECDH Box (the P-256 wrap construction)
- piggy RFC 0004 — age recipients in piggy (the X25519 family)
- [age v1 specification](https://age-encryption.org/v1)
- RFC 2119 — Key words
- RFC 5869 — HKDF
- RFC 8439 — ChaCha20-Poly1305
- RFC 2104 — HMAC

### Informative

- `crates/age-plugin-piggy/src/p256_stanza.rs` — the `piv-p256` wrap
  pigpen reuses (the agent-ECDH-oracle decrypt path).
- `docs/plans/2026-06-24-pigpen-wasm.md` — WASM build & host-oracle
  sketch.
- `go/markl/pigpen/`, `crates/piggy-pigpen/` — reference prototypes.
