---
status: draft (piggy 2.x; companion to piggy#3 Rust parity roadmap)
date: 2026-05-15
provenance: |
  Captures the wire-format extension that lets piggy 2.x encrypt to
  age v1 X25519 recipients alongside PIV ECDH P-256 recipients. The
  markl-format and `piggy-ids`-grammar pieces shipped first (RFC 0003
  §4 broadening; piggy-markl `PiggyRecipientV1` accepts `AgeX25519Pub`
  in addition to `PivyEcdhP256Pub`). This RFC pins the remaining
  pieces: how an ebox carries age recipient parts, how
  `piggy-ids encrypt`/`decrypt` route per format, and how
  age-plugin-yubikey identities slot into the decrypt path.
---

# Age Recipients in Piggy (piggy normative, draft)

## Abstract

This RFC extends piggy's ebox container (RFC 0002) and `piggy-ids`
recipient files (RFC 0003) to carry age v1 X25519 recipients
alongside the existing PIV ECDH P-256 recipients. The user-facing
shape is unchanged: a `piggy-ids` file lists markl IDs under the
`piggy-recipient-v1` purpose, and `piggy pass`/`piggy box` operate
on the same `.ebox` files. The internal change is a new per-recipient
share-wrap variant — `AgeBox` — that sits next to the existing
`PivBox` in the ebox template/part wire shape, and a Rust-side
decrypt dispatcher (`piggy-ids decrypt`) that replaces the current
shell-out to the C `pivy-box stream decrypt` so age parts can be
unwrapped via the `age` crate (with plugin-identity support
including `age-plugin-yubikey`).

## Status and Provenance

Draft. The user-facing surface (markl parsing, `piggy-ids` file
grammar) shipped under the "age recipient surface" change that
landed alongside this RFC; the wire-format and decrypt-dispatcher
pieces below are the remaining work.

Until the wire format lands, `piggy-box::age_part_from_markl`
returns `BoxError::UnsupportedRecipientFormat` and points callers
at this document.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

## Specification

### Recipient Identifiers

Per RFC 0003 §4.2 (broadened), the `piggy-recipient-v1` purpose
accepts two markl formats:

| Format               | Size (bytes) | Recipient family            |
|----------------------|--------------|-----------------------------|
| `pivy_ecdh_p256_pub` | 33           | PIV slot 9D (ECDH P-256)    |
| `age_x25519_pub`     | 32           | age v1 X25519 recipient     |

The 32-byte `age_x25519_pub` payload is the raw X25519 public key
(the same 32 bytes that the upstream `age1…` bech32 string encodes;
the two formats differ only in the surrounding envelope).

### Ebox Wire-Format Extension (v2)

The current ebox stream wire format (RFC 0002 §5) carries one
`PivBox` per recipient inside each template part. To carry age
recipients, an ebox v2 introduces a part-kind discriminator before
the box payload:

```text
part = TAG_PART_KIND u8(kind) <kind-specific payload>
kind = 0x01 (PivBox, today's payload)
     | 0x02 (AgeBox)
```

- v2 readers MUST accept v1 streams unchanged (every v1 part is
  treated as `kind=0x01`).
- v1 readers (notably the C `pivy-box`) reject v2 streams with an
  unknown-version error; this is acceptable because `piggy box` is
  reserved for template/key administration, not stream crypto, after
  this change. The Rust-side decrypt dispatcher
  (`piggy-ids decrypt`) is the only piece that must understand v2.

### `AgeBox` Payload

An `AgeBox` part carries:

- `recipient_pubkey` — the 32-byte X25519 pubkey (mirrors the markl
  `data()` payload), kept inline so a future tool can identify
  candidate identities without consulting the template separately.
- `stanza_bytes` — the byte-encoded age stanza(s) wrapping the
  recovery share for this single recipient, as produced by
  `age::Encryptor::with_recipients` over a one-recipient
  encryptor whose payload is the share bytes. Decoding hands the
  same bytes to `age::Decryptor` along with the configured identity
  set.

This delegates all cryptographic decisions (KDF, AEAD, key wrap)
to the age v1 specification — piggy does not add a second layer of
its own KEM on top of age. The recovery cipher / shamir share
logic in `Ebox::create` (`crates/piggy-box/src/ebox.rs`) wraps the
share-bytes payload identically for both `PivBox` and `AgeBox`
parts, so the threshold (N=1 of M for Primary; N=M' of M for
Recovery) remains family-agnostic.

### Encrypt Pipeline

`piggy_box::recipients::tpl_part_from_markl` is the routing point.
It already validates and routes today; the remaining work is to
have `age_part_from_markl` produce a real `EboxTplPart` with
`kind = Age` instead of returning `UnsupportedRecipientFormat`.

`Ebox::create` then dispatches on kind:

- `Piv`: existing `PivBox::seal_offline_with_ephemeral` path
  (RFC 0002 §6).
- `Age`: load the recipient pubkey, build an
  `age::x25519::Recipient`, encrypt the share with
  `age::Encryptor::with_recipients(vec![recipient])`, store the
  produced bytes as `stanza_bytes`.

### Decrypt Pipeline

Today, `src/piggy.sh::piggy_decrypt` shells out to the C
`pivy-box stream decrypt` binary. That binary only knows v1 +
`PivBox`. Under this RFC, `piggy_decrypt` switches to a new
`piggy-ids decrypt` Rust subcommand that:

1. Reads the ebox stream and parses the template.
2. Enumerates parts; for each part tries the kind-specific unwrap:
   - `Piv`: existing piggy-piv path (SSH-agent ECDH oracle today
     via `crates/piggy-box::oracle`; direct PC/SC oracle planned in
     piggy#57).
   - `Age`: load identities from `$PIGGY_AGE_IDENTITY` (default
     `~/.config/piggy/age-identity`) via `age::IdentityFile`. This
     transparently handles plugin identities, so an
     `AGE-PLUGIN-YUBIKEY-…` identity invokes the
     `age-plugin-yubikey` binary the same way age does natively.
3. First successful unwrap wins. If every part fails, surface
   per-part errors so the user can distinguish "card unplugged"
   from "wrong age identity" from "plugin binary missing".

### `piggy-ids` File Grammar

No grammar change beyond RFC 0003 §4.2 (broadened to accept
`age_x25519_pub`). Mixed `piggy-ids` files (pivy + age recipients)
produce a single ebox whose Primary config carries one part per
recipient with `n=1`.

### Identity Configuration

- `PIGGY_AGE_IDENTITY` — path to an age identity file (default
  `~/.config/piggy/age-identity`). Same format as the file
  consumed by `age --identity` (one identity per line; lines
  starting with `AGE-SECRET-KEY-1…` or `AGE-PLUGIN-…`).
- Multiple identities in the file are tried in order against each
  age part until one succeeds.
- A missing identity file is not an error when no age parts are
  present in the ebox; it IS an error when at least one age part
  exists and no other part decrypts.

### Build/Dependency Changes

- `piggy-box` adds the `age` crate (with the `plugin` feature) as
  a direct dependency.
- `flake.nix` adds `age-plugin-yubikey` to `runtimeDeps` so
  hardware-backed age identities work out of the box. (The base
  `age` / `rage` binaries are NOT required — piggy uses the
  library, not the CLI.)

## Security Considerations

1. **Cross-family share isolation.** Each recipient's share is
   wrapped independently. Compromise of one family's identity
   (e.g. an exfiltrated age secret) exposes only the corresponding
   share's plaintext, not the others'. The threshold rule (N=1 for
   Primary) means that compromise of any one identity in the file
   is sufficient to decrypt the body — this is unchanged from the
   all-pivy case, but worth restating since adding age widens the
   attack surface by adding new identity-holding endpoints (e.g.
   laptops with age secret keys are now in scope).

2. **No KEM-on-KEM stacking.** Age stanzas are stored verbatim
   inside `AgeBox`; piggy does not re-wrap, re-encode, or
   otherwise interpret them. This keeps the security argument
   for the age path co-extensive with age v1's security argument
   (Curve25519 ECDH → HKDF → ChaCha20-Poly1305) and avoids
   inventing piggy-specific crypto on top.

3. **Plugin-identity trust.** When the configured identity
   references a plugin (e.g. `AGE-PLUGIN-YUBIKEY-…`), piggy hands
   control to the `age` crate, which invokes the named plugin
   binary. Operators MUST ensure the plugin binary on PATH is the
   intended one; piggy SHOULD provide a clear error message when
   a referenced plugin binary is missing.

4. **Format-confusion across recipient families.** Markl
   purpose+format validation prevents an `age_x25519_pub` payload
   from being mis-routed into the PIV path or vice versa (RFC 0002
   §8.3 plus the broadened RFC 0003 §4.2). The wire-format
   discriminator (`part-kind` byte) gives a second, redundant
   gate at the ebox layer; readers MUST reject a part whose
   kind+payload disagree (e.g. kind=Piv with an age-shaped 32-byte
   pubkey) instead of attempting a recovery fallback.

## Backwards Compatibility

- Existing v1 ebox files (PIV-only) MUST remain decryptable after
  this RFC lands. The Rust decrypt dispatcher MUST detect v1 by
  the version byte and dispatch accordingly.
- New encryptions to PIV-only recipient sets MAY continue to
  produce v1 ebox files for maximum compatibility with legacy
  tooling, OR MAY produce v2. The reference implementation
  produces v2 by default; the version is metadata, not a security
  boundary.
- Encrypting to a set that contains at least one age recipient
  MUST produce v2.

## Implementation Plan

1. **piggy-markl `PiggyRecipientV1` broadening.** **Done** —
   accepts `AgeX25519Pub` in addition to `PivyEcdhP256Pub`.
2. **`piggy-ids` parser broadening.** **Done** — file parser,
   `Recipient::new`, and `validate_recipient_shape` accept the
   broadened format set.
3. **`piggy-box::age_part_from_markl` skeleton.** **Done** —
   validates the markl input and returns
   `BoxError::UnsupportedRecipientFormat` pending wire-format
   work.
4. **Ebox v2 wire-format extension.** **TODO** — add part-kind
   discriminator; introduce `AgeBox` part variant; bump
   `EBOX_VERSION` from 3 to 4 (or add a v2 template variant
   alongside the existing v1 template). Touches
   `crates/piggy-box/src/template.rs` and `ebox.rs`.
5. **`AgeBox` primitive.** **TODO** — implement
   `crates/piggy-box/src/age_box.rs` with seal/unwrap via the
   `age` crate. Round-trip tests with known X25519 keypairs.
6. **`piggy-ids decrypt` subcommand.** **TODO** — Rust-side
   decrypt dispatcher that handles v1 + v2 ebox files, routing
   PIV parts through the existing path and age parts through
   `age::IdentityFile`.
7. **`piggy.sh` decrypt re-point.** **TODO** — swap
   `piggy_decrypt()` and `reencrypt_path()` from
   `pivy-box stream decrypt` to `piggy-ids decrypt`.
8. **`flake.nix`.** **TODO** — add `age-plugin-yubikey` to
   `runtimeDeps`.
9. **bats coverage.** **TODO** — new
   `zz-tests_bats/t0150-age-recipients.bats` exercising
   homogeneous-age, homogeneous-pivy (regression), and mixed
   stores.

## References

### Normative

- amarbel-llc/madder RFC 0002 — Markl ID Format
- piggy RFC 0002 — PIV ECDH Box wire format
- piggy RFC 0003 — `piggy-ids` File Format (broadened in §4.2)
- age v1 specification — <https://age-encryption.org/v1>

### Informative

- piggy#3 — Rust parity roadmap (umbrella tracker)
- piggy#26 — Sequenced work triage
- piggy#56/#57 — direct PC/SC paths in piggy-piv (precondition for
  removing the SSH-agent ECDH oracle from the decrypt path)
- `crates/piggy-box/src/recipients.rs` — markl → template router
- `crates/piggy-markl/src/purpose.rs` — `PiggyRecipientV1` accepted
  format set
