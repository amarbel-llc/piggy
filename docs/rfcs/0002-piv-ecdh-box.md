---
status: adopted (piggy)
date: 2026-04-25
provenance: |
  Forked from vendor/pivy/docs/rfcs/0002-piv-ecdh-box-encryption.md
  (upstream "proposed" 2026-03-02). The vendored copy is historical
  reference; this file is the normative spec for piggy-box. Updated
  2026-04-25 by #36 to standardize on RFC 7539 ChaCha20-Poly1305
  (12-byte wire IV); earlier text described the OpenSSH variant with
  a 0-byte wire IV.
---

# PIV ECDH Box Encryption Format (piggy normative)

## Abstract

This RFC specifies the PIV ECDH Box ("Box") encryption format used by piggy to
encrypt data to the holder of a PIV smart card's EC private key. A Box combines
ECDH key agreement on NIST P-curves with a hash-based KDF and an authenticated
stream cipher to produce a sealed, authenticated ciphertext that can only be
decrypted by the intended recipient's hardware token. This document defines the
cryptographic construction, the binary serialization format, and the behavioral
requirements for implementations that produce or consume Boxes.

## Status and Provenance

This document is the normative wire-format spec for `piggy-box`. It was forked
on 2026-04-25 from `vendor/pivy/docs/rfcs/0002-piv-ecdh-box-encryption.md` so
that piggy's wire format is anchored independently of the vendored pivy C
implementation. The vendored copy is preserved as historical reference and may
diverge.

This revision was updated by #36 (2026-04-25) to standardize on RFC 7539 /
RFC 8439 ChaCha20-Poly1305 AEAD with a 12-byte wire IV (the AEAD nonce, fresh
per box). Earlier revisions described the OpenSSH `chacha20-poly1305@openssh.com`
variant with a 0-byte wire IV. Boxes sealed under that earlier revision are
not interoperable with this one. piggy is greenfield; no real-world data was
sealed under the earlier shape.

## Introduction

piggy encrypts data to PIV smart card holders using a construction inspired by
libsodium's `crypto_box_seal`. A "sealed box" anonymously encrypts data such
that only the holder of a particular EC private key can recover it. Unlike
`crypto_box_seal`, this construction uses NIST P-curves (required by PIV
hardware) rather than Curve25519, and uses SHA-512 rather than HSalsa20 as the
KDF.

The Box primitive serves as the foundation for:

- The `ecdh@joyent.com` and `ecdh-rebox@joyent.com` SSH agent extensions
  (specified in vendor/pivy/docs/rfcs/0001-ssh-agent-extensions.md)
- The Ebox (Enterprise Box) system for at-rest key management with threshold
  recovery
- The `pivy-box` command-line tool for file encryption
- Challenge-response recovery protocols for remote key operations

This specification covers the Box primitive only. The Ebox format, which
composes multiple Boxes with Shamir secret sharing for threshold recovery, is
documented separately in `vendor/pivy/docs/rfcs/0003-box-ebox-formats.adoc`.
The SSH agent wire protocol for Box operations is specified in
`vendor/pivy/docs/rfcs/0001-ssh-agent-extensions.md`.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### Overview

A Box encrypts an arbitrary plaintext to a recipient identified by an ECDSA
public key. The construction proceeds as follows:

1. Generate an ephemeral ECDSA key pair on the same curve as the recipient key.
2. Compute an ECDH shared secret between the ephemeral private key and the
   recipient public key.
3. Derive a symmetric key by hashing the shared secret (and optionally a nonce).
4. Encrypt the plaintext with an authenticated cipher using the derived key.
5. Serialize the ephemeral public key, ciphertext, and metadata into the Box
   binary format.

Decryption reverses this: the recipient performs ECDH between their private key
and the stored ephemeral public key, derives the same symmetric key, and
decrypts the ciphertext.

When the recipient key is held on a PIV smart card, the ECDH step is performed
by the card via the `GENERAL AUTHENTICATE` command (ISO 7816-4 INS `0x87`).
When the recipient key is available in software, ECDH is performed using
OpenSSL.

### Versioning

Boxes carry a version number that determines which fields are present:

| Version | Value  | Description                    |
|---------|--------|--------------------------------|
| V1      | `0x01` | Original format, no nonce      |
| V2      | `0x02` | Adds nonce field for KDF input |

Implementations MUST support both V1 and V2 for deserialization.
Implementations MUST produce V2 when creating new Boxes.

### Cryptographic Algorithms

#### Elliptic Curves

The ephemeral and recipient keys MUST be ECDSA keys on the same NIST P-curve.
Supported curves:

| Curve    | Field size | SSH name     |
|----------|------------|--------------|
| P-256    | 256 bits   | `nistp256`   |
| P-384    | 384 bits   | `nistp384`   |
| P-521    | 521 bits   | `nistp521`   |

Implementations MUST support P-256. Implementations SHOULD support P-384 and
P-521.

The curve is dictated by the recipient's PIV key slot; the ephemeral key MUST
be generated on the same curve.

#### Cipher

The cipher MUST be an authenticated encryption algorithm (AEAD or equivalent).
Implementations MUST NOT use non-authenticated ciphers.

The default and RECOMMENDED cipher is `chacha20-poly1305`, which in this spec
denotes the IETF construction defined in [RFC 7539] / [RFC 8439]:

- 256-bit key
- 12-byte AEAD nonce, supplied per box and serialized verbatim into the wire
  `iv` field. Implementations MUST generate a fresh 12 bytes of uniform random
  data per box from a cryptographically-secure source.
- Empty associated data
- 16-byte Poly1305 authentication tag appended to the ciphertext

Within this spec, the wire string `chacha20-poly1305` denotes RFC 7539
unconditionally. It is NOT the OpenSSH `chacha20-poly1305@openssh.com`
construction, which uses two ChaCha20 keys, a sequence-number-derived nonce,
and a 0-byte wire IV. The two are incompatible.

Other authenticated ciphers MAY be used in future revisions. Each MUST
advertise its own wire `cipher` string and define its own wire `iv` length;
the recipient MUST reject any unrecognized cipher name.

#### Key Derivation Function

The KDF is a single-pass hash of the ECDH shared secret, optionally
concatenated with a nonce:

```
key = Hash(shared_secret || nonce)     # V2
key = Hash(shared_secret)              # V1
```

Where `||` denotes byte string concatenation.

The default and RECOMMENDED KDF is `sha512` (SHA-512, producing 512 bits of
output). The KDF digest MUST produce output at least as long as the cipher's
key length. If the digest output exceeds the key length, the first `keylen`
bytes are used.

The KDF name is an OpenSSH `digest.c` algorithm name stored in the Box.

#### Nonce

V2 Boxes include a random nonce that is mixed into the KDF. The nonce MUST be
at least 128 bits (16 bytes) of uniform random data. Implementations producing
V2 Boxes MUST generate a fresh 16-byte random nonce using a
cryptographically-secure random source.

V1 Boxes have no nonce. When decrypting a V1 Box, the KDF input is the shared
secret alone.

The nonce is critical for security when the same recipient key is used with
a shared ephemeral key (as in the Ebox format). In standalone Boxes, where each
Box has a unique ephemeral key, the nonce provides defense-in-depth.

### Sealing (Encryption)

To seal a Box with plaintext `P` and recipient public key `Q`:

1. **Generate ephemeral key pair.** Generate an ECDSA key pair `(e, E)` on the
   same curve as `Q`, where `e` is the private key and `E` is the public key.

2. **Compute shared secret.** Calculate `S = ECDH(e, Q)`, producing a raw
   shared secret of field-element size.

3. **Generate nonce.** (V2 only) Generate 16 bytes of uniform random data `N`.

4. **Derive symmetric key.** Compute `K = Hash(S || N)` (V2) or `K = Hash(S)`
   (V1). Truncate `K` to the cipher's key length.

5. **Generate IV.** For `chacha20-poly1305`, generate 12 bytes of uniform
   random data `IV` from a cryptographically-secure source. `IV` is both the
   AEAD nonce passed to the cipher and the value serialized verbatim into the
   wire `iv` field. Implementations MUST NOT reuse an `IV` across boxes
   sealed under the same KDF-derived key.

6. **Pad plaintext.** Apply PKCS#7 padding: append `p` bytes of value `p`,
   where `p = blocksz - (len(P) % blocksz)` and `blocksz` is the cipher's
   block size. The padded plaintext length is always a multiple of `blocksz`.

7. **Encrypt.** Initialize the cipher with `K` and IV in encryption mode.
   Encrypt the padded plaintext, producing ciphertext `C` of length
   `len(padded_P) + authlen`, where `authlen` is the cipher's authentication
   tag length.

8. **Zero sensitive material.** Immediately zero `S`, `K`, `e`, and the
   padded plaintext from memory.

9. **Serialize.** Write the Box in the binary format specified below.

Implementations MUST zero the shared secret, derived key, and ephemeral private
key from memory immediately after use. Implementations SHOULD use memory
allocation functions that prevent the memory from being swapped to disk.

### Unsealing (Decryption)

To unseal a Box:

1. **Deserialize.** Parse the binary format, extracting the ephemeral public
   key `E`, cipher name, KDF name, nonce (V2), IV, and ciphertext.

2. **Compute shared secret.** Calculate `S = ECDH(privkey, E)`, where
   `privkey` is either:
   - The PIV smart card's private key (via `GENERAL AUTHENTICATE`), or
   - A software private key (via `ECDH_compute_key`).

3. **Derive symmetric key.** Compute `K = Hash(S || N)` (V2) or `K = Hash(S)`
   (V1). Truncate to the cipher's key length.

4. **Validate IV length.** The IV length MUST match the cipher's expected IV
   length. For `chacha20-poly1305` this is 12 bytes. If it does not match, the
   implementation MUST return a `LengthError`.

5. **Validate ciphertext length.** The ciphertext MUST be at least
   `authlen + blocksz` bytes long. If it is not, the implementation MUST
   return an error.

6. **Decrypt.** Initialize the cipher with `K` and IV in decryption mode.
   Decrypt `len(C) - authlen` bytes of ciphertext. The cipher MUST verify the
   authentication tag; if verification fails, the implementation MUST return an
   error and zero all decrypted material.

7. **Remove padding.** Read the last byte of the decrypted data as the padding
   value `p`. Verify that `1 <= p <= blocksz` and that the last `p` bytes all
   equal `p`. If padding validation fails, the implementation MUST return an
   error and zero all decrypted material.

8. **Zero sensitive material.** Immediately zero `S` and `K` from memory.

### Binary Serialization Format

#### Primitive Types

The Box format uses OpenSSH wire format primitives:

| Type       | Encoding                                                        |
|------------|-----------------------------------------------------------------|
| `uint8`    | Single byte                                                     |
| `string8`  | `uint8` length prefix followed by that many raw bytes           |
| `cstring8` | `string8` containing a NUL-terminated C string                  |
| `string`   | `uint32` (big-endian) length prefix followed by that many bytes |
| `eckey8`   | `string8` containing a compressed EC point (`0x02`/`0x03`)      |

#### Box Layout

```
uint8[2]   magic               always 0xB0, 0xC5
uint8      version             0x01 (V1) or 0x02 (V2)
uint8      guid_slot_valid     0x00 (false) or 0x01 (true)
string8    guid                16 bytes if valid, 0 bytes if not
uint8      slot_id             PIV slot (e.g., 0x9D); 0x00 if not valid
cstring8   cipher              e.g., "chacha20-poly1305"
cstring8   kdf                 e.g., "sha512"
string8    nonce               V2 only; at least 16 bytes (omitted in V1)
cstring8   curve               e.g., "nistp256"
eckey8     recipient_pubkey    compressed EC point
eckey8     ephemeral_pubkey    compressed EC point
string8    iv                  initialization vector (12 bytes for chacha20-poly1305)
string     ciphertext_and_tag  ciphertext with appended authentication tag
```

When `guid_slot_valid` is `0x00`, the `guid` field MUST be encoded as a
zero-length `string8` (a single `0x00` byte for the length) and `slot_id` MUST
be `0x00`. When `guid_slot_valid` is `0x01`, the `guid` field MUST be exactly
16 bytes.

The `nonce` field MUST be present if and only if `version >= 0x02`.

The `ciphertext_and_tag` field uses a `string` (32-bit length prefix), not
`string8`, because ciphertexts may exceed 255 bytes.

#### GUID and Slot Metadata

The GUID is the PIV CHUID UUID of the token that holds the recipient's private
key. The slot ID is the PIV key reference value (e.g., `0x9D` for Key
Management). These fields are advisory — they allow implementations to quickly
locate the correct hardware token without trying all available devices.

A Box MAY be created without GUID/slot metadata (e.g., when encrypting to a
key that is not on any known token). In this case, `guid_slot_valid` MUST be
`0x00`.

#### Magic Number Validation

Implementations MUST verify that the first two bytes are `0xB0`, `0xC5` before
parsing. If the magic number does not match, the implementation MUST return a
`MagicError`.

#### Version Validation

Implementations MUST reject versions outside the range `[0x01, 0x02]` with a
`VersionError`.

### Rebox Operation

Reboxing decrypts a Box and re-encrypts the plaintext to a new recipient in a
single atomic operation. This is used to transfer encrypted data between tokens
without exposing the plaintext outside the agent process.

To rebox a Box from recipient `Q_old` to recipient `Q_new`:

1. Unseal the Box using `Q_old`'s private key.
2. Create a new Box containing the recovered plaintext.
3. Seal the new Box to `Q_new`.
4. Zero the plaintext from memory immediately after sealing.

Implementations MUST NOT expose the intermediate plaintext to callers. When
performed via the SSH agent, the plaintext MUST never leave the agent process
boundary.

### Error Types

| Error type          | Condition                                            |
|---------------------|------------------------------------------------------|
| `MagicError`        | First two bytes are not `0xB0`, `0xC5`               |
| `VersionError`      | Unsupported version number                           |
| `CurveError`        | EC curve not supported                               |
| `BadAlgorithmError` | Cipher or KDF not recognized or not supported        |
| `LengthError`       | IV or ciphertext length is invalid for the cipher    |
| `PaddingError`      | PKCS#7 padding validation failed after decryption    |
| `BoxKeyError`       | ECDH operation failed (e.g., PIV card communication) |
| `ArgumentError`     | Keys are not ECDSA or are on different curves        |

## Security Considerations

**Authenticated encryption.** The Box format REQUIRES authenticated ciphers.
The authentication tag prevents ciphertext tampering; any modification to the
ciphertext or tag will cause decryption to fail. Implementations MUST NOT
support non-authenticated ciphers without adding a separate HMAC, and this
specification does not define such an extension.

**ECDH on NIST curves.** The construction is constrained to NIST P-curves by
PIV hardware requirements. P-256 provides approximately 128 bits of security,
P-384 approximately 192 bits, and P-521 approximately 256 bits. The security
level of a Box is bounded by the curve used.

**KDF simplicity.** The KDF is a single hash invocation rather than a standard
KDF construction like HKDF. This is acceptable because the ECDH output has
sufficient entropy (it is a random group element) and the hash output is used
only as a symmetric key, never published. The construction does not require
resistance to length extension attacks. However, implementations extending this
specification SHOULD consider HKDF for new algorithm negotiation.

**Nonce criticality in Ebox context.** When Boxes share an ephemeral key (as
in the Ebox format), the nonce is the sole source of key uniqueness. In this
context, nonce reuse completely compromises the encryption. Standalone Boxes
with unique ephemeral keys are not vulnerable to nonce reuse in the same way,
but the nonce still provides defense-in-depth.

**Ephemeral key management.** The ephemeral private key MUST be zeroed
immediately after computing the ECDH shared secret. Failure to do so would
allow an attacker with memory access to decrypt the Box without the recipient's
private key.

**PKCS#7 padding oracle.** The authentication tag is verified before padding is
examined, so a padding oracle attack is not possible when using authenticated
ciphers. If a future extension adds non-authenticated ciphers, it MUST add
HMAC verification before padding removal.

**Memory protection.** Implementations SHOULD use memory allocation functions
that prevent sensitive data from being swapped to disk. All sensitive buffers
(shared secrets, derived keys, plaintext) MUST be zeroed before deallocation.

**No key confirmation.** The Box format does not include a key confirmation
step. If the wrong private key is used for ECDH, the decryption will produce
garbage, but the authentication tag will detect this and return an error. The
error message MUST NOT distinguish between "wrong key" and "tampered
ciphertext" to prevent oracle attacks.

**Compressed EC points.** The serialization format uses compressed EC points
(`eckey8`) for compactness. Implementations MUST correctly handle point
decompression. Invalid points MUST be rejected.

## Compatibility

V1 Boxes (without nonce) are a legacy format. Implementations MUST continue to
support V1 deserialization for backwards compatibility. Implementations MUST
produce V2 Boxes with a random nonce when creating new Boxes.

The KDF name `sha512` follows the OpenSSH `digest.c` registry. The cipher name
`chacha20-poly1305` is reused from that registry's spelling but denotes the
RFC 7539 / RFC 8439 construction in this spec, NOT the OpenSSH
`chacha20-poly1305@openssh.com` construction. Implementations using a
different crypto library MUST map `chacha20-poly1305` to RFC 7539 specifically.

This revision (#36, 2026-04-25) is wire-incompatible with two earlier shapes:

- The vendored pivy `pivy-box` C tool (and pivy-derived libraries) produces
  `chacha20-poly1305@openssh.com`-flavoured boxes with a 0-byte wire IV.
- piggy at `f8ab33f`..`be83aeb` produced 0-byte-IV boxes for the same reason.

Implementations conforming to this revision MUST reject any v2 Box whose
`chacha20-poly1305` `iv` field is not exactly 12 bytes.

## Conformance

Conforming implementations MUST reproduce, byte-for-byte, every wire vector in
Appendix A given the listed inputs. Vectors A.1–A.3 are replayed by the test
module `crates/piggy-box/src/piv_box.rs::tests::rfc0002_vectors`. Drift between
this appendix and that test module is a CI failure.

## Appendix A: Test Vectors

Each vector pins all inputs that feed the wire (recipient private scalar,
ephemeral private scalar, KDF nonce, cipher IV, plaintext, GUID/slot) so that
`PivBox::seal_offline_with_ephemeral_and_pinned_random` produces a known-byte
output. Private scalars are interpreted as big-endian integers per RFC 5915 §3
(the recipient private key is `BigNum::from_slice(scalar)` interpreted
MSB-first).

### A.1 — P-256, no GUID/slot, empty plaintext

Smallest realistic box: empty plaintext PKCS#7-padded to one 16-byte block,
plus the 16-byte AEAD tag. Total wire length 174 bytes.

**Inputs**

```
curve              = nistp256
recipient_priv     = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ephemeral_priv     = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
kdf_nonce          = a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
cipher_iv          = d0d1d2d3d4d5d6d7d8d9dadb
plaintext          = (empty)
guid_slot          = absent
```

**Expected wire bytes** (hex, 174 bytes)

```
b0c5020000001163686163686132302d706f6c79313330350673686135313210
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf086e697374703235362102515c3d6eb9
e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f21031f1401
46bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e0cd0d1
d2d3d4d5d6d7d8d9dadb000000208dd88e114913dc759f69c7590b369008a754
ee2d0528e4386c46661631e7fbfd
```

Replayed by `tests::rfc0002_vectors::vector_a_1`.

### A.2 — P-256, GUID + slot, plaintext "hello"

Exercises the `guid_slot_valid = 0x01` branch of the wire format and a
non-empty payload (5 bytes of plaintext + 11 bytes PKCS#7 padding + 16-byte
tag). Total wire length 190 bytes.

**Inputs**

```
curve              = nistp256
recipient_priv     = 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f
ephemeral_priv     = 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
kdf_nonce          = b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
cipher_iv          = e0e1e2e3e4e5e6e7e8e9eaeb
plaintext          = "hello"   (5 bytes ASCII: 68 65 6c 6c 6f)
guid               = 000102030405060708090a0b0c0d0e0f
slot               = 0x9D
```

**Expected wire bytes** (hex, 190 bytes)

```
b0c5020110000102030405060708090a0b0c0d0e0f9d1163686163686132302d
706f6c79313330350673686135313210b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
086e6973747032353621038e71ca9d7a62917be7f0db9896b47bf9b91c8b8662
8eed55d47fe750e65e5bcb21038ed57ec2b8f5e75e9192327b51e5661c87c8e5
db0170721309a517fc6e1046b10ce0e1e2e3e4e5e6e7e8e9eaeb00000020f0a8
350c88929a3f68dd0d5a74b5d339c5d3624f6b5be4a3b7aa86eac9e0e0db
```

Replayed by `tests::rfc0002_vectors::vector_a_2`.

### A.3 — P-384, no GUID/slot, plaintext "piggy rfc0002 vector A.3"

Exercises the second supported curve. Compressed P-384 points are 49 bytes
each (vs. 33 for P-256), and the 24-byte ASCII plaintext PKCS#7-pads to two
16-byte blocks. Total wire length 222 bytes.

**Inputs**

```
curve              = nistp384
recipient_priv     = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                     202122232425262728292a2b2c2d2e2f30
ephemeral_priv     = 3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
                     505152535455565758595a5b5c5d5e5f60
kdf_nonce          = c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
cipher_iv          = f0f1f2f3f4f5f6f7f8f9fafb
plaintext          = "piggy rfc0002 vector A.3"   (24 bytes ASCII)
guid_slot          = absent
```

**Expected wire bytes** (hex, 222 bytes)

```
b0c5020000001163686163686132302d706f6c79313330350673686135313210
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf086e697374703338343103c76f2283dd
a95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0
b97499aef2f0ab313fa0283103db89855d1980b2aacdec0752249bea9e0630c1
6b69c095f6c752b2547b520d8109511d908881491780594f03cfee8a0a0cf0f1
f2f3f4f5f6f7f8f9fafb0000003001ed7daba77156dd87a22208274ce93706f3
261619acf1f52c8c3d12e71380f30fe5091f18b17ccdfbcefe2a15d0d6df
```

Replayed by `tests::rfc0002_vectors::vector_a_3`.

## References

### Normative

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC 7539] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF
  Protocols", RFC 7539, May 2015. (Obsoleted by RFC 8439.)
- [RFC 8439] Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF
  Protocols", RFC 8439, June 2018.

### Informative

- vendor/pivy/docs/rfcs/0001-ssh-agent-extensions.md — pivy SSH agent protocol
  extensions.
- vendor/pivy/docs/rfcs/0003-box-ebox-formats.adoc — Ebox format that composes
  multiple Boxes with Shamir secret sharing.
- [PIV] NIST SP 800-73-4, "Interfaces for Personal Identity Verification".
- [libsodium sealed box] libsodium documentation, "Sealed boxes",
  https://doc.libsodium.org/public-key_cryptography/sealed_boxes
- [PKCS#7] RFC 5652, "Cryptographic Message Syntax (CMS)", Section 6.3
  (padding).
