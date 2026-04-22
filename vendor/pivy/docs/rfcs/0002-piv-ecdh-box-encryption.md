---
status: proposed
date: 2026-03-02
---

# PIV ECDH Box Encryption Format

## Abstract

This RFC specifies the PIV ECDH Box ("Box") encryption format used by pivy to
encrypt data to the holder of a PIV smart card's EC private key. A Box combines
ECDH key agreement on NIST P-curves with a hash-based KDF and an authenticated
stream cipher to produce a sealed, authenticated ciphertext that can only be
decrypted by the intended recipient's hardware token. This document defines the
cryptographic construction, the binary serialization format, and the behavioral
requirements for implementations that produce or consume Boxes.

## Introduction

pivy encrypts data to PIV smart card holders using a construction inspired by
libsodium's `crypto_box_seal`. A "sealed box" anonymously encrypts data such
that only the holder of a particular EC private key can recover it. Unlike
`crypto_box_seal`, pivy's construction uses NIST P-curves (required by PIV
hardware) rather than Curve25519, and uses SHA-512 rather than HSalsa20 as the
KDF.

The Box primitive serves as the foundation for:

- The `ecdh@joyent.com` and `ecdh-rebox@joyent.com` SSH agent extensions
  (specified in [RFC 0001])
- The Ebox (Enterprise Box) system for at-rest key management with threshold
  recovery
- The `pivy-box` command-line tool for file encryption
- Challenge-response recovery protocols for remote key operations

This specification covers the Box primitive only. The Ebox format, which
composes multiple Boxes with Shamir secret sharing for threshold recovery, is
documented separately in `docs/box-ebox-formats.adoc`. The SSH agent wire
protocol for Box operations is specified in [RFC 0001].

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

The default and RECOMMENDED cipher is `chacha20-poly1305`, which provides:

- 256-bit key
- 0-byte IV (implementation uses all-zero IV, but generates a random IV during
  sealing for forward-compatibility)
- 16-byte authentication tag appended to ciphertext

Other authenticated ciphers from the OpenSSH `cipher.c` registry MAY be used
(e.g., `aes256-gcm@openssh.com`). The cipher name is stored in the Box and
MUST be recognized by the recipient.

#### Key Derivation Function

The KDF is a single-pass hash of the ECDH shared secret, optionally
concatenated with a nonce:

```
key = Hash(shared_secret || nonce)     # V2
key = Hash(shared_secret)             # V1
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
cryptographically-secure random source (e.g., `arc4random_buf`).

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

5. **Generate IV.** Generate `ivlen` bytes of uniform random data using
   `arc4random_buf`.

6. **Pad plaintext.** Apply PKCS#7 padding: append `p` bytes of value `p`,
   where `p = blocksz - (len(P) % blocksz)` and `blocksz` is the cipher's
   block size. The padded plaintext length is always a multiple of `blocksz`.

7. **Encrypt.** Initialize the cipher with `K` and IV in encryption mode.
   Encrypt the padded plaintext, producing ciphertext `C` of length
   `len(padded_P) + authlen`, where `authlen` is the cipher's authentication
   tag length.

8. **Zero sensitive material.** Immediately zero `S`, `K`, `e`, and the
   padded plaintext from memory using `freezero` or equivalent.

9. **Serialize.** Write the Box in the binary format specified in
   Section 3.5.

Implementations MUST zero the shared secret, derived key, and ephemeral private
key from memory immediately after use. Implementations SHOULD use
`calloc_conceal` or equivalent allocation functions that prevent the memory
from being swapped to disk.

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
   length. If it does not, the implementation MUST return an error.

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
string8    iv                  initialization vector
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

1. Unseal the Box using `Q_old`'s private key (Section 3.4).
2. Create a new Box containing the recovered plaintext.
3. Seal the new Box to `Q_new` (Section 3.3).
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
that prevent sensitive data from being swapped to disk (`mlock`,
`calloc_conceal`, or equivalent). All sensitive buffers (shared secrets,
derived keys, plaintext) MUST be zeroed with `freezero`, `explicit_bzero`, or
equivalent before deallocation.

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

The cipher and KDF names use the OpenSSH algorithm registries
(`cipher.c`/`digest.c`). Implementations that use a different crypto library
MUST map these names to equivalent algorithms. The default `chacha20-poly1305`
and `sha512` are widely available.

## References

### Normative

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC 0001] "pivy-agent SSH Agent Protocol Extensions (`@joyent.com`)",
  docs/rfcs/0001-ssh-agent-extensions.md.

### Informative

- [PIV] NIST SP 800-73-4, "Interfaces for Personal Identity Verification"
- [libsodium sealed box] libsodium documentation, "Sealed boxes",
  https://doc.libsodium.org/public-key_cryptography/sealed_boxes
- [RFD 77] Joyent RFD 77, "Hardware-backed per-zone encryption in Triton and
  Manta"
- [PKCS#7] RFC 5652, "Cryptographic Message Syntax (CMS)", Section 6.3
  (padding)
