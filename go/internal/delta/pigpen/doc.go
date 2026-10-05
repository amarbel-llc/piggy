// Package pigpen implements the pigpen encrypted-document format (piggy
// RFC 0008): a hyphence document (madder RFC 0001) carrying a markl-ID
// recipient set in its metadata section and an optional ciphertext
// payload in its body.
//
// The pigpen-v1 bytes are frozen. This package and the Rust crate
// crates/piggy-pigpen both replay the normative vector file
// docs/rfcs/0008-pigpen-vectors.txt (vectors_test.go), so what Seal
// writes and what ParseDocument and Open accept are pinned across the two.
//
// Limits a consumer should know:
//
//   - Seal and Open work on whole buffers; nothing streams. The format
//     suits small payloads such as a wrapped key.
//   - Only the inline payload form is implemented. An `@`-referenced
//     payload (RFC 0008 §2.5) is a parse error.
//   - There is no add-recipient or re-wrap: to change the recipients of a
//     sealed document, Open it and Seal again.
//   - Seal's rng argument is an entropy source, not a way to get
//     reproducible output (see Seal).
//
// It is deliberately self-contained:
//
//   - It frames documents with a minimal in-tree hyphence
//     encoder/decoder (hyphence.go) rather than importing madder's
//     canonical implementation, because the dewey → piggy → madder
//     layering forbids piggy from importing madder. See RFC 0008
//     "Compatibility".
//   - Recipient lines use the real markl codec (go/markl/pkgs/markl) and
//     the registered pivy_ecdh_p256_pub / age_x25519_pub formats.
//   - The pigpen-specific blobs (wrapped keys, header MAC) are markl IDs
//     in the registered pigpen_wrap_p256, pigpen_wrap_x25519 and
//     pigpen_header_mac formats (RFC 0008 §5), so the registry enforces
//     their sizes and the pigpen-wrap-v1 purpose pairing. A wrap lock
//     must carry that purpose and the wrap format matching its
//     recipient's family; the header MAC lock is bare.
//
// Crypto dependency choice (RFC 0008 §7): only stdlib crypto
// (crypto/ecdh, crypto/elliptic, crypto/hkdf, crypto/hmac, crypto/sha256)
// plus golang.org/x/crypto/chacha20poly1305 — all of which build under
// GOOS=js GOARCH=wasm and tinygo. It imports only the dep-light go/markl
// core, never the agent/age heavy sub-packages.
//
// Card-bound P-256 decryption is abstracted behind the ECDHOracle
// interface so a WASM host can supply the scalar multiplication via a
// syscall/js callback wired to piggy-agent.
package pigpen
