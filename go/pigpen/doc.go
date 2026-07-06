// Package pigpen is a prototype of the pigpen encrypted-document format
// (piggy RFC 0008): a hyphence document (madder RFC 0001) carrying a
// markl-ID recipient set in its metadata section and an optional
// ciphertext payload in its body.
//
// This is a SKETCH, not a production path. It exists to validate the
// RFC 0008 wire model and to prove the format is WASM-buildable. It is
// deliberately self-contained:
//
//   - It frames documents with a minimal in-tree hyphence
//     encoder/decoder (hyphence.go) rather than importing madder's
//     canonical implementation, because the dewey → piggy → madder
//     layering forbids piggy from importing madder. See RFC 0008
//     "Compatibility".
//   - Recipient lines use the real markl codec (go/markl/pkgs/markl) and
//     the registered pivy_ecdh_p256_pub / age_x25519_pub formats.
//   - The pigpen-specific blobs (wrapped keys, header MAC, payload
//     digest) are encoded with the blech32 codec directly under their
//     own HRPs (pigpen_wrap_p256, pigpen_wrap_x25519, pigpen_header_mac).
//     RFC 0008 §5 registers these as real markl formats at cutover; the
//     prototype uses the codec without mutating the gated registry.
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
