package pigpen

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// pigpen-v1 crypto suite (RFC 0008 §4).

const (
	fileKeyLen      = 16 // RFC 0008 §4.1
	payloadNonceLen = 16 // RFC 0008 §4.5
	streamChunkSize = 64 * 1024
	streamTagLen    = chacha20poly1305.Overhead // 16

	infoPayload = "pigpen-v1 payload"
	infoHeader  = "pigpen-v1 header"
	infoP256    = "pigpen-v1 piv-p256"
	infoX25519  = "pigpen-v1 x25519"
)

// concat returns a fresh slice holding a followed by b, allocated once. Used
// to build the epk‖recipient HKDF salt without aliasing either input.
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}

func hkdf32(secret, salt []byte, info string) []byte {
	out, err := hkdf.Key(sha256.New, secret, salt, info, 32)
	if err != nil {
		// HKDF over 32 bytes of SHA-256 output never fails for these inputs.
		panic(err)
	}
	return out
}

// aeadSeal/aeadOpen wrap ChaCha20-Poly1305 with a 12-byte nonce.
func aeadSeal(key, nonce, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

func aeadOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

var zeroNonce = make([]byte, chacha20poly1305.NonceSize)

// --- X25519 wrap (RFC 0008 §4.4) -----------------------------------------

func wrapX25519(fileKey, recipientPub []byte, rng io.Reader) (blob []byte, err error) {
	curve := ecdh.X25519()
	esk, err := curve.GenerateKey(rng)
	if err != nil {
		return nil, err
	}
	rpk, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	shared, err := esk.ECDH(rpk)
	if err != nil {
		return nil, err
	}
	epk := esk.PublicKey().Bytes() // 32 bytes
	salt := concat(epk, recipientPub)
	kw := hkdf32(shared, salt, infoX25519)
	ct, err := aeadSeal(kw, zeroNonce, fileKey)
	if err != nil {
		return nil, err
	}
	return append(epk, ct...), nil // 32 + 32
}

func unwrapX25519(blob, recipientPub, recipientSec []byte) (fileKey []byte, err error) {
	if len(blob) != 32+fileKeyLen+streamTagLen {
		return nil, fmt.Errorf("pigpen: bad x25519 wrap length %d", len(blob))
	}
	epk, ct := blob[:32], blob[32:]
	curve := ecdh.X25519()
	sk, err := curve.NewPrivateKey(recipientSec)
	if err != nil {
		return nil, err
	}
	epub, err := curve.NewPublicKey(epk)
	if err != nil {
		return nil, err
	}
	shared, err := sk.ECDH(epub)
	if err != nil {
		return nil, err
	}
	salt := concat(epk, recipientPub)
	kw := hkdf32(shared, salt, infoX25519)
	return aeadOpen(kw, zeroNonce, ct)
}

// --- P-256 wrap (RFC 0008 §4.3) ------------------------------------------
//
// Encrypt-side is pure software. Decrypt-side delegates the ECDH to an
// ECDHOracle (a card via piggy-agent), so the slot-9D scalar never
// materialises and the WASM module does no PCSC I/O.

func wrapP256(fileKey, recipientCompressed []byte, rng io.Reader) (blob []byte, err error) {
	curve := ecdh.P256()
	esk, err := curve.GenerateKey(rng)
	if err != nil {
		return nil, err
	}
	rpk, err := p256PublicFromCompressed(recipientCompressed)
	if err != nil {
		return nil, err
	}
	shared, err := esk.ECDH(rpk) // 32-byte X-coordinate
	if err != nil {
		return nil, err
	}
	epkCompressed, err := p256Compress(esk.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	salt := concat(epkCompressed, recipientCompressed)
	kw := hkdf32(shared, salt, infoP256)
	ct, err := aeadSeal(kw, zeroNonce, fileKey)
	if err != nil {
		return nil, err
	}
	return append(epkCompressed, ct...), nil // 33 + 32
}

func unwrapP256(blob, recipientCompressed []byte, oracle ECDHOracle, self markIdentity) (fileKey []byte, err error) {
	if len(blob) != 33+fileKeyLen+streamTagLen {
		return nil, fmt.Errorf("pigpen: bad p256 wrap length %d", len(blob))
	}
	epkCompressed, ct := blob[:33], blob[33:]
	shared, err := oracle.ECDH(self, epkCompressed) // 32-byte X-coordinate from the card
	if err != nil {
		return nil, err
	}
	salt := concat(epkCompressed, recipientCompressed)
	kw := hkdf32(shared, salt, infoP256)
	return aeadOpen(kw, zeroNonce, ct)
}

// p256 point (de)compression via the stdlib elliptic helpers. RustCrypto's
// p256 crate does this natively; here we lean on elliptic.* which builds
// fine for wasm (deprecation warnings are not errors).

func p256Compress(uncompressed []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), uncompressed)
	if x == nil {
		return nil, errors.New("pigpen: invalid uncompressed P-256 point")
	}
	return elliptic.MarshalCompressed(elliptic.P256(), x, y), nil
}

func p256PublicFromCompressed(compressed []byte) (*ecdh.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return nil, errors.New("pigpen: invalid compressed P-256 point")
	}
	uncompressed := elliptic.Marshal(elliptic.P256(), x, y)
	return ecdh.P256().NewPublicKey(uncompressed)
}

// --- Payload STREAM (RFC 0008 §4.5) --------------------------------------

func sealPayload(fileKey, plaintext []byte, rng io.Reader) ([]byte, error) {
	nonce := make([]byte, payloadNonceLen)
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return nil, err
	}
	streamKey := hkdf32(fileKey, nonce, infoPayload)
	aead, err := chacha20poly1305.New(streamKey)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, nonce...)
	// Chunk the plaintext; emit at least one (final) chunk so empty
	// plaintext still produces a terminating tag (age parity).
	for i := 0; ; i++ {
		start := i * streamChunkSize
		end := start + streamChunkSize
		last := end >= len(plaintext)
		if end > len(plaintext) {
			end = len(plaintext)
		}
		chunk := plaintext[start:end]
		out = aead.Seal(out, streamNonce(uint64(i), last), chunk, nil)
		if last {
			break
		}
	}
	return out, nil
}

func openPayload(fileKey, payload []byte) ([]byte, error) {
	if len(payload) < payloadNonceLen {
		return nil, errors.New("pigpen: payload shorter than nonce")
	}
	nonce, body := payload[:payloadNonceLen], payload[payloadNonceLen:]
	streamKey := hkdf32(fileKey, nonce, infoPayload)
	aead, err := chacha20poly1305.New(streamKey)
	if err != nil {
		return nil, err
	}
	encChunk := streamChunkSize + streamTagLen
	var out []byte
	for i := 0; ; i++ {
		start := i * encChunk
		if start >= len(body) {
			// We consumed everything but never saw a "last" chunk.
			return nil, errors.New("pigpen: truncated payload (no final chunk)")
		}
		end := start + encChunk
		last := end >= len(body)
		if end > len(body) {
			end = len(body)
		}
		chunk := body[start:end]
		plain, err := aead.Open(nil, streamNonce(uint64(i), last), chunk, nil)
		if err != nil {
			// Retry as a non-final chunk only matters when our "last"
			// guess was wrong; with fixed-size chunking the guess is
			// exact except at the boundary, so a failure here is real.
			return nil, fmt.Errorf("pigpen: chunk %d auth failed: %w", i, err)
		}
		out = append(out, plain...)
		if last {
			break
		}
	}
	return out, nil
}

// streamNonce builds the 12-byte age STREAM nonce: 11-byte big-endian
// counter followed by a 1-byte last-chunk flag.
func streamNonce(counter uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], counter) // top 3 bytes stay zero (88-bit counter)
	if last {
		n[11] = 0x01
	}
	return n
}

// --- Header MAC (RFC 0008 §4.6) ------------------------------------------

func headerMAC(fileKey, canonicalHeader []byte) []byte {
	km := hkdf32(fileKey, nil, infoHeader)
	m := hmac.New(sha256.New, km)
	m.Write(canonicalHeader)
	return m.Sum(nil)
}

func randomFileKey(rng io.Reader) ([]byte, error) {
	fk := make([]byte, fileKeyLen)
	_, err := io.ReadFull(rng, fk)
	return fk, err
}

// defaultRand is the package CSPRNG; tests may inject a deterministic one.
var defaultRand io.Reader = rand.Reader
