//go:build test

package markl_registrations_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// rfc0002FixturePath is the on-disk RFC 0002 conformance fixture,
// relative to this test package's directory. Both the generator
// (TestGenerateRFC0002Vectors, gated by the rfc0002_generate build tag)
// and the round-trip verifier (TestRFC0002VectorsRoundTrip) read this
// constant. Lives under testdata/ so the file is part of the Go module
// source tree.
//
// SCOPE (piggy#183 / #9): this is piggy's piggy-SCOPED reference
// fixture — every registered format (including the #86 ssh_ed25519_pub
// / ssh_ecdsa_nistp384_pub) crossed with PIGGY's own purposes only
// (piggy-piv_auth/sig/card_auth-v1, piggy-recipient-v1). go/markl
// registers only piggy's purposes (ADR 0006), so it cannot emit the
// dodder/madder/papi purpose vectors madder's cross-domain fixture
// carries. Assembling a single cross-domain superset (and re-sourcing
// crates/piggy-markl/testdata/0002-markl-id-format-vectors.json — the
// pinned madder copy the Rust replay uses — from piggy) is the open
// #187 RFC. Until then the two fixtures coexist deliberately.
const rfc0002FixturePath = "testdata/0002-markl-id-format-vectors.json"

// rfc0002Fixture is the on-disk JSON shape pinned by RFC 0002.
// Independent implementations load this same shape and verify each
// vector byte-for-byte.
type rfc0002Fixture struct {
	Vectors []rfc0002Vector        `json:"vectors"`
	Invalid []rfc0002InvalidVector `json:"invalid"`
}

// rfc0002Vector is one round-trip-conformant markl ID. Encoding
// PayloadHex (decoded to bytes) under Format and Purpose MUST produce
// Encoded; decoding Encoded MUST produce (Purpose, Format, payload).
type rfc0002Vector struct {
	Name       string `json:"name"`
	Purpose    string `json:"purpose,omitempty"`
	Format     string `json:"format"`
	PayloadHex string `json:"payload_hex"`
	Encoded    string `json:"encoded"`
}

// rfc0002InvalidVector is an encoded string the decoder MUST reject.
// Error names a structural failure category — the exact error type is
// implementation-specific but the rejection MUST happen.
type rfc0002InvalidVector struct {
	Name    string `json:"name"`
	Encoded string `json:"encoded"`
	Error   string `json:"error"`
}

func loadRFC0002Fixture(t *testing.T) rfc0002Fixture {
	t.Helper()

	bites, err := os.ReadFile(rfc0002FixturePath)
	if err != nil {
		t.Fatalf("read %s: %v", rfc0002FixturePath, err)
	}

	var fixture rfc0002Fixture
	if err := json.Unmarshal(bites, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	return fixture
}

func decodePayloadHex(t *testing.T, name, payloadHex string) []byte {
	t.Helper()

	out, err := hex.DecodeString(payloadHex)
	if err != nil {
		t.Fatalf("%s: decode payload_hex: %v", name, err)
	}

	return out
}
