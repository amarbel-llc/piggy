//go:build test

package markl

import (
	"testing"
)

// testPurposeSig is a file-local registered purpose standing in for
// madder's bravo-level test fixtures (unported here — go/markl registers
// no purposes in this framework package, so the strictness half of the
// madder#255 contract needs a registration to exercise). Restricted to
// ed25519_sig so an sha256 pairing is incompatible.
var testPurposeSig = RegisterPurpose(RegisterPurposeOpts{
	Id:        "piggy-test-unknown_purpose-sig-v1",
	Type:      PurposeTypeDodderObjectSig,
	FormatIds: []string{FormatIdEd25519Sig},
})

// Ids whose purpose is not registered must decode and round-trip with the
// purpose carried opaquely (madder#255): every markl-id parse surface in
// the binary (CLI args, blob API paths, config TOML, archive indexes)
// needs only the format to route bytes. Purpose semantics stay strict —
// GetPurpose still panics for unknown ids — so only the (purpose, format)
// compatibility check is skipped when the purpose has no registration.
func TestSetMarklId_UnknownPurposeAcceptedOpaquely(t *testing.T) {
	const unknownPurpose = "test-unregistered-purpose-v1"

	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}

	var id Id
	if err := id.SetPurposeId(unknownPurpose); err != nil {
		t.Fatalf("SetPurposeId: %v", err)
	}
	if err := id.SetMarklId(FormatIdHashSha256, payload); err != nil {
		t.Fatalf("SetMarklId with unknown purpose: %v", err)
	}

	encoded, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var decoded Id
	if err := decoded.Set(string(encoded)); err != nil {
		t.Fatalf("Set(%q): %v", encoded, err)
	}

	if got := decoded.GetPurposeId(); got != unknownPurpose {
		t.Errorf("decoded purpose: got %q, want %q", got, unknownPurpose)
	}
	if got := decoded.GetMarklFormat().GetMarklFormatId(); got != FormatIdHashSha256 {
		t.Errorf("decoded format: got %q, want %q", got, FormatIdHashSha256)
	}
}

// The lenient-unknown path must not weaken validation for registered
// purposes: a registered purpose with an incompatible format is still
// rejected with an error.
func TestSetMarklId_RegisteredPurposeIncompatibleFormatRejected(t *testing.T) {
	payload := make([]byte, 32)

	var id Id
	if err := id.SetPurposeId(testPurposeSig.id); err != nil {
		t.Fatalf("SetPurposeId: %v", err)
	}
	if err := id.SetMarklId(FormatIdHashSha256, payload); err == nil {
		t.Errorf(
			"SetMarklId(%q) under registered purpose %q should error, got nil",
			FormatIdHashSha256, testPurposeSig.id,
		)
	}
}

// General/unregistered purposes admit the general identifier charset
// (piggy#219), including interior `/` — the shape hyphence RFC 0003 uses
// to spell an object-id-shaped purpose atomically joined to its pinned
// digest (`one/uno@blake2b256-...`). No registration and no format
// constraint apply; only the RFC 0002 §2.1 purpose-char charset
// (validatePurposeCharset) does.
func TestSetMarklId_GeneralIdentifierPurposeWithSlash(t *testing.T) {
	const purpose = "one/uno"

	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}

	var id Id
	if err := id.SetPurposeId(purpose); err != nil {
		t.Fatalf("SetPurposeId(%q): %v", purpose, err)
	}
	if err := id.SetMarklId(FormatIdHashBlake2b256, payload); err != nil {
		t.Fatalf("SetMarklId under general purpose %q: %v", purpose, err)
	}

	encoded, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var decoded Id
	if err := decoded.Set(string(encoded)); err != nil {
		t.Fatalf("Set(%q): %v", encoded, err)
	}

	if got := decoded.GetPurposeId(); got != purpose {
		t.Errorf("decoded purpose: got %q, want %q", got, purpose)
	}
	if got := decoded.GetMarklFormat().GetMarklFormatId(); got != FormatIdHashBlake2b256 {
		t.Errorf("decoded format: got %q, want %q", got, FormatIdHashBlake2b256)
	}
}

// A short, bare general identifier (e.g. a hyphence type name like `md`)
// is likewise legal as a purpose — the ruled `md@<digest>` shape (type
// pinned to its definition).
func TestSetMarklId_ShortGeneralIdentifierPurpose(t *testing.T) {
	const purpose = "md"

	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i + 1)
	}

	var id Id
	if err := id.SetPurposeId(purpose); err != nil {
		t.Fatalf("SetPurposeId(%q): %v", purpose, err)
	}
	if err := id.SetMarklId(FormatIdHashBlake2b256, payload); err != nil {
		t.Fatalf("SetMarklId under general purpose %q: %v", purpose, err)
	}

	encoded, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var decoded Id
	if err := decoded.Set(string(encoded)); err != nil {
		t.Fatalf("Set(%q): %v", encoded, err)
	}

	if got := decoded.GetPurposeId(); got != purpose {
		t.Errorf("decoded purpose: got %q, want %q", got, purpose)
	}
}

// A purpose MUST NOT contain the literal `@`, registered or not — it is
// markl's own purpose/digest join rune (RFC 0002 §2.1, §4 step 1), never
// content. This holds regardless of registration status: the constraint
// is structural, not a registry policy.
func TestSetPurposeId_RejectsAtSign(t *testing.T) {
	if err := (&Id{}).SetPurposeId("a@b"); err == nil {
		t.Error(`SetPurposeId("a@b") should error, got nil`)
	}
}

// A purpose MUST NOT contain whitespace: markl's bare text form has no
// quoting mechanism (RFC 0002 §2.2), so a purpose value containing a
// space cannot round-trip through it. Embedding grammars (trellis,
// hyphence) that need to carry such a value quote the purpose slot on
// their own side before it ever reaches markl.
func TestSetPurposeId_RejectsWhitespace(t *testing.T) {
	if err := (&Id{}).SetPurposeId("my thing"); err == nil {
		t.Error(`SetPurposeId("my thing") should error, got nil`)
	}
}

// The whitespace rejection applies uniformly through the text-form
// decoder too, not just the direct SetPurposeId API: a wire string whose
// purpose slot contains a space must fail to decode.
func TestId_UnmarshalText_RejectsWhitespaceInPurpose(t *testing.T) {
	payload := make([]byte, 32)

	var good Id
	if err := good.SetMarklId(FormatIdHashSha256, payload); err != nil {
		t.Fatalf("SetMarklId: %v", err)
	}
	encoded, err := good.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	bad := "my thing@" + string(encoded)

	var decoded Id
	if err := decoded.UnmarshalText([]byte(bad)); err == nil {
		t.Errorf("UnmarshalText(%q) should error, got nil", bad)
	}
}
