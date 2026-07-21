//go:build test

package markl

import (
	"strings"
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

// A purpose value containing whitespace is LEGAL and round-trips
// through the quoted spelling (RFC 0011 §2.1, madder#273 ruling 2).
//
// This inverts the pre-2026-07-20 behaviour. Formerly markl's text form
// had no quoting mechanism at all, so a space-bearing purpose had no
// spelling and SetPurposeId rejected it outright (the superseded
// TestSetPurposeId_RejectsWhitespace, replaced by this test). Ruling 1
// narrowed the BARE charset to [a-zA-Z0-9_/-] and ruling 2 added the
// quoted alternative, which is what keeps such values reachable: the
// value validator now bans only '@' (§2.2), and the marshaller decides
// the spelling.
func TestSetPurposeId_AcceptsWhitespaceAndSpellsItQuoted(t *testing.T) {
	payload := make([]byte, 32)

	var id Id
	if err := id.SetMarklId(FormatIdHashSha256, payload); err != nil {
		t.Fatalf("SetMarklId: %v", err)
	}

	if err := id.SetPurposeId("my thing"); err != nil {
		t.Fatalf(`SetPurposeId("my thing"): %v`, err)
	}

	encoded, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	if !strings.HasPrefix(string(encoded), `"my thing"@`) {
		t.Errorf(
			"a purpose outside the bare charset must be spelled quoted, got %q",
			string(encoded),
		)
	}

	var decoded Id
	if err := decoded.UnmarshalText(encoded); err != nil {
		t.Fatalf("UnmarshalText(%q): %v", string(encoded), err)
	}

	if got := decoded.GetPurposeId(); got != "my thing" {
		t.Errorf("purpose round-trip: got %q, want %q", got, "my thing")
	}
}

// A purpose outside the bare charset MUST NOT be spelled bare. The
// quoted form above is the only spelling; an unquoted slot containing a
// space is a decode error, so ruling 1's narrowing has teeth on the
// wire-parse path and not merely in the marshaller's choice of
// spelling.
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
