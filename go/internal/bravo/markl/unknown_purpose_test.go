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
