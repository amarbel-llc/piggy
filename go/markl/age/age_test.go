package age

import (
	"testing"

	markl "github.com/amarbel-llc/piggy/go/markl/pkgs/markl"
)

// ageSecFormat resolves the age_x25519_sec format and asserts it is a
// FormatSec (it is registered as a stub by markl_registrations and swapped
// to the real impl by this package's init()).
func ageSecFormat(t *testing.T) markl.FormatSec {
	t.Helper()
	format, err := markl.GetFormatOrError(markl.FormatIdAgeX25519Sec)
	if err != nil {
		t.Fatalf("GetFormatOrError(age_x25519_sec): %v", err)
	}
	fs, ok := format.(markl.FormatSec)
	if !ok {
		t.Fatalf("age_x25519_sec format is %T, want markl.FormatSec", format)
	}
	return fs
}

// TestAgeX25519SwappedAtInit verifies this package's init() swapped the
// real age machinery over the core's erroring age_x25519_sec stub: Generate
// returns a real 32-byte secret instead of the ErrAgeX25519NotConnected
// sentinel.
func TestAgeX25519SwappedAtInit(t *testing.T) {
	secret, err := ageSecFormat(t).Generate(nil)
	if err != nil {
		if markl.IsErrAgeX25519NotConnected(err) {
			t.Fatalf("age_x25519_sec still on the stub (swap did not fire): %v", err)
		}
		t.Fatalf("Generate: %v", err)
	}
	if len(secret) != 32 {
		t.Errorf("expected a 32-byte age secret, got %d bytes", len(secret))
	}
}

// TestAgeX25519GenerateThenIOWrapper exercises the full age secret-key
// machinery in pure software (no card, no agent): mint an identity, stamp
// it into a markl Id, and build its IOWrapper. Pins the
// Generate -> bech32(AGE-SECRET-KEY-) -> dewey/age round-trip the swap
// installs.
func TestAgeX25519GenerateThenIOWrapper(t *testing.T) {
	fs := ageSecFormat(t)

	secret, err := fs.Generate(nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdAgeX25519Sec, secret); err != nil {
		t.Fatalf("SetMarklId(age_x25519_sec): %v", err)
	}

	wrapper, err := fs.GetIOWrapper(id)
	if err != nil {
		t.Fatalf("GetIOWrapper: %v", err)
	}
	if wrapper == nil {
		t.Fatal("GetIOWrapper returned a nil wrapper")
	}
}
