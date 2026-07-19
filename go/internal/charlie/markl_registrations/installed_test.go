package markl_registrations_test

import (
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"

	// Blank-importing markl_registrations fires its init(), installing
	// piggy's native formats + purposes into the framework registry. This
	// IS the activation contract (ADR 0006): a consumer opts in by import.
	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

func TestPiggyFormatsInstalled(t *testing.T) {
	for _, fid := range []string{
		// the #86 additions this change lands
		markl.FormatIdSshEd25519Pub,
		markl.FormatIdSshEcdsaNistp384Pub,
		// piggy-recipient formats
		markl.FormatIdPivyEcdhP256Pub,
		markl.FormatIdAgeX25519Pub,
		// a few relocated software/stub formats, to confirm the moved
		// init() still installs the full set
		markl.FormatIdSshEcdsaNistp256Pub,
		markl.FormatIdEd25519Sig,
		markl.FormatIdNonceSec,
		markl.FormatIdAgeX25519Sec, // stub
	} {
		if _, err := markl.GetFormatOrError(fid); err != nil {
			t.Errorf("format %q not registered after blank-import: %v", fid, err)
		}
	}
}

func TestPiggyPurposesInstalled(t *testing.T) {
	// GetPurpose panics on an unregistered id, so a missing registration
	// fails the test loudly.
	for _, pid := range []string{
		markl.PurposePiggyRecipientV1,
		markl.PurposePiggyPivAuthV1,
		markl.PurposePiggyPivSigV1,
		markl.PurposePiggyPivCardAuthV1,
	} {
		if got := markl.GetPurpose(pid).GetPurposeType(); got != markl.PurposeTypePubKey {
			t.Errorf("purpose %q: type = %v, want PurposeTypePubKey", pid, got)
		}
	}
}
