package markl_registrations_test

import (
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"

	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

// piggy RFC 0013 §8: the public key of a principal certified by a
// piggy-act-v1 certifying act, Ed25519 or P-256 in the SSH key form.
func TestPiggyPrincipalPubAcceptsOnlyItsFormats(t *testing.T) {
	for _, tc := range []struct {
		formatId string
		size     int
		accepted bool
	}{
		{markl.FormatIdSshEd25519Pub, 32, true},
		{markl.FormatIdSshEcdsaNistp256Pub, 33, true},
		{markl.FormatIdSshEcdsaNistp384Pub, 49, false},
		{markl.FormatIdEd25519Pub, 32, false},
		{markl.FormatIdPivyEcdhP256Pub, 33, false},
		{markl.FormatIdEd25519Sig, 64, false},
	} {
		text := pigpenIdText(t, markl.PurposePiggyPrincipalPubV1, tc.formatId, tc.size)

		var id markl.Id
		err := id.Set(text)

		switch {
		case tc.accepted && err != nil:
			t.Errorf("%s: rejected: %v", tc.formatId, err)
		case !tc.accepted && err == nil:
			t.Errorf("%s: accepted, want a purpose/format mismatch", tc.formatId)
		case tc.accepted:
			round, err := id.MarshalText()
			if err != nil {
				t.Errorf("%s: MarshalText: %v", tc.formatId, err)
			} else if string(round) != text {
				t.Errorf("%s: round-trip = %q, want %q", tc.formatId, round, text)
			}
		}
	}
}

func TestPiggyPrincipalPubIsAPubKey(t *testing.T) {
	if got := markl.GetPurpose(markl.PurposePiggyPrincipalPubV1).GetPurposeType(); got != markl.PurposeTypePubKey {
		t.Errorf("piggy-principal_pub-v1: type = %v, want PurposeTypePubKey", got)
	}
}
