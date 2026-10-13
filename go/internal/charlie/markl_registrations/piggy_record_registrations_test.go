package markl_registrations_test

import (
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"

	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

// piggy RFC 0012 §4: a signed record's digest and its raw signature are
// each carried under their own purpose.
func TestPiggyRecordPurposesAcceptOnlyTheirFormats(t *testing.T) {
	for _, tc := range []struct {
		purposeId string
		formatId  string
		size      int
		accepted  bool
	}{
		{markl.PurposePiggyRecordDigestV1, markl.FormatIdHashSha256, 32, true},
		{markl.PurposePiggyRecordDigestV1, markl.FormatIdHashBlake2b256, 32, true},
		{markl.PurposePiggyRecordDigestV1, markl.FormatIdEcdsaP256Sig, 64, false},
		{markl.PurposePiggyRecordDigestV1, markl.FormatIdPigpenHeaderMac, 32, false},
		{markl.PurposePiggyRecordSigV1, markl.FormatIdEd25519Sig, 64, true},
		{markl.PurposePiggyRecordSigV1, markl.FormatIdEcdsaP256Sig, 64, true},
		{markl.PurposePiggyRecordSigV1, markl.FormatIdHashSha256, 32, false},
		{markl.PurposePiggyRecordSigV1, markl.FormatIdSshEcdsaNistp256Pub, 33, false},
	} {
		text := pigpenIdText(t, tc.purposeId, tc.formatId, tc.size)

		var id markl.Id
		err := id.Set(text)

		switch {
		case tc.accepted && err != nil:
			t.Errorf("%s@%s: rejected: %v", tc.purposeId, tc.formatId, err)
		case !tc.accepted && err == nil:
			t.Errorf("%s@%s: accepted, want a purpose/format mismatch", tc.purposeId, tc.formatId)
		}
	}
}

func TestPiggyRecordPurposesCarryTheirOwnTypes(t *testing.T) {
	if got := markl.GetPurpose(markl.PurposePiggyRecordDigestV1).GetPurposeType(); got != markl.PurposeTypePiggyRecordDigest {
		t.Errorf("piggy-record-digest-v1: type = %v, want PurposeTypePiggyRecordDigest", got)
	}

	if got := markl.GetPurpose(markl.PurposePiggyRecordSigV1).GetPurposeType(); got != markl.PurposeTypePiggyRecordSig {
		t.Errorf("piggy-record-sig-v1: type = %v, want PurposeTypePiggyRecordSig", got)
	}
}
