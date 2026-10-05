package markl_registrations_test

import (
	"bytes"
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"

	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

// RFC 0008 §5: the pigpen wrap and header-MAC blobs are fixed-size opaque
// formats, each carried under its own purpose.
var pigpenFormatSizes = []struct {
	formatId string
	size     int
}{
	{markl.FormatIdPigpenWrapP256, 65},
	{markl.FormatIdPigpenWrapX25519, 64},
	{markl.FormatIdPigpenHeaderMac, 32},
}

func pigpenPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i + 1)
	}
	return payload
}

func TestPigpenFormatsRoundTripAtTheirFixedSize(t *testing.T) {
	for _, tc := range pigpenFormatSizes {
		var id markl.Id
		if err := id.SetMarklId(tc.formatId, pigpenPayload(tc.size)); err != nil {
			t.Fatalf("%s: SetMarklId at %d bytes: %v", tc.formatId, tc.size, err)
		}

		var parsed markl.Id
		if err := parsed.Set(id.StringWithFormat()); err != nil {
			t.Fatalf("%s: reparse %q: %v", tc.formatId, id.StringWithFormat(), err)
		}

		if got := parsed.GetMarklFormat().GetMarklFormatId(); got != tc.formatId {
			t.Errorf("%s: reparsed format = %q", tc.formatId, got)
		}

		if !bytes.Equal(parsed.GetBytes(), pigpenPayload(tc.size)) {
			t.Errorf("%s: payload changed across a text round trip", tc.formatId)
		}
	}
}

func TestPigpenFormatsRejectAWrongSize(t *testing.T) {
	for _, tc := range pigpenFormatSizes {
		var id markl.Id
		if err := id.SetMarklId(tc.formatId, pigpenPayload(tc.size-1)); err == nil {
			t.Errorf("%s: accepted %d bytes, want only %d", tc.formatId, tc.size-1, tc.size)
		}
	}
}

func pigpenIdText(t *testing.T, purposeId, formatId string, size int) string {
	t.Helper()

	var bare markl.Id
	if err := bare.SetMarklId(formatId, pigpenPayload(size)); err != nil {
		t.Fatalf("%s: SetMarklId: %v", formatId, err)
	}

	return purposeId + "@" + bare.StringWithFormat()
}

func TestPigpenPurposesAcceptOnlyTheirFormats(t *testing.T) {
	for _, tc := range []struct {
		purposeId string
		formatId  string
		size      int
		accepted  bool
	}{
		{markl.PurposePigpenWrapV1, markl.FormatIdPigpenWrapP256, 65, true},
		{markl.PurposePigpenWrapV1, markl.FormatIdPigpenWrapX25519, 64, true},
		{markl.PurposePigpenWrapV1, markl.FormatIdPigpenHeaderMac, 32, false},
		{markl.PurposePigpenWrapV1, markl.FormatIdPivyEcdhP256Pub, 33, false},
		{markl.PurposePigpenDocV1, markl.FormatIdPigpenHeaderMac, 32, true},
		{markl.PurposePigpenDocV1, markl.FormatIdHashBlake2b256, 32, true},
		{markl.PurposePigpenDocV1, markl.FormatIdPigpenWrapP256, 65, false},
		{markl.PurposePiggyRecipientV1, markl.FormatIdPigpenWrapP256, 65, false},
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

func TestPigpenPurposesCarryTheirOwnTypes(t *testing.T) {
	if got := markl.GetPurpose(markl.PurposePigpenWrapV1).GetPurposeType(); got != markl.PurposeTypePigpenWrap {
		t.Errorf("pigpen-wrap-v1: type = %v, want PurposeTypePigpenWrap", got)
	}

	if got := markl.GetPurpose(markl.PurposePigpenDocV1).GetPurposeType(); got != markl.PurposeTypePigpenDoc {
		t.Errorf("pigpen-doc-v1: type = %v, want PurposeTypePigpenDoc", got)
	}
}
