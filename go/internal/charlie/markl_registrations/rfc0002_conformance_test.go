//go:build test

package markl_registrations_test

import (
	"bytes"
	"strings"
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

// TestRFC0002VectorsRoundTrip pins the wire format claimed normatively
// by RFC 0002. For every vector in the on-disk fixture the test:
//
//  1. Encodes (Purpose, Format, payload_hex) and asserts the result
//     equals Encoded byte-for-byte (canonical lowercase form).
//  2. Decodes Encoded and asserts the recovered (Purpose, Format,
//     bytes) match the inputs.
//
// Independent implementations (e.g. piggy's Rust port) load the same
// fixture and verify the same outcomes.
func TestRFC0002VectorsRoundTrip(t *testing.T) {
	fixture := loadRFC0002Fixture(t)

	if len(fixture.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fixture.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			payload := decodePayloadHex(t, v.Name, v.PayloadHex)

			var id markl.Id
			if v.Purpose != "" {
				if err := id.SetPurposeId(v.Purpose); err != nil {
					t.Fatalf("SetPurposeId(%q): %v", v.Purpose, err)
				}
			}
			if err := id.SetMarklId(v.Format, payload); err != nil {
				t.Fatalf("SetMarklId(%q, %d bytes): %v",
					v.Format, len(payload), err)
			}

			gotEncoded, err := id.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText: %v", err)
			}
			if string(gotEncoded) != v.Encoded {
				t.Errorf("encoded mismatch:\n got  %q\n want %q",
					string(gotEncoded), v.Encoded)
			}

			// Decode via UnmarshalText, which splits on `@` textually
			// before blech32-decoding the body with HRP = format
			// (matching how MarshalText writes it) and runs the §4
			// validations (size, (purpose, format) compatibility) via
			// SetMarklId.
			var decoded markl.Id
			if err := decoded.UnmarshalText([]byte(v.Encoded)); err != nil {
				t.Fatalf("UnmarshalText(%q): %v", v.Encoded, err)
			}

			if got := decoded.GetPurposeId(); got != v.Purpose {
				t.Errorf("decoded purpose: got %q, want %q", got, v.Purpose)
			}
			format := decoded.GetMarklFormat()
			if format == nil {
				t.Fatalf("decoded format is nil")
			}
			if got := format.GetMarklFormatId(); got != v.Format {
				t.Errorf("decoded format: got %q, want %q", got, v.Format)
			}
			if got := decoded.GetBytes(); !bytes.Equal(got, payload) {
				t.Errorf("decoded payload: got %x, want %x", got, payload)
			}
		})
	}
}

// TestRFC0002InvalidVectorsRejected verifies the decoder rejects each
// failure case enumerated in the fixture (mixed case, missing
// separator, wrong checksum, charset violation, wrong size,
// incompatible (purpose, format) pair). The exact error wording is
// implementation-specific; the test asserts only that decoding errors.
func TestRFC0002InvalidVectorsRejected(t *testing.T) {
	fixture := loadRFC0002Fixture(t)

	if len(fixture.Invalid) == 0 {
		t.Fatal("fixture has no invalid vectors")
	}

	for _, v := range fixture.Invalid {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			var id markl.Id
			err := id.UnmarshalText([]byte(v.Encoded))
			if err == nil {
				t.Errorf("decoding %q should error (%s), got nil",
					v.Encoded, v.Error)
			}
		})
	}
}

// TestRFC0002VectorsRoundTripViaSet exercises markl.Id.Set against the
// same fixture, pinning that the string-form decoder accepts the same
// wire format the byte-form decoder (UnmarshalText) accepts.
func TestRFC0002VectorsRoundTripViaSet(t *testing.T) {
	fixture := loadRFC0002Fixture(t)

	if len(fixture.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range fixture.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			payload := decodePayloadHex(t, v.Name, v.PayloadHex)

			var decoded markl.Id
			if err := decoded.Set(v.Encoded); err != nil {
				t.Fatalf("Set(%q): %v", v.Encoded, err)
			}

			if got := decoded.GetPurposeId(); got != v.Purpose {
				t.Errorf("decoded purpose: got %q, want %q", got, v.Purpose)
			}
			format := decoded.GetMarklFormat()
			if format == nil {
				t.Fatalf("decoded format is nil")
			}
			if got := format.GetMarklFormatId(); got != v.Format {
				t.Errorf("decoded format: got %q, want %q", got, v.Format)
			}
			if got := decoded.GetBytes(); !bytes.Equal(got, payload) {
				t.Errorf("decoded payload: got %x, want %x", got, payload)
			}
		})
	}
}

// TestRFC0002CrossPurposeBlech32Equal pins the wire-form property that
// encoding the same (format, data) under two different purposes MUST
// produce identical blech32 bodies, differing only in the `<purpose>@`
// textual prefix. The blech32 checksum binds to (format, data) only.
// Adapted from madder's cross-purpose test to two PIGGY purposes that
// share a format (piggy-piv_auth-v1 / piggy-piv_sig-v1 both accept
// ssh_ecdsa_nistp256_pub) — go/markl registers no dodder/madder
// purposes (ADR 0006).
func TestRFC0002CrossPurposeBlech32Equal(t *testing.T) {
	const (
		formatId   = markl.FormatIdSshEcdsaNistp256Pub
		purposeOne = markl.PurposePiggyPivAuthV1
		purposeTwo = markl.PurposePiggyPivSigV1
	)

	payload := bytes.Repeat([]byte{0xCD}, 33) // ssh_ecdsa_nistp256_pub size

	encode := func(purposeId string) string {
		var id markl.Id
		if purposeId != "" {
			if err := id.SetPurposeId(purposeId); err != nil {
				t.Fatalf("SetPurposeId(%q): %v", purposeId, err)
			}
		}
		if err := id.SetMarklId(formatId, payload); err != nil {
			t.Fatalf("SetMarklId(%q, ...): %v", formatId, err)
		}
		bites, err := id.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		return string(bites)
	}

	bodyOf := func(encoded string) string {
		at := strings.IndexByte(encoded, '@')
		if at < 0 {
			return encoded
		}
		return encoded[at+1:]
	}

	bareBody := bodyOf(encode(""))
	oneBody := bodyOf(encode(purposeOne))
	twoBody := bodyOf(encode(purposeTwo))

	if oneBody != bareBody {
		t.Errorf("blech32 body under %q diverged from purposeless form:\n got  %q\n want %q",
			purposeOne, oneBody, bareBody)
	}
	if twoBody != bareBody {
		t.Errorf("blech32 body under %q diverged from purposeless form:\n got  %q\n want %q",
			purposeTwo, twoBody, bareBody)
	}
	if oneBody != twoBody {
		t.Errorf("blech32 bodies diverged across purposes:\n %q -> %q\n %q -> %q",
			purposeOne, oneBody, purposeTwo, twoBody)
	}
}
