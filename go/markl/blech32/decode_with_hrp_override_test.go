package blech32

import (
	"bytes"
	"testing"
)

// TestDecodeWithHRPOverride_AcceptsCombinedHRP pins the load-bearing
// case for #170: a body whose checksum was computed with a combined
// `<purpose>@<format>` HRP verifies under that override, and the
// inner `<format>` HRP segment plus the original data bytes are
// recovered intact.
func TestDecodeWithHRPOverride_AcceptsCombinedHRP(t *testing.T) {
	const (
		combinedHRP = "test-purpose-v1@blake2b256"
		innerHRP    = "test-purpose-v1@blake2b256"
	)

	payload := bytes.Repeat([]byte{0xAB}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	gotHRP, gotData, ok := DecodeWithHRPOverride(combinedHRP, encoded)
	if !ok {
		t.Fatalf(
			"DecodeWithHRPOverride(%q, %q) = ok=false; want ok=true",
			combinedHRP, string(encoded),
		)
	}

	if gotHRP != innerHRP {
		t.Errorf(
			"innerHRP: got %q, want %q",
			gotHRP, innerHRP,
		)
	}

	if !bytes.Equal(gotData, payload) {
		t.Errorf(
			"data: got %x, want %x",
			gotData, payload,
		)
	}

	// Override with the WRONG HRP must reject — proves the override
	// is load-bearing and not just rubber-stamping any well-formed
	// body.
	_, _, ok = DecodeWithHRPOverride("blake2b256", encoded)
	if ok {
		t.Errorf(
			"DecodeWithHRPOverride(%q, %q) = ok=true; want false",
			"blake2b256", string(encoded),
		)
	}
}

// TestDecodeWithHRPOverride_RecoversSplitInnerHRP pins that for the
// markl legacy-form recovery shape — body=`<format>-<data><cksum>`
// verified against HRP=`<purpose>@<format>` — the returned innerHRP
// is the bare `<format>` segment, not the combined override. This is
// the property that lets ErrLegacyCombinedHRPWireForm.FormatId carry
// just the format id (e.g. "ed25519_sec").
func TestDecodeWithHRPOverride_RecoversSplitInnerHRP(t *testing.T) {
	const (
		purpose  = "test-purpose-v1"
		formatId = "blake2b256"
	)

	combinedHRP := purpose + "@" + formatId
	payload := bytes.Repeat([]byte{0xAB}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	gotHRP, gotData, ok := DecodeWithHRPOverride(combinedHRP, encoded)
	if !ok {
		t.Fatalf("DecodeWithHRPOverride: ok=false")
	}

	// The body's own inner HRP segment IS the combined HRP because
	// Encode wrote `<combinedHRP>-<data><cksum>`. The split-HRP
	// shape (where innerHRP=`<format>` only) shows up at the markl
	// layer, where `<purpose>@` is stripped textually from the
	// input before this helper is called. See
	// markl.UnmarshalText's legacy-form path.
	if gotHRP != combinedHRP {
		t.Errorf("innerHRP: got %q, want %q", gotHRP, combinedHRP)
	}

	if !bytes.Equal(gotData, payload) {
		t.Errorf("data: got %x, want %x", gotData, payload)
	}
}

// TestDecodeWithHRPOverride_RejectsCorruption pins that bit flips in
// the data portion don't accidentally verify under any HRP the
// caller might supply.
func TestDecodeWithHRPOverride_RejectsCorruption(t *testing.T) {
	const combinedHRP = "test-purpose-v1@blake2b256"

	payload := bytes.Repeat([]byte{0xCD}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	corrupted := append([]byte(nil), encoded...)

	last := corrupted[len(corrupted)-1]
	idx := bytes.IndexByte(charset, last)
	if idx < 0 {
		t.Fatalf("encoded body's last char %q not in charset", last)
	}
	corrupted[len(corrupted)-1] = charset[(idx+1)%len(charset)]

	gotHRP, gotData, ok := DecodeWithHRPOverride(combinedHRP, corrupted)
	if ok {
		t.Errorf(
			"corrupted body must not verify: %q",
			string(corrupted),
		)
	}
	if gotHRP != "" {
		t.Errorf("innerHRP on failure: got %q, want %q", gotHRP, "")
	}
	if gotData != nil {
		t.Errorf("data on failure: got %x, want nil", gotData)
	}
}

// TestDecodeWithHRPOverride_RejectsCharsetViolation pins that
// non-charset bytes in the data portion fail closed (ok=false), not
// panic.
func TestDecodeWithHRPOverride_RejectsCharsetViolation(t *testing.T) {
	body := []byte("blake2b256-qpzry9x8gf2tvdw0s3jn54kh!e6mua7lqqqqqqq")

	_, _, ok := DecodeWithHRPOverride(
		"test-purpose-v1@blake2b256", body,
	)
	if ok {
		t.Errorf(
			"body with charset violation must not verify: %q",
			string(body),
		)
	}
}

// TestDecodeWithHRPOverride_DoesNotMutateBody pins the helper's
// non-mutation contract — callers reuse the body slice for error
// reporting and expect it unchanged.
func TestDecodeWithHRPOverride_DoesNotMutateBody(t *testing.T) {
	const combinedHRP = "TEST-PURPOSE-V1@BLAKE2B256"

	payload := bytes.Repeat([]byte{0x01}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	original := append([]byte(nil), encoded...)

	_, _, _ = DecodeWithHRPOverride(combinedHRP, encoded)

	if !bytes.Equal(encoded, original) {
		t.Errorf(
			"DecodeWithHRPOverride mutated body: got %q, want %q",
			string(encoded), string(original),
		)
	}
}
