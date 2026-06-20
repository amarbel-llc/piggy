package blech32

import (
	"bytes"
	"testing"
)

// TestVerifyChecksumWithHRPOverride_AcceptsCombinedHRP pins the helper's
// load-bearing case for #168: a body whose checksum was computed with a
// combined `<purpose>@<format>` HRP verifies under that override.
//
// Note: blech32 itself is HRP-agnostic — Decode would re-discover the
// combined HRP via its own LastIndex split, so the canonical Decode
// can verify combined-HRP bodies too. The split-vs-combined
// distinction is enforced one level up, in markl's UnmarshalText,
// where the `@` is stripped before the blech32 call. This helper
// exists for that caller.
func TestVerifyChecksumWithHRPOverride_AcceptsCombinedHRP(t *testing.T) {
	const combinedHRP = "test-purpose-v1@blake2b256"

	payload := bytes.Repeat([]byte{0xAB}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	if !VerifyChecksumWithHRPOverride(combinedHRP, encoded) {
		t.Errorf(
			"VerifyChecksumWithHRPOverride(%q, %q) = false; want true",
			combinedHRP, string(encoded),
		)
	}

	// Override with the WRONG HRP must reject — proves the override is
	// load-bearing and not just rubber-stamping any well-formed body.
	if VerifyChecksumWithHRPOverride("blake2b256", encoded) {
		t.Errorf(
			"VerifyChecksumWithHRPOverride(%q, %q) = true; want false",
			"blake2b256", string(encoded),
		)
	}
}

// TestVerifyChecksumWithHRPOverride_RejectsCorruption pins that bit
// flips in the data portion don't accidentally verify under any HRP
// the caller might supply. Without this property, the diagnostic in
// id_coding_text.go would silently misclassify corruption as legacy.
func TestVerifyChecksumWithHRPOverride_RejectsCorruption(t *testing.T) {
	const combinedHRP = "test-purpose-v1@blake2b256"

	payload := bytes.Repeat([]byte{0xCD}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	corrupted := append([]byte(nil), encoded...)

	// Cycle the last data char to a different charset character so
	// the failure is genuinely a checksum mismatch rather than a
	// charset violation (an XOR flip on `0` or `q` lands outside the
	// charset and short-circuits the polymod path).
	last := corrupted[len(corrupted)-1]
	idx := bytes.IndexByte(charset, last)
	if idx < 0 {
		t.Fatalf("encoded body's last char %q not in charset", last)
	}
	corrupted[len(corrupted)-1] = charset[(idx+1)%len(charset)]

	if VerifyChecksumWithHRPOverride(combinedHRP, corrupted) {
		t.Errorf(
			"corrupted body must not verify: %q",
			string(corrupted),
		)
	}
}

// TestVerifyChecksumWithHRPOverride_RejectsCharsetViolation pins that
// non-charset bytes in the data portion fail closed (false), not panic.
func TestVerifyChecksumWithHRPOverride_RejectsCharsetViolation(t *testing.T) {
	body := []byte("blake2b256-qpzry9x8gf2tvdw0s3jn54kh!e6mua7lqqqqqqq")

	if VerifyChecksumWithHRPOverride("test-purpose-v1@blake2b256", body) {
		t.Errorf(
			"body with charset violation must not verify: %q",
			string(body),
		)
	}
}

// TestVerifyChecksumWithHRPOverride_DoesNotMutateBody pins the helper's
// non-mutation contract — callers reuse the body slice for error
// reporting and expect it unchanged.
func TestVerifyChecksumWithHRPOverride_DoesNotMutateBody(t *testing.T) {
	const combinedHRP = "TEST-PURPOSE-V1@BLAKE2B256"

	payload := bytes.Repeat([]byte{0x01}, 32)

	encoded, err := Encode(combinedHRP, payload)
	if err != nil {
		t.Fatalf("Encode(%q, ...): %v", combinedHRP, err)
	}

	original := append([]byte(nil), encoded...)

	_ = VerifyChecksumWithHRPOverride(combinedHRP, encoded)

	if !bytes.Equal(encoded, original) {
		t.Errorf(
			"VerifyChecksumWithHRPOverride mutated body: got %q, want %q",
			string(encoded), string(original),
		)
	}
}
