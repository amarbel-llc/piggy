//go:build test

// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2016-2017 The Lightning Network Developers
// Copyright (c) 2019 The age Authors
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package blech32

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/test_ui"
)

func TestBlech32(t1 *testing.T) {
	t := test_ui.T{T: t1}

	type testCase struct {
		str   string
		valid bool
	}

	tests := []testCase{
		// Uppercase is REJECTED as of 2026-07-20 (RFC 0011 §3.5,
		// madder#273 ruling 6). This vector is bech32's own
		// all-uppercase spelling and used to be valid; lowercase-only
		// narrows bech32's all-lower-or-all-upper rule, because the QR
		// alphanumeric mode that motivates bech32's uppercase allowance
		// can never encode a markl-id anyway (its charset has no
		// lowercase, no '@', no '_'). Kept as a rejection vector rather
		// than deleted, so the narrowing stays pinned.
		{"A-2UEL5L", false},
		{"a-2uel5l", true}, // empty
		{
			"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio-tt5tgs",
			true,
		},
		{"abcdef-qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", true},
		{
			"1-qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
			true,
		},
		{"split-checkupstagehandshakeupstreamerranterredcaperred2y9e3w", true},

		// invalid checksum
		{"split-checkupstagehandshakeupstreamerranterredcaperred2y9e2w", false},
		// invalid character (space) in hrp
		{"s lit-checkupstagehandshakeupstreamerranterredcaperredp8hs2p", false},
		{"split-cheo2y9e2w", false}, // invalid character (o) in data part
		{"split-a2y9w", false},      // too short data part
		{
			"-checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
			false,
		}, // empty hrp
		// invalid character (DEL) in hrp
		{
			"spl" + string(
				rune(127),
			) + "t-checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
			false,
		},

		// long vectors that we do accept despite the spec, see Issue 453
		{
			"long-0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7qfcsvr0",
			true,
		},
		{
			"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio-569pvx",
			true,
		},

		// BIP 173 invalid vectors.
		{"pzry9x0s0muk", false},
		{"-pzry9x0s0muk", false},
		{"x-b4n0q5v", false},
		{"li-dgmt3", false},
		{"de-lg7wt\xff", false},
		{"A-G7SGD8", false},
		{"-0a06t8", false},
		{"-qzzfhee", false},
	}

	for _, tc := range tests {
		t.Run(
			test_ui.MakeTestCase(tc.str, tc),
			func(t *test_ui.T) {
				expected := tc.str
				hrp, decoded, err := DecodeString(expected)
				if !tc.valid {
					// Invalid string decoding should result in error.
					if err == nil {
						t.Errorf(
							"expected decoding to fail for invalid string %v",
							tc.str,
						)
					}
					return
				}

				// Valid string decoding should result in no error.
				if err != nil {
					t.Errorf("expected string to be valid blech32: %v", err)
				}

				// Check that it encodes to the same string.
				actual, err := Encode(hrp, decoded)
				if err != nil {
					t.Errorf("encoding failed: %v", err)
				}
				if string(actual) != expected {
					t.Errorf(
						"expected data to encode to %v, but got %v",
						expected,
						string(actual),
					)
				}

				// Flip a bit in the string an make sure it is caught.
				pos := strings.LastIndexAny(expected, "1")
				flipped := expected[:pos+1] + string(
					(expected[pos+1] ^ 1),
				) + expected[pos+2:]
				if _, _, err = DecodeString(flipped); err == nil {
					t.Error("expected decoding to fail")
				}
			},
		)
	}
}

// TestSeparatorErrors_DistinguishEmptyHRPFromMissing pins RFC 0011 §4
// step 3's two separator categories (piggy#228): a missing `-` is
// SeparatorMissing; a LEADING `-` is EmptyHrp — the separator is there,
// the format identifier is not, and the two malformations point a
// reader at different defects. Go formerly returned SeparatorMissing
// for both, diverging from Rust, whose distinction was pinned by a
// real piggy-ids typo incident; Rust's behaviour is now normative.
func TestSeparatorErrors_DistinguishEmptyHRPFromMissing(t *testing.T) {
	if _, _, err := DecodeString("pzry9x0s0muk"); !errors.Is(err, ErrSeparatorMissing) {
		t.Errorf("no separator: want ErrSeparatorMissing, got %v", err)
	}

	if _, _, err := DecodeString("-pzry9x0s0muk"); !errors.Is(err, ErrEmptyHRP) {
		t.Errorf("leading separator: want ErrEmptyHRP, got %v", err)
	}
}

// TestDecodeDataOnly_RejectsUppercase pins that RFC 0011 §3.5's
// lowercase-only rule (madder#273 ruling 6) reaches the data-only decode
// path too, not just DecodeString/Decode.
//
// This exists because piggy#224 was filed on a misreading of
// TestBlech32DataOnly below: that test's vectors are raw PAYLOAD bytes
// handed to EncodeDataOnly, not blech32 strings, so `2UEL5L` there is
// six bytes of content and says nothing about the case rule. Nothing
// actually covered the encoded form on this path — hence this test.
func TestDecodeDataOnly_RejectsUppercase(t *testing.T) {
	encoded, err := EncodeDataOnly([]byte{0x00, 0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("EncodeDataOnly: %v", err)
	}

	if _, err := DecodeDataOnly(encoded); err != nil {
		t.Fatalf("lowercase form should decode: %v", err)
	}

	upper := bytes.ToUpper(encoded)

	if _, err := DecodeDataOnly(upper); err == nil {
		t.Errorf(
			"DecodeDataOnly(%q) should reject uppercase, got nil",
			string(upper),
		)
	}
}

// TestDecodeDataOnly_DoesNotMutateInput pins the non-mutation contract
// the *WithHRPOverride helpers already assert for themselves. decode
// used to call unicorn.ToLower on the caller's slice in place; that was
// a side effect on memory the caller still owns, and dead besides once
// uppercase became a rejection rather than something to normalise.
func TestDecodeDataOnly_DoesNotMutateInput(t *testing.T) {
	encoded, err := EncodeDataOnly([]byte{0x00, 0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("EncodeDataOnly: %v", err)
	}

	before := append([]byte(nil), encoded...)

	if _, err := DecodeDataOnly(encoded); err != nil {
		t.Fatalf("DecodeDataOnly: %v", err)
	}

	if !bytes.Equal(before, encoded) {
		t.Errorf(
			"DecodeDataOnly mutated its input: %q -> %q",
			string(before),
			string(encoded),
		)
	}
}

func TestBlech32DataOnly(t1 *testing.T) {
	// t1.Skip()
	t := test_ui.T{T: t1}

	type testCase struct {
		input string
		valid bool
	}

	tests := []testCase{
		{"2UEL5L", true}, // empty
		{"2uel5l", true},
		// {
		// 	"tt5tgs",
		// 	true,
		// },
		// {"qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", true},
		// {
		// 	"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
		// 	true,
		// },
		// {"checkupstagehandshakeupstreamerranterredcaperred2y9e3w", true},

		// // invalid checksum
		// {"checkupstagehandshakeupstreamerranterredcaperred2y9e2w", false},
		// // invalid character (space) in hrp
		// {"checkupstagehandshakeupstreamerranterredcaperredp8hs2p", true},
		// {"cheo2y9e2w", false}, // invalid character (o) in data part
		// {"a2y9w", false},      // too short data part
		// {
		// 	"checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
		// 	false,
		// }, // empty hrp
		// // invalid character (DEL) in hrp

		// // long vectors that we do accept despite the spec, see Issue 453
		// {
		// 	"0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7rc0pu8s7qfcsvr0",
		// 	true,
		// },
		// {
		// 	"569pvx",
		// 	true,
		// },

		// // BIP 173 invalid vectors.
		// {"pzry9x0s0muk", false},
		// {"-pzry9x0s0muk", false},
	}

	for _, tc := range tests {
		t.Run(
			test_ui.MakeTestCase(tc.input, tc),
			func(t *test_ui.T) {
				// Check that it encodes to the same string.
				encoded, err := EncodeDataOnly([]byte(tc.input))
				if err != nil {
					t.Errorf("encoding failed: %v", err)
				}
				// if string(actual) != expected {
				// 	t.Errorf(
				// 		"expected data to encode to %v, but got %v",
				// 		expected,
				// 		string(actual),
				// 	)
				// }

				expected := tc.input
				decoded, err := DecodeDataOnly([]byte(encoded))
				if !bytes.Equal([]byte(tc.input), decoded) {
					t.Errorf("expected %x but got %x", tc.input, decoded)
				}
				if !tc.valid {
					// Invalid string decoding should result in error.
					if err == nil {
						t.Errorf(
							"expected decoding to fail for invalid string %v",
							tc.input,
						)
					}
					return
				}

				// Valid string decoding should result in no error.
				if err != nil {
					t.Errorf("expected string to be valid blech32: %v. Encoded: %q", err, encoded)
				}

				// Flip a bit in the string an make sure it is caught.
				pos := strings.LastIndexAny(expected, "1")
				flipped := expected[:pos+1] + string(
					(expected[pos+1] ^ 1),
				) + expected[pos+2:]
				if _, _, err = DecodeString(flipped); err == nil {
					t.Error("expected decoding to fail")
				}
			},
		)
	}
}
