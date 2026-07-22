// Copyright (c) 2017 Takatoshi Nakagawa
// Copyright (c) 2019 The age Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Package blech32 is a modified version bech32 backage which itself is a
// modified version of the reference implementation of BIP173. This package
// changes the spec so that the last occurrence of `1` is actually a `-`
// instead.
package blech32

//go:generate dagnabit export

import (
	"bytes"
	"fmt"
	"strings"

	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/unicorn"
)

const separator = '-'

var (
	charsetString = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	charset       = []byte(charsetString)
)

var generator = []uint32{
	0x3b6a57b2,
	0x26508e6d,
	0x1ea119fa,
	0x3d4233dd,
	0x2a1462b3,
}

func polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk & 0x1ffffff) << 5
		chk = chk ^ uint32(v)
		for i := range 5 {
			bit := top >> i & 1
			if bit == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []byte {
	if hrp == "" {
		return nil
	}

	h := []byte(strings.ToLower(hrp))
	var ret []byte
	for _, c := range h {
		ret = append(ret, c>>5)
	}
	ret = append(ret, 0)
	for _, c := range h {
		ret = append(ret, c&31)
	}
	return ret
}

func verifyChecksum(hrp string, data []byte) bool {
	return polymod(append(hrpExpand(hrp), data...)) == 1
}

func createChecksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, []byte{0, 0, 0, 0, 0, 0}...)
	mod := polymod(values) ^ 1
	ret := make([]byte, 6)
	for p := range ret {
		shift := 5 * (5 - p)
		ret[p] = byte(mod>>shift) & 31
	}
	return ret
}

func convertBits(data []byte, frombits, tobits byte, pad bool) ([]byte, error) {
	var ret []byte
	acc := uint32(0)
	bits := byte(0)
	maxv := byte(1<<tobits - 1)
	for idx, value := range data {
		if value>>frombits != 0 {
			return nil, fmt.Errorf(
				"invalid data range: data[%d]=%d (frombits=%d)",
				idx,
				value,
				frombits,
			)
		}
		acc = acc<<frombits | uint32(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte(acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte(acc<<(tobits-bits))&maxv)
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("illegal zero padding")
	} else if byte(acc<<(tobits-bits))&maxv != 0 {
		return nil, fmt.Errorf("non-zero padding")
	}
	return ret, nil
}

// Encode encodes the HRP and a bytes slice to Blech32. If the HRP is uppercase,
// the output will be uppercase.
func Encode(hrp string, data []byte) ([]byte, error) {
	if len(hrp) < 1 {
		return nil, ErrEmptyHRP
	}
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return nil, errInvalidHRPCharacter{pos: p, char: c}
		}
	}
	return encode(hrp, data)
}

func EncodeDataOnly(data []byte) ([]byte, error) {
	return encode("", data)
}

// Encode encodes the HRP and a bytes slice to Blech32. If the HRP is uppercase,
// the output will be uppercase.
func encode(hrp string, data []byte) ([]byte, error) {
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return nil, err
	}

	if err = validateCaseString(hrp); err != nil {
		return nil, err
	}

	hrp = strings.ToLower(hrp)

	var ret bytes.Buffer

	if hrp != "" {
		ret.WriteString(hrp)
		ret.WriteString("-")
	}

	for _, p := range values {
		ret.WriteByte(charsetString[p])
	}

	for _, p := range createChecksum(hrp, values) {
		ret.WriteByte(charsetString[p])
	}

	return ret.Bytes(), nil
}

func EncodeHRPAsData(hrp string, data []byte) ([]byte, error) {
	dataConverted, err := convertBits(data, 8, 5, true)
	if err != nil {
		return nil, err
	}

	hrpBytes := []byte(hrp)

	if err = validateCase(hrpBytes); err != nil {
		return nil, err
	}

	unicorn.ToLower(hrpBytes)

	var ret bytes.Buffer

	hrpBytesConverted, err := convertBits(hrpBytes, 8, 5, true)
	if err != nil {
		return nil, err
	}

	for _, p := range hrpBytesConverted {
		ret.WriteByte(charsetString[p])
	}

	for _, p := range dataConverted {
		ret.WriteByte(charsetString[p])
	}

	for _, p := range createChecksum(hrp, dataConverted) {
		ret.WriteByte(charsetString[p])
	}

	return ret.Bytes(), nil
}

// validateHRP enforces RFC 0011 §3's HRP charset: [a-zA-Z0-9_].
//
// NARROWED 2026-07-20 (linenisgreat/madder#273 ruling 8) from printable
// ASCII 33–126. The narrowing is what makes the separator unambiguous:
// blech32 is bech32 with the HRP/data separator changed from `1` to
// `-`, and that swap only works if `-` cannot itself occur in an HRP.
// Under the old printable-ASCII rule it could, which is why the decoder
// had to guess by taking the LAST `-`. With the HRP charset excluding
// `-`, a well-formed blech32 string contains exactly one separator and
// the split is determined rather than guessed (see ruling 9 and
// validateSeparatorPosition's callers).
//
// Evidence that this costs nothing: every format-id across piggy,
// madder, and dodder uses `_` as its word separator, never `-`.
func validateHRP(hrp string) (err error) {
	for p, c := range hrp {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_':
		default:
			return errInvalidHRPCharacter{pos: p, char: c}
		}
	}

	return err
}

// validateCaseString enforces RFC 0011 §3.5: lowercase only.
//
// Formerly this accepted all-lower OR all-upper and returned which one
// it saw, mirroring bech32; the encoders used that to decide whether to
// upper-case their output. Ruling 6 narrowed the rule to lowercase, so
// mixed case and all-uppercase are now BOTH rejections — the first
// still as ErrMixedCase (a distinct malformation worth naming), the
// second as ErrUppercase.
//
// That left the `lower` result always true on success and the encoders'
// bytes.ToUpper branches unreachable, so both were removed rather than
// left as dead alternatives that imply an upper-case form still exists.
func validateCaseString(s string) error {
	toLower := strings.ToLower(s)
	toUpper := strings.ToUpper(s)

	switch {
	case toLower != s && toUpper != s:
		return ErrMixedCase

	case toLower != s:
		return ErrUppercase
	}

	return nil
}

// validateCase is validateCaseString's byte-slice twin; see its note for
// the ruling-6 narrowing.
func validateCase(bites []byte) error {
	lowerCount, _, upperCount := unicorn.CountCase(bites)

	if lowerCount != 0 && upperCount != 0 {
		return fmt.Errorf(
			"mixed case: lower: %d, upper: %d",
			lowerCount,
			upperCount,
		)
	}

	if upperCount != 0 {
		return ErrUppercase
	}

	return nil
}

type bytesOrString interface {
	~[]byte | ~string
}

const dataPortionMinWidth = 7

// validateSeparatorPosition distinguishes a MISSING separator (pos < 0)
// from a separator in the first position (pos == 0), which means the
// HRP is EMPTY — a different malformation deserving a different error
// (RFC 0011 §4 step 3; piggy#228).
//
// Formerly both returned ErrSeparatorMissing (`pos < 1`), diverging
// from the Rust decoder, which has distinguished EmptyHrp since a real
// piggy-ids typo incident pinned the value of the distinction: a
// leading `-` means "you lost your HRP", and reporting it as "no
// separator" sends the reader hunting for the wrong defect. The Rust
// behaviour was adopted as normative and Go converged.
func validateSeparatorPosition[INPUT bytesOrString](
	input INPUT,
	pos int,
) error {
	if pos < 0 {
		return ErrSeparatorMissing
	} else if pos == 0 {
		return ErrEmptyHRP
	} else if pos+dataPortionMinWidth > len(input) {
		return errDataPortionTooShort{
			expected: dataPortionMinWidth,
			actual:   len(input) - (pos + 1),
			data:     string(input[pos+1:]),
		}
	}

	return nil
}

// DecodeString decodes a Blech32 string. If the string is uppercase, the HRP
// will be
// uppercase.
func DecodeString(input string) (hrp string, data []byte, err error) {
	if err = validateCaseString(input); err != nil {
		return hrp, data, err
	}

	// Single-separator split (RFC 0011 §3.2, madder#273 ruling 9).
	// Formerly strings.LastIndex: with the HRP charset narrowed to
	// [a-zA-Z0-9_] a well-formed string has exactly one `-`, so a
	// second one is a malformed input to REJECT rather than a
	// still-decodable string to guess at. Taking the last `-` would
	// silently accept `a-b-<data>` by treating `a-b` as the HRP —
	// which validateHRP now rejects anyway, but only after the split
	// has already committed to the wrong boundary.
	pos := strings.Index(input, "-")

	if err = validateSeparatorPosition(input, pos); err != nil {
		return hrp, data, err
	}

	hrp = input[:pos]

	if err = validateHRP(hrp); err != nil {
		return hrp, data, err
	}

	// No ToLower here: validateCaseString above already rejected any
	// uppercase input (RFC 0011 §3.5), so by this point the string is
	// lowercase by construction. The normalising call this replaced was
	// dead once ruling 6 landed.

	for p, c := range input[pos+1:] {
		d := strings.IndexRune(charsetString, c)
		if d == -1 {
			return "", nil, errInvalidCharacterInData{
				pos:  p + pos + 1,
				char: rune(c),
			}
		}
		data = append(data, byte(d))
	}
	if !verifyChecksum(hrp, data) {
		return "", nil, ErrInvalidChecksum
	}
	data, err = convertBits(data[:len(data)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

// Decode decodes a Blech32 string. If the string is uppercase, the HRP
// will be uppercase.
func Decode(bites []byte) (hrp string, data []byte, err error) {
	// Per BIP173 / blech32 §case-rules: the whole input — HRP and
	// data together — MUST be uniformly cased. DecodeString already
	// enforces this on its string input; do the same here on bytes.
	if err = validateCase(bites); err != nil {
		return hrp, data, err
	}

	// Single-separator split — see DecodeString's note (RFC 0011 §3.2,
	// madder#273 ruling 9).
	pos := bytes.Index(bites, []byte("-"))

	if err = validateSeparatorPosition(bites, pos); err != nil {
		return hrp, data, err
	}

	hrp = string(bites[:pos])
	bites = bites[pos+1:]

	if data, err = decode(hrp, bites); err != nil {
		return hrp, data, err
	}

	return hrp, data, err
}

// DecodeDataOnly decodes the data portion of a blech32 string — the
// payload plus its 6-character checksum, with no HRP. The checksum is
// verified against an empty HRP.
//
// Like every decode path it is lowercase-only (RFC 0011 §3.5) and does
// NOT mutate bites.
func DecodeDataOnly(bites []byte) (data []byte, err error) {
	if data, err = decode("", bites); err != nil {
		return data, err
	}

	return data, err
}

// decode is the shared data-portion decoder behind Decode and
// DecodeDataOnly.
//
// It does NOT mutate bites. It previously called unicorn.ToLower on the
// caller's slice in place, which was both a caller-visible side effect
// on an input the caller still owns — the *WithHRPOverride helpers
// carry explicit DoesNotMutateBody tests, so non-mutation is an
// established contract in this package — and, since ruling 6, dead:
// validateCase rejects any uppercase input, so there is never anything
// left to lower.
func decode(hrp string, bites []byte) (data []byte, err error) {
	if err = validateCase(bites); err != nil {
		return data, err
	}

	for p, c := range bites {
		// TODO make more performance with a lookup map
		d := bytes.IndexRune(charset, rune(c))

		if d == -1 {
			return nil, errInvalidCharacterInData{
				pos:  p,
				char: rune(c),
			}
		}

		data = append(data, byte(d))
	}

	if !verifyChecksum(hrp, data) {
		return nil, ErrInvalidChecksum
	}

	data, err = convertBits(data[:len(data)-6], 5, 8, false)
	if err != nil {
		return nil, err
	}

	return data, nil
}
