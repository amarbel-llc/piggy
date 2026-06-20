package blech32

import (
	"bytes"
)

// VerifyChecksumWithHRPOverride checks the blech32 checksum of `body`
// against `hrp` instead of the leading segment in `body`'s own
// `<own-hrp>-<data>` shape. Used to verify a blech32 string against an
// alternate HRP shape — in particular, the legacy combined
// `<purpose>@<format>` form documented in RFC 0002 §9.1, briefly
// shipped between commits `8dc78c7` and the #159 revert (`fd53684`).
//
// Returns true iff `body` passes uniform-case, separator-position, and
// charset validations AND the polymod over (hrp-expand(hrp), data
// indices) yields 1. On any structural failure (mixed case, missing
// separator, charset violation) it returns false rather than a typed
// error — this helper exists for diagnostic re-verification only;
// callers that need precise failure categories use Decode.
//
// The function does not mutate `body`.
func VerifyChecksumWithHRPOverride(hrp string, body []byte) bool {
	if _, err := validateCase(body); err != nil {
		return false
	}

	pos := bytes.LastIndex(body, []byte("-"))

	if err := validateSeparatorPosition(body, pos); err != nil {
		return false
	}

	encoded := body[pos+1:]
	data := make([]byte, 0, len(encoded))

	for _, c := range encoded {
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}

		d := bytes.IndexByte(charset, c)
		if d == -1 {
			return false
		}

		data = append(data, byte(d))
	}

	return verifyChecksum(hrp, data)
}
