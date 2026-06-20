package blech32

import (
	"bytes"
)

// DecodeWithHRPOverride verifies `body`'s blech32 checksum against
// `hrp` instead of the leading segment in `body`'s own
// `<inner-hrp>-<data>` shape, and on success returns the recovered
// inner HRP segment and the decoded data bytes.
//
// Used to recover a `(formatId, data)` pair from the legacy combined
// `<purpose>@<format>` markl-id wire form (RFC 0002 §9.1), briefly
// shipped between commits `8dc78c7` and the #159 revert (`fd53684`).
// The caller verifies under the combined HRP but receives the inner
// `<format>` HRP and recovered bytes so it can re-emit under the
// canonical split-HRP rule (RFC 0002 §3.3).
//
// Returns ok=false (with empty innerHRP and nil data) on any
// structural failure (mixed case, missing separator, charset
// violation, bit-conversion error) or checksum mismatch. This helper
// exists for diagnostic recovery only; callers that need precise
// failure categories use Decode.
//
// The function does not mutate `body`.
func DecodeWithHRPOverride(
	hrp string, body []byte,
) (innerHRP string, data []byte, ok bool) {
	if _, err := validateCase(body); err != nil {
		return "", nil, false
	}

	pos := bytes.LastIndex(body, []byte("-"))

	if err := validateSeparatorPosition(body, pos); err != nil {
		return "", nil, false
	}

	innerHRP = string(body[:pos])

	encoded := body[pos+1:]
	indices := make([]byte, 0, len(encoded))

	for _, c := range encoded {
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}

		d := bytes.IndexByte(charset, c)
		if d == -1 {
			return "", nil, false
		}

		indices = append(indices, byte(d))
	}

	if !verifyChecksum(hrp, indices) {
		return "", nil, false
	}

	data, err := convertBits(indices[:len(indices)-6], 5, 8, false)
	if err != nil {
		return "", nil, false
	}

	return innerHRP, data, true
}
