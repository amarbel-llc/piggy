package markl

import (
	"strings"
)

// Purpose-slot quoting, RFC 0011 §2.1 / §2.2 (linenisgreat/madder#273
// rulings 1 and 2).
//
// The bare purpose production is the ASCII inclusion set [a-zA-Z0-9_/-]
// (purposeIsBareExpressible). Ruling 2 adds a quoted alternative so that
// purposes outside that set remain spellable — which is what keeps
// madder#270's pinnability concern answered after ruling 1 revoked BARE
// Unicode pinnability: a Unicode-named object is pinned quoted,
// `"café/naïve"@blake2b256-...`, rather than not at all.
//
// The quoting rules are Doddish, matching 0014-trellis.peg's String
// production verbatim so a markl-id embedded in trellis quotes
// identically: double or single quotes; backslash escapes \n \t \r \a
// \b \f \v, \" and \\ round-trip; an unknown escape passes the
// following character through unchanged.
//
// Only the PURPOSE slot is quoted. The digest slot stays bare and
// structurally intact (RFC 0011 §2.2) so tooling that operates on the
// digest independently — prefix elision, trie abbreviation, diffing,
// the mother→child digest-extraction paths — can locate it without
// first undoing any quoting. RFC 0011 §2.3 admits a quoted digest as a
// parse-time extension point, but the reference decoders refuse it;
// nothing here ever produces one.

const (
	purposeQuoteDouble = '"'
	purposeQuoteSingle = '\''
)

// splitPurposeSlot splits a markl-id wire string into its purpose slot
// and the body that follows the `@` join, quote-aware.
//
// A first-`@` split is NOT sufficient. RFC 0011 §2.2 permits a quoted
// purpose to contain `@` (madder#273 follow-up, piggy#227): quoting is
// the escape mechanism, so the rune most in need of escaping is exactly
// the one it must be able to carry. `"a@b"@blake2b256-...` therefore has
// its join at the SECOND `@`, and a naive Cut would slice the purpose in
// half. The bare form still cannot contain `@` at all — it is outside
// §2.1's `[a-zA-Z0-9_/-]` inclusion set — so the restriction lives
// entirely in the unquoted spelling.
//
// When value does not begin with a quote rune, the first `@` is the
// join, exactly as before. When it does, the closing quote is located
// honouring backslash escapes and the join must immediately follow it.
//
// A slot that opens with a quote but never resolves is returned whole,
// with hasPurpose true, so unquotePurpose reports it as unterminated
// rather than letting a mangled body reach the blech32 decoder and fail
// there with a misleading checksum or separator error.
func splitPurposeSlot(value string) (slot, body string, hasPurpose bool) {
	if value == "" {
		return "", value, false
	}

	quote := value[0]

	if quote != purposeQuoteDouble && quote != purposeQuoteSingle {
		return strings.Cut(value, "@")
	}

	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '\\':
			// Skip the escaped byte so an escaped quote does not read
			// as the terminator.
			i++

		case quote:
			if i+1 < len(value) && value[i+1] == '@' {
				return value[:i+1], value[i+2:], true
			}

			return value, "", true
		}
	}

	return value, "", true
}

// spellPurpose renders a purpose VALUE as its canonical wire spelling:
// bare when the bare production can express it, quoted otherwise.
// Callers hold the value; this decides only how it is written.
func spellPurpose(purposeId string) string {
	if purposeIsBareExpressible(purposeId) {
		return purposeId
	}

	return quotePurpose(purposeId)
}

// quotePurpose renders purposeId in the double-quoted form, escaping per
// the Doddish rules above. It always quotes, even when the bare form
// would do — spellPurpose is the canonical-spelling entry point.
func quotePurpose(purposeId string) string {
	var sb strings.Builder

	// Worst case every rune needs a two-byte escape, plus both quotes.
	sb.Grow(len(purposeId)*2 + 2)
	sb.WriteByte(purposeQuoteDouble)

	for _, r := range purposeId {
		switch r {
		case '\\':
			sb.WriteString(`\\`)
		case '"':
			sb.WriteString(`\"`)
		case '\n':
			sb.WriteString(`\n`)
		case '\t':
			sb.WriteString(`\t`)
		case '\r':
			sb.WriteString(`\r`)
		case '\a':
			sb.WriteString(`\a`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\v':
			sb.WriteString(`\v`)
		default:
			sb.WriteRune(r)
		}
	}

	sb.WriteByte(purposeQuoteDouble)

	return sb.String()
}

// unquotePurpose reverses spellPurpose for a wire-form purpose slot.
//
// A slot that opens with a quote rune MUST close with the same one; the
// interior is unescaped per the Doddish rules. A slot that does not open
// with a quote rune is a BARE purpose and MUST satisfy the bare
// inclusion set — this is where ruling 1's narrowing actually bites on
// the decode path, rejecting the Unicode and punctuation shapes the
// pre-#273 grammar admitted unquoted.
func unquotePurpose(slot string) (string, error) {
	if slot == "" {
		return "", ErrInvalidPurposeCharset{PurposeId: slot}
	}

	quote := rune(slot[0])

	if quote != purposeQuoteDouble && quote != purposeQuoteSingle {
		if !purposeIsBareExpressible(slot) {
			return "", newInvalidBarePurposeError(slot)
		}

		return slot, nil
	}

	if len(slot) < 2 || rune(slot[len(slot)-1]) != quote {
		return "", ErrUnterminatedQuotedPurpose{PurposeId: slot}
	}

	return unescapePurposeInterior(slot[1 : len(slot)-1]), nil
}

// unescapePurposeInterior applies the Doddish escape rules to the text
// between a quoted purpose's delimiters. A trailing lone backslash is
// written through literally rather than eating the closing quote; the
// closing quote was already removed by the caller, so there is nothing
// left to escape.
func unescapePurposeInterior(interior string) string {
	if !strings.ContainsRune(interior, '\\') {
		return interior
	}

	var sb strings.Builder
	sb.Grow(len(interior))

	runes := []rune(interior)

	for i := 0; i < len(runes); i++ {
		if runes[i] != '\\' || i == len(runes)-1 {
			sb.WriteRune(runes[i])
			continue
		}

		i++

		switch runes[i] {
		case 'n':
			sb.WriteRune('\n')
		case 't':
			sb.WriteRune('\t')
		case 'r':
			sb.WriteRune('\r')
		case 'a':
			sb.WriteRune('\a')
		case 'b':
			sb.WriteRune('\b')
		case 'f':
			sb.WriteRune('\f')
		case 'v':
			sb.WriteRune('\v')
		default:
			// Unknown escape: pass the following character through
			// unchanged, per the Doddish rule. This is what makes \"
			// and \\ round-trip without needing their own cases.
			sb.WriteRune(runes[i])
		}
	}

	return sb.String()
}

// newInvalidBarePurposeError reports the first rune of slot that the
// bare production rejects, so the error names the offending character
// rather than just the whole slot.
func newInvalidBarePurposeError(slot string) error {
	for _, r := range slot {
		if !purposeRuneIsBareExpressible(r) {
			return ErrInvalidPurposeCharset{PurposeId: slot, Rune: r}
		}
	}

	return ErrInvalidPurposeCharset{PurposeId: slot}
}

// SetPurposeFromWireSlot sets the Id's purpose from a WIRE-FORM purpose
// slot — the bytes between the start of a markl ID and its `@` join,
// bare or quoted.
//
// This is the single chokepoint for the wire path, and it exists
// because splitting it into "unquote" then "validate" invited exactly
// the bug it now prevents. Both steps are mandatory and neither is
// sufficient alone: unquoting without validating lets an `@`-bearing
// value through (§2.2), and validating without unquoting lets a bare
// `my thing` through, since the value-level rule bans only `@`. During
// the madder#273 implementation the two wire-parse paths were wired
// independently and one of them missed a step; the tests caught it, but
// a comment saying "remember both" is not an enforcement mechanism.
//
// Callers that already hold a purpose VALUE (not a wire slot) — a
// decoded Id, a registry constant, a caller-supplied argument — want
// SetPurposeId instead. Passing a value here would treat a leading
// quote character as quoting rather than as content.
func (id *Id) SetPurposeFromWireSlot(slot string) (err error) {
	var purposeId string

	if purposeId, err = unquotePurpose(slot); err != nil {
		return err
	}

	return id.SetPurposeId(purposeId)
}
