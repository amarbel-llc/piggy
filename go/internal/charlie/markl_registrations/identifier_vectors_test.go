//go:build test

package markl_registrations_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// identifierVectorsPath is RFC 0011 §7.3's identifier conformance-vector
// corpus, relative to this package.
const identifierVectorsPath = "../../../../docs/rfcs/0011-identifier-vectors.txt"

// identifierVectorDigest is an arbitrary valid bare digest slot. The
// corpus scopes itself to the PURPOSE slot, but marklid.peg's start rule
// matches a whole markl ID, so each purpose vector is embedded ahead of
// a known-good digest to be exercised through the intended production.
// Taken from marklid.peg's own conformance-vector block.
const identifierVectorDigest = "blake2b256-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd"

type identifierVector struct {
	verdict string
	slot    string
	line    int
}

// TestIdentifierVectors runs RFC 0011 §7.3's corpus against
// marklid.peg. This is the piggy half of ruling 13's drift guard
// (linenisgreat/madder#273, RFC 0011 §7.4): downstream grammars —
// trellis foremost — run the SAME file against their own identifier
// production, and any verdict mismatch not recorded in §7.4's
// divergence register fails a gate.
//
// Publishing a corpus nobody executes would be the same zero-power trap
// piggy#220 / hyphence#9 warned about one level down, so the corpus is
// gated HERE too, not merely shipped for downstream's benefit.
//
// Verdict handling, per the corpus header:
//
//   - parse         — MUST parse under marklid.peg.
//   - reject        — MUST NOT parse.
//   - parse-invalid — MUST parse (the grammar admits the shape); the
//     decoder's separate refusal is not this test's
//     business. Asserting the parse is what pins the
//     grammar/validation split.
//
// Requires the langlang binary; skips when unavailable, matching
// TestGrammarVectors. The enforced check is `just test-grammar-vectors`.
func TestIdentifierVectors(t *testing.T) {
	langlangBin, err := resolveLanglangBin()
	if err != nil {
		t.Skipf("skipping identifier-vector cross-check: %v (see piggy#220)", err)
	}

	grammarPeg, err := resolveMarklIdGrammarPeg()
	if err != nil {
		t.Skipf("skipping identifier-vector cross-check: %v (see piggy#220)", err)
	}

	vectors := loadIdentifierVectors(t)

	if len(vectors) == 0 {
		t.Fatal("identifier vector corpus is empty; the gate would pass vacuously")
	}

	for _, v := range vectors {
		v := v

		t.Run(identifierVectorName(v), func(t *testing.T) {
			content := v.slot + "@" + identifierVectorDigest

			switch v.verdict {
			case "parse", "parse-invalid":
				assertParsesUnderGrammar(t, langlangBin, grammarPeg, content)

			case "reject":
				assertRejectedByGrammar(t, langlangBin, grammarPeg, content)

			default:
				t.Fatalf(
					"line %d: unknown verdict %q (want parse, reject, or parse-invalid)",
					v.line,
					v.verdict,
				)
			}
		})
	}
}

// identifierVectorName renders a subtest name that survives an empty or
// whitespace-only slot, both of which the corpus deliberately includes.
func identifierVectorName(v identifierVector) string {
	name := v.slot

	if strings.TrimSpace(name) == "" {
		name = "<whitespace-or-empty>"
	}

	return v.verdict + "/" + name
}

// loadIdentifierVectors parses the corpus. The format is deliberately
// trivial — `<verdict> TAB <slot>`, with the slot running verbatim to
// end-of-line — so a downstream consumer in any language can read it
// without pulling in a parser.
func loadIdentifierVectors(t *testing.T) []identifierVector {
	t.Helper()

	path := filepath.FromSlash(identifierVectorsPath)

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open identifier vector corpus %s: %v", path, err)
	}

	defer file.Close()

	var vectors []identifierVector

	scanner := bufio.NewScanner(file)

	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		verdict, slot, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf(
				"%s:%d: malformed vector %q: expected <verdict> TAB <slot>",
				path,
				lineNo,
				line,
			)
		}

		vectors = append(vectors, identifierVector{
			verdict: verdict,
			slot:    slot,
			line:    lineNo,
		})
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("read identifier vector corpus: %v", err)
	}

	return vectors
}
