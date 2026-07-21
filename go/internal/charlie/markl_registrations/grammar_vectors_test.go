//go:build test

package markl_registrations_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// structurallyInvalidVectors are the fixture's invalid-vector names this
// grammar CAN judge on its own. A pure PEG grammar has no way to check
// blech32 checksum validity, payload-size-per-format, or purpose/format
// registry compatibility (all semantic, RFC 0011 §3.3/§5/§6.1 — see
// marklid.peg's own Scope note), so only the structural failure
// categories go here. Everything else in fixture.Invalid is asserted to
// still PARSE (proving the grammar doesn't over-reject), with its actual
// invalidity left to the Go/Rust reference decoders.
//
// mixed_case moved here on 2026-07-20 (linenisgreat/madder#273 ruling 6,
// RFC 0011 §3.5). Case uniformity used to be a semantic check, because
// DataChar admitted both cases and only the decoders enforced the
// all-one-case rule. Lowercase-only makes case a STRUCTURAL property:
// an uppercase data portion no longer matches DataChar, so the grammar
// now rejects mixed_case on its own and asserting it still parses would
// be asserting the narrowing never happened.
var structurallyInvalidVectors = map[string]bool{
	"missing_separator":           true,
	"charset_violation":           true,
	"purpose_contains_whitespace": true,
	"mixed_case":                  true,
}

// langlangStartRule is marklid.peg's start (first) rule. langlang's
// `-input` mode always parses against the grammar's start rule (there
// is no rule-selection flag) — a successful parse's stdout is a
// highlighted tree dump rooted at that name; a failed parse instead
// prints a `path:line:col: message` line and (as of this writing)
// langlang exits 0 either way, so the tree-dump prefix is the only
// reliable success signal (mirrors hyphence's own
// grammar_vectors_test.go, hyphence#9).
const langlangStartRule = "MarklId"

var langlangFailurePattern = regexp.MustCompile(`^\S+:\d+:\d+: `)

// langlang's tree-dump output is ANSI-colored by default (no -no-color
// flag exists as of this writing) — strip SGR escape sequences before
// checking for langlangStartRule, or a literal-prefix check would
// always see the escape sequence first and never match.
var ansiSGRPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

// TestGrammarVectors cross-checks the RFC 0002 conformance fixture
// (0002-markl-id-format-vectors.json — the same vectors the Go/Rust
// reference decoders round-trip, extended by piggy#219 with the ruled
// general-identifier shapes) against
// go/internal/bravo/markl/marklid.peg via langlang -input. Closes the
// gap validate-grammar alone leaves open: a grammar can be well-formed
// and still have zero power to catch a real regression if it contains
// an accidental catch-all fallback (hyphence#9's "zero-power trap"
// lesson). marklid.peg has no catch-all production by construction,
// but this test is what verifies that claim empirically rather than by
// inspection alone.
//
// Requires the langlang binary; skips (not fails) when unavailable, so
// a plain `go test -tags test ./...` outside the langlang-wired gate
// still passes — the enforced check is `just test-grammar-vectors`,
// which builds langlang and sets LANGLANG_BIN.
func TestGrammarVectors(t *testing.T) {
	langlangBin, err := resolveLanglangBin()
	if err != nil {
		t.Skipf("skipping grammar-vector cross-check: %v (see piggy#220)", err)
	}

	grammarPeg, err := resolveMarklIdGrammarPeg()
	if err != nil {
		t.Skipf("skipping grammar-vector cross-check: %v (see piggy#220)", err)
	}

	fixture := loadRFC0002Fixture(t)

	t.Run("valid", func(t *testing.T) {
		for _, v := range fixture.Vectors {
			v := v
			t.Run(v.Name, func(t *testing.T) {
				assertParsesUnderGrammar(t, langlangBin, grammarPeg, v.Encoded)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, v := range fixture.Invalid {
			v := v
			t.Run(v.Name, func(t *testing.T) {
				if structurallyInvalidVectors[v.Name] {
					assertRejectedByGrammar(t, langlangBin, grammarPeg, v.Encoded)
				} else {
					// Semantic-only failure category (checksum, case,
					// size, or registry compatibility) — marklid.peg
					// can't and shouldn't reject these structurally;
					// their actual invalidity is the Go/Rust decoders'
					// job (see marklid.peg's Scope note). Assert the
					// grammar doesn't over-reject.
					assertParsesUnderGrammar(t, langlangBin, grammarPeg, v.Encoded)
				}
			})
		}
	})
}

func resolveLanglangBin() (string, error) {
	if bin := os.Getenv("LANGLANG_BIN"); bin != "" {
		return bin, nil
	}
	return exec.LookPath("langlang")
}

func resolveMarklIdGrammarPeg() (string, error) {
	if p := os.Getenv("MARKLID_GRAMMAR_PEG"); p != "" {
		return p, nil
	}
	p := filepath.Join("..", "..", "bravo", "markl", "marklid.peg")
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

// runLanglang runs langlang -input against content and returns the
// ANSI-stripped, trimmed stdout plus the command's exit error (if
// any). Separate stdout/stderr rather than CombinedOutput():
// interleaving order between the two streams is unspecified, and the
// success/failure checks key off stdout starting with a specific
// token — any concurrently-written stderr text could land first in a
// combined buffer and break that check spuriously.
func runLanglang(t *testing.T, langlangBin, grammarPeg, content string) (trimmed string, cmdErr error) {
	t.Helper()

	tmp, err := os.CreateTemp(t.TempDir(), "marklid-grammar-vector-*")
	if err != nil {
		t.Fatalf("create temp input: %v", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("write temp input: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp input: %v", err)
	}

	// NOT -grammar-ast: that flag returns early after printing the
	// compiled grammar's AST, before any -input matching happens.
	cmd := exec.Command(
		langlangBin,
		"-grammar", grammarPeg,
		"-input", tmp.Name(),
		"-disable-builtins",
		"-disable-spaces",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmdErr = cmd.Run()
	trimmed = strings.TrimSpace(ansiSGRPattern.ReplaceAllString(stdout.String(), ""))

	return trimmed, cmdErr
}

func parsedSuccessfully(trimmed string, cmdErr error) bool {
	return cmdErr == nil &&
		strings.HasPrefix(trimmed, langlangStartRule) &&
		!langlangFailurePattern.MatchString(trimmed)
}

func assertParsesUnderGrammar(t *testing.T, langlangBin, grammarPeg, content string) {
	t.Helper()

	trimmed, cmdErr := runLanglang(t, langlangBin, grammarPeg, content)
	if !parsedSuccessfully(trimmed, cmdErr) {
		t.Errorf("content %q did not parse under marklid.peg:\n%s", content, trimmed)
	}
}

func assertRejectedByGrammar(t *testing.T, langlangBin, grammarPeg, content string) {
	t.Helper()

	trimmed, cmdErr := runLanglang(t, langlangBin, grammarPeg, content)
	if parsedSuccessfully(trimmed, cmdErr) {
		t.Errorf("content %q parsed under marklid.peg but should have been structurally rejected:\n%s", content, trimmed)
	}
}
