//go:build test

package markl_registrations_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// importSurfaceRules is marklid.peg's FROZEN export contract
// (piggy#236): the named rules downstream grammars @import
// individually under the 2026-07-22 grammar-composition ruling (piggy →
// trellis → hyphence, papi consuming validators; piggy is the chain's
// root). Renaming or restructuring any rule listed here is a BREAKING
// CHANGE for downstream importers — if this test fails on a rename,
// that is the gate working, not the gate being stale. Extending the
// list is the non-breaking direction.
//
// String/Char are listed first deliberately: their ownership FLIPPED to
// piggy under the same ruling (trellis drops its local copy and imports
// ours), so their importability is the contract downstream depends on
// most directly.
var importSurfaceRules = []string{
	"String",
	"Char",
	"FormatData",
	"Format",
	"Data",
	"PurposeBare",
	"PurposeChar",
}

// TestGrammarImportSurface asserts langlang can @import each contract
// rule from marklid.peg, per-rule and all-at-once, and that an imported
// composition actually PARSES an input (imports resolving transitively
// — FormatData internally references FormatDataBare/String/Char, which
// are not all imported explicitly).
//
// Mechanics: marklid.peg's bytes are copied into a temp dir and the
// importing grammars written next to it with `from "./marklid.peg"` —
// the exact relative-path shape langlang's own import tests use
// (langlang go/tests/import/*.peg). The copy is byte-identical to the
// source of truth, so the contract under test (the rule names in the
// file's CONTENT) is unaffected by the staging; this also mirrors how
// downstreams consume the file, staged out of the flake output
// `.#marklid-grammar` rather than referenced in-tree.
//
// Requires the langlang binary; skips when unavailable, matching
// TestGrammarVectors. The enforced check is `just test-grammar-vectors`
// — whose -run alternation MUST name this test, the trap its recipe
// comment records.
func TestGrammarImportSurface(t *testing.T) {
	langlangBin, err := resolveLanglangBin()
	if err != nil {
		t.Skipf("skipping import-surface check: %v (see piggy#220)", err)
	}

	grammarPeg, err := resolveMarklIdGrammarPeg()
	if err != nil {
		t.Skipf("skipping import-surface check: %v (see piggy#220)", err)
	}

	pegBytes, err := os.ReadFile(grammarPeg)
	if err != nil {
		t.Fatalf("read %s: %v", grammarPeg, err)
	}

	stageDir := t.TempDir()

	stagedPeg := filepath.Join(stageDir, "marklid.peg")
	if err := os.WriteFile(stagedPeg, pegBytes, 0o644); err != nil {
		t.Fatalf("stage marklid.peg: %v", err)
	}

	writeGrammar := func(t *testing.T, name, content string) string {
		t.Helper()

		path := filepath.Join(stageDir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}

		return path
	}

	// Per-rule: each contract rule is importable on its own. The
	// importing grammar's start rule must USE the import — an unused
	// import could be discarded unresolved.
	for _, rule := range importSurfaceRules {
		rule := rule

		t.Run(rule, func(t *testing.T) {
			grammar := writeGrammar(
				t,
				"import_"+rule+".peg",
				"@import "+rule+" from \"./marklid.peg\"\n\n"+
					"Smoke <- "+rule+"\n",
			)

			assertGrammarWellFormed(t, langlangBin, grammar)
		})
	}

	// Negative control, so the per-rule checks above cannot rot into
	// the hyphence#9 zero-power trap: if langlang resolved imports
	// LAZILY, a grammar importing a rule marklid.peg does not define
	// would still validate, and every per-rule pass above would be
	// meaningless. This subtest pins the assumption they rest on — an
	// unresolvable import MUST fail grammar validation. If langlang
	// ever changes that, this fails loudly and the per-rule mechanism
	// has to move to input-driven checks.
	t.Run("nonexistent_rule_is_rejected", func(t *testing.T) {
		grammar := writeGrammar(
			t,
			"import_nonexistent.peg",
			"@import NoSuchRuleInMarklid from \"./marklid.peg\"\n\n"+
				"Smoke <- NoSuchRuleInMarklid\n",
		)

		trimmed, cmdErr := runLanglangGrammarOnly(t, langlangBin, grammar)
		if cmdErr == nil && !langlangFailurePattern.MatchString(trimmed) {
			t.Errorf(
				"importing a nonexistent rule validated cleanly — the per-rule import checks are zero-power:\n%s",
				trimmed,
			)
		}
	})

	// All-at-once, and end-to-end: a composition importing the full
	// contract parses a real markl-id-shaped input, proving imports
	// resolve transitively rather than merely tokenizing. The vector is
	// marklid.peg's own `md@…` conformance vector.
	t.Run("composite_parses_input", func(t *testing.T) {
		// Smoke mirrors marklid.peg's own MarklId structure, rebuilt
		// from the imported parts: the purpose slot is bare OR quoted
		// (the String alternative is what lets `"a@b"@…` parse — a
		// first draft omitted it and the quoted vector correctly
		// failed, which is itself evidence the input actually runs
		// through the imported rules).
		grammar := writeGrammar(
			t,
			"import_composite.peg",
			"@import String, Char, FormatData, Format, Data, PurposeBare, PurposeChar from \"./marklid.peg\"\n\n"+
				"Smoke <- ((PurposeBare / String) '@')? FormatData !.\n",
		)

		assertParsesUnderNamedGrammar(
			t,
			langlangBin,
			grammar,
			"Smoke",
			"md@blake2b256-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd",
		)

		// And the quoted spelling, exercising String/Char through the
		// same imports (ruling 2 / piggy#227's join-scan shape).
		assertParsesUnderNamedGrammar(
			t,
			langlangBin,
			grammar,
			"Smoke",
			`"a@b"@blake2b256-9ft3m74l5t2ppwjrvfg3wp380jqj2zfrm6zevxqx34sdethvey0s5vm9gd`,
		)
	})
}

// assertGrammarWellFormed runs langlang's grammar-ast pass (the same
// check `just validate-grammar` applies to marklid.peg itself) over an
// importing grammar; an unresolvable @import fails it — an assumption
// pinned by the nonexistent_rule_is_rejected negative control, not
// taken on faith.
func assertGrammarWellFormed(t *testing.T, langlangBin, grammarPath string) {
	t.Helper()

	trimmed, cmdErr := runLanglangGrammarOnly(t, langlangBin, grammarPath)
	if cmdErr != nil || langlangFailurePattern.MatchString(trimmed) {
		t.Errorf(
			"grammar %s failed langlang validation (err %v):\n%s",
			filepath.Base(grammarPath),
			cmdErr,
			trimmed,
		)
	}
}

// runLanglangGrammarOnly is runLanglang without an -input: the
// grammar-compile pass alone, exit status included (grammar-mode
// langlang exits nonzero on a bad grammar — the `validate-grammar`
// recipe depends on exactly that, unlike -input mode's always-zero
// exit the shared harness works around).
func runLanglangGrammarOnly(
	t *testing.T,
	langlangBin, grammarPath string,
) (trimmed string, cmdErr error) {
	t.Helper()

	cmd := exec.Command(
		langlangBin,
		"-grammar", grammarPath,
		"-grammar-ast",
		"-disable-builtins",
		"-disable-spaces",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmdErr = cmd.Run()

	trimmed = strings.TrimSpace(
		ansiSGRPattern.ReplaceAllString(stdout.String()+stderr.String(), ""),
	)

	return trimmed, cmdErr
}

// assertParsesUnderNamedGrammar is assertParsesUnderGrammar for a
// grammar whose start rule is not MarklId: success is the tree dump
// rooted at startRule.
func assertParsesUnderNamedGrammar(
	t *testing.T,
	langlangBin, grammarPath, startRule, content string,
) {
	t.Helper()

	trimmed, cmdErr := runLanglang(t, langlangBin, grammarPath, content)
	if cmdErr != nil ||
		!strings.HasPrefix(trimmed, startRule) ||
		langlangFailurePattern.MatchString(trimmed) {
		t.Errorf(
			"content %q did not parse under %s (err %v):\n%s",
			content,
			filepath.Base(grammarPath),
			cmdErr,
			trimmed,
		)
	}
}
