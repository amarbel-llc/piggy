//go:build test

package markl

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// TestCodecDoesNotImportTerminalUI pins piggy#239: the markl codec does not
// import dewey's terminal-UI package, whose init a wasm or headless consumer
// pays for (purse-first#177, papi#62).
func TestCodecDoesNotImportTerminalUI(t *testing.T) {
	const forbidden = "code.linenisgreat.com/purse-first/libs/dewey/pkgs/ui"

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()

	for _, name := range files {
		file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if path == forbidden {
				t.Errorf("%s imports %s", name, forbidden)
			}
		}
	}
}

// TestIsNullTreatsAPanickingIdAsNull keeps IsNull's recover behaviour.
func TestIsNullTreatsAPanickingIdAsNull(t *testing.T) {
	if !IsNull(panickingId{}) {
		t.Error("IsNull of an id whose IsNull panics should be true")
	}
}

type panickingId struct{ Id }

func (panickingId) IsNull() bool { panic("boom") }
