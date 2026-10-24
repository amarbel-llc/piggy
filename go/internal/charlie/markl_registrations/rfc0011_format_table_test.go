//go:build test

package markl_registrations_test

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"

	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

// rfc0011Path is RFC 0011 itself, through a testdata/ symlink so the go
// test cache sees a change to it (see identifierVectorsPath).
const rfc0011Path = "testdata/0011-markl-id-format.md"

// TestRFC0011FormatTableMatchesRegistry gates RFC 0011 §5's format table
// against the formats this module registers (piggy#232): every row names
// a registered format of that size, and every registered format has a
// row. piggy#225 was this drift caught by hand.
func TestRFC0011FormatTableMatchesRegistry(t *testing.T) {
	table := loadRFC0011FormatTable(t)

	for id, size := range table {
		format, err := markl.GetFormatOrError(id)
		if err != nil {
			t.Errorf("§5 lists %q, which is not registered", id)
			continue
		}

		if got := format.GetSize(); got != size {
			t.Errorf("§5 gives %q %d bytes; the registry has %d", id, size, got)
		}
	}

	for _, id := range markl.FormatIds() {
		if _, ok := table[id]; !ok {
			t.Errorf("format %q is registered but has no row in RFC 0011 §5", id)
		}
	}
}

// loadRFC0011FormatTable reads the `| `id` | size | description |` rows
// of the first table under the "## 5. Format ID Registry" heading.
func loadRFC0011FormatTable(t *testing.T) map[string]int {
	t.Helper()

	file, err := os.Open(filepath.FromSlash(rfc0011Path))
	if err != nil {
		t.Fatalf("open %s: %v", rfc0011Path, err)
	}

	defer file.Close()

	table := map[string]int{}
	inSection, inTable := false, false
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "## "):
			inSection = strings.HasPrefix(line, "## 5. Format ID Registry")
			continue

		case !inSection:
			continue

		case !strings.HasPrefix(line, "|"):
			if inTable {
				return checkedTable(t, table)
			}

			continue
		}

		inTable = true
		cells := strings.Split(strings.Trim(line, "|"), "|")

		if len(cells) < 2 {
			continue
		}

		id := strings.TrimSpace(cells[0])
		if !strings.HasPrefix(id, "`") {
			continue // the header and its divider
		}

		size, err := strconv.Atoi(strings.TrimSpace(cells[1]))
		if err != nil {
			t.Fatalf("§5 row %q: size %q is not a number", line, cells[1])
		}

		table[strings.Trim(id, "`")] = size
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", rfc0011Path, err)
	}

	return checkedTable(t, table)
}

func checkedTable(t *testing.T, table map[string]int) map[string]int {
	t.Helper()

	if len(table) == 0 {
		t.Fatal("found no rows in RFC 0011 §5's format table; the gate would pass vacuously")
	}

	ids := make([]string, 0, len(table))
	for id := range table {
		ids = append(ids, id)
	}

	sort.Strings(ids)
	t.Logf("RFC 0011 §5 formats: %s", strings.Join(ids, " "))

	return table
}
