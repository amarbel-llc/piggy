package pigpen_resolve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/piggy/go/internal/delta/pigpen"
)

// installResolver writes an executable `pigpen-resolver-<kind>` shell
// script into a fresh directory and makes that directory the whole PATH
// apart from /bin and /usr/bin's stand-ins the script itself needs.
//
// The file is written, closed and only then made executable, and these
// tests do not run in parallel: an exec races a still-open write fd into
// ETXTBSY otherwise (piggy#249).
func installResolver(t *testing.T, kind, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, resolverPrefix+kind)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func x25519Recipient(t *testing.T, seed byte) markl.Id {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	var id markl.Id
	if err := id.SetPurposeId(markl.PurposePiggyRecipientV1); err != nil {
		t.Fatal(err)
	}
	if err := id.SetMarklId(markl.FormatIdAgeX25519Pub, key); err != nil {
		t.Fatal(err)
	}
	return id
}

func recipientSetText(t *testing.T, ids ...markl.Id) string {
	t.Helper()
	recipients := make([]pigpen.Recipient, len(ids))
	for i, id := range ids {
		recipients[i] = pigpen.Recipient{ID: id}
	}
	wire, err := pigpen.NewRecipientSet(recipients).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func pointerText(t *testing.T, kind, locator string) []byte {
	t.Helper()
	wire, err := (&pigpen.Pointer{Kind: kind, Locator: locator}).MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestResolveReturnsTheResolversRecipientSet(t *testing.T) {
	want := x25519Recipient(t, 0x10)
	// The script proves it was handed `resolve <locator>` by refusing
	// anything else.
	installResolver(t, "test",
		`[ "$1" = resolve ] && [ "$2" = "the locator" ] || { echo "bad argv: $*" >&2; exit 3; }
cat <<'EOF'
`+recipientSetText(t, want)+`EOF
`)

	doc, err := Resolve(context.Background(), &pigpen.Pointer{Kind: "test", Locator: "the locator"})
	if err != nil {
		t.Fatal(err)
	}
	got := doc.EncryptionRecipients()
	if len(got) != 1 || got[0].StringWithFormat() != want.StringWithFormat() {
		t.Fatalf("resolved recipients: %v", got)
	}
}

func TestLoadRecipientsReadsAllThreeForms(t *testing.T) {
	want := x25519Recipient(t, 0x10)
	installResolver(t, "test", "cat <<'EOF'\n"+recipientSetText(t, want)+"EOF\n")

	for label, raw := range map[string][]byte{
		"rfc 0003 lines":       []byte(want.StringWithFormat() + "\n"),
		"pigpen recipient set": []byte(recipientSetText(t, want)),
		"pigpen pointer":       pointerText(t, "test", "anywhere"),
	} {
		got, err := LoadRecipients(context.Background(), raw)
		if err != nil {
			t.Errorf("%s: %v", label, err)
			continue
		}
		if len(got) != 1 || got[0].StringWithFormat() != want.StringWithFormat() {
			t.Errorf("%s: recipients %v", label, got)
		}
	}
}

func TestResolveFailuresNameThePointerAndTheCause(t *testing.T) {
	sealed, err := pigpen.Seal([]byte("x"), []markl.Id{x25519Recipient(t, 0x10)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealedWire, err := sealed.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	sealedPath := filepath.Join(t.TempDir(), "sealed.pigpen")
	if err := os.WriteFile(sealedPath, sealedWire, 0o600); err != nil {
		t.Fatal(err)
	}

	installResolver(t, "fails", `echo "connection refused" >&2; exit 1`)
	installResolver(t, "garbage", `echo "not a pigpen document"`)
	installResolver(t, "pointer", "cat <<'EOF'\n"+string(pointerText(t, "fails", "x"))+"EOF\n")
	installResolver(t, "sealed", `cat "`+sealedPath+`"`)

	for _, tc := range []struct {
		label, kind string
		wantInError []string
	}{
		{"a resolver that exits non-zero", "fails", []string{"connection refused"}},
		{"no such resolver", "absent", []string{"no pigpen-resolver-absent on PATH"}},
		{"output that is not a pigpen document", "garbage", []string{"did not print a pigpen recipient set"}},
		{"output that is itself a pointer", "pointer", []string{"did not print a pigpen recipient set"}},
		{"output that is a sealed document", "sealed", []string{"sealed document"}},
	} {
		_, err := Resolve(context.Background(), &pigpen.Pointer{Kind: tc.kind, Locator: "the-locator"})
		if err == nil {
			t.Errorf("%s: resolved, want an error", tc.label)
			continue
		}
		for _, want := range append(tc.wantInError, `kind="`+tc.kind+`"`, `locator="the-locator"`) {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error %q does not mention %q", tc.label, err, want)
			}
		}
	}
}

func TestResolveRefusesAKindThatIsNotAnExecutableName(t *testing.T) {
	for _, kind := range []string{"", "../evil", "a/b", "nul\x00byte"} {
		if _, err := Resolve(context.Background(), &pigpen.Pointer{Kind: kind, Locator: "l"}); err == nil {
			t.Errorf("kind %q: resolved, want refusal", kind)
		}
	}
}

func TestResolveStopsWhenTheContextEnds(t *testing.T) {
	installResolver(t, "slow", "exec sleep 30")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := Resolve(ctx, &pigpen.Pointer{Kind: "slow", Locator: "l"})
	if err == nil {
		t.Fatal("a resolver that never finishes resolved")
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("Resolve returned after %v; the context did not stop the resolver", elapsed)
	}
	if !strings.Contains(err.Error(), "did not finish") {
		t.Errorf("error %q does not say the resolver was cut off", err)
	}
}

func TestIsPointerLooksOnlyAtTheMetadataSection(t *testing.T) {
	if !IsPointer(pointerText(t, "k", "l")) {
		t.Error("a pointer document was not recognized")
	}
	for label, raw := range map[string]string{
		"rfc 0003 lines":        "# ! pigpen-pointer-v1\n",
		"a recipient set":       recipientSetText(t, x25519Recipient(t, 0x10)),
		"a type line in a body": "---\n! pigpen-v1\n---\n\n! pigpen-pointer-v1\n",
	} {
		if IsPointer([]byte(raw)) {
			t.Errorf("%s: recognized as a pointer", label)
		}
	}
}
