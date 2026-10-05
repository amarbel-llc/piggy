//go:build test

package pigpen

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

// pigpenVectorsPath is the normative pigpen-v1 vector file (RFC 0008 §10,
// RFC 0009 §8), relative to this package. The Rust crate replays the same
// file (crates/piggy-pigpen/tests/vectors.rs), so there is one source and
// no second copy to drift. Regenerate with `just codemod-pigpen-vectors`.
//
// testdata/ holds a symlink to the file's home, docs/rfcs/. The go test
// cache only tracks files opened under the module root, so reading
// docs/rfcs/ directly let a changed vector file hide behind a cached pass.
const pigpenVectorsPath = "testdata/0008-pigpen-vectors.txt"

// vectorRecord is one blank-line-separated block of `key: value` lines.
type vectorRecord map[string]string

func loadPigpenVectors(t *testing.T) []vectorRecord {
	t.Helper()

	file, err := os.Open(filepath.FromSlash(pigpenVectorsPath))
	if err != nil {
		t.Fatalf("open %s: %v", pigpenVectorsPath, err)
	}
	defer file.Close()

	var records []vectorRecord
	current := vectorRecord{}
	flush := func() {
		if len(current) > 0 {
			records = append(records, current)
			current = vectorRecord{}
		}
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<24)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		switch {
		case strings.HasPrefix(text, "#"):
			continue
		case strings.TrimSpace(text) == "":
			flush()
			continue
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok {
			t.Fatalf("%s:%d: not a `key: value` line", pigpenVectorsPath, line)
		}
		if _, dup := current[key]; dup {
			t.Fatalf("%s:%d: duplicate key %q in one record", pigpenVectorsPath, line, key)
		}
		current[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	flush()
	return records
}

func (r vectorRecord) hex(t *testing.T, key string) []byte {
	t.Helper()
	out, err := hex.DecodeString(r[key])
	if err != nil {
		t.Fatalf("%s: field %q is not hex: %v", r["name"], key, err)
	}
	return out
}

func (r vectorRecord) hexList(t *testing.T, key string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, field := range strings.Fields(r[key]) {
		b, err := hex.DecodeString(field)
		if err != nil {
			t.Fatalf("%s: field %q is not a hex list: %v", r["name"], key, err)
		}
		out = append(out, b)
	}
	return out
}

func (r vectorRecord) recipients(t *testing.T) []markl.Id {
	t.Helper()
	var out []markl.Id
	for _, field := range strings.Fields(r["recipients"]) {
		var id markl.Id
		if err := id.Set(field); err != nil {
			t.Fatalf("%s: bad recipient %q: %v", r["name"], field, err)
		}
		out = append(out, id)
	}
	return out
}

// plaintext is `plaintext` (hex), or `plaintext-zeros` (a count of zero
// bytes, so a multi-chunk case does not put 64 KiB of hex in the file).
func (r vectorRecord) plaintext(t *testing.T) []byte {
	t.Helper()
	if count, ok := r["plaintext-zeros"]; ok {
		n, err := strconv.Atoi(count)
		if err != nil {
			t.Fatalf("%s: plaintext-zeros: %v", r["name"], err)
		}
		return make([]byte, n)
	}
	return r.hex(t, "plaintext")
}

func (r vectorRecord) identities(t *testing.T) (ECDHOracle, []X25519Identity) {
	t.Helper()

	var x25519 []X25519Identity
	for _, secret := range r.hexList(t, "x25519-secrets") {
		sk, err := ecdh.X25519().NewPrivateKey(secret)
		if err != nil {
			t.Fatalf("%s: bad x25519 secret: %v", r["name"], err)
		}
		x25519 = append(x25519, X25519Identity{Public: sk.PublicKey().Bytes(), Secret: secret})
	}

	var oracle ECDHOracle
	if _, ok := r["p256-secret"]; ok {
		sk, err := ecdh.P256().NewPrivateKey(r.hex(t, "p256-secret"))
		if err != nil {
			t.Fatalf("%s: bad p256 secret: %v", r["name"], err)
		}
		oracle = &softwareP256Oracle{sk: sk}
	}
	return oracle, x25519
}

// reseal reproduces a sealed document from the record's explicit inputs.
func (r vectorRecord) reseal(t *testing.T) []byte {
	t.Helper()
	doc, err := sealWith(r.plaintext(t), r.recipients(t), sealInputs{
		fileKey:      r.hex(t, "file-key"),
		payloadNonce: r.hex(t, "payload-nonce"),
		ephemeral:    r.hexList(t, "ephemeral-secrets"),
	})
	if err != nil {
		t.Fatalf("%s: seal with the record's inputs: %v", r["name"], err)
	}
	wire, err := doc.MarshalText()
	if err != nil {
		t.Fatalf("%s: marshal: %v", r["name"], err)
	}
	return wire
}

// checkRecipientFields compares the document's encryption recipients and
// their canonical-set bytes against the record, when it carries them.
func checkRecipientFields(t *testing.T, r vectorRecord, doc *Document) {
	t.Helper()
	recipients := doc.EncryptionRecipients()

	if want, ok := r["encryption-recipients"]; ok {
		got := make([]string, len(recipients))
		for i, id := range recipients {
			got[i] = id.StringWithFormat()
		}
		if strings.Join(got, " ") != want {
			t.Fatalf("encryption recipients:\n got %s\nwant %s", strings.Join(got, " "), want)
		}
	}

	if _, ok := r["canonical-set"]; ok {
		if got, want := CanonicalRecipientSet(recipients), r.hex(t, "canonical-set"); !bytes.Equal(got, want) {
			t.Fatalf("canonical recipient set:\n got %q\nwant %q", got, want)
		}
	}
}

func parseWithoutPanicking(t *testing.T, raw []byte) (doc *Document, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parse panicked: %v", r)
		}
	}()
	return ParseDocument(raw)
}

func TestNormativePigpenVectors(t *testing.T) {
	records := loadPigpenVectors(t)
	if len(records) == 0 {
		t.Fatal("no vectors loaded")
	}

	for _, r := range records {
		t.Run(r["name"], func(t *testing.T) {
			switch r["outcome"] {
			case "open":
				replayOpenVector(t, r)
			case "normalize":
				replayNormalizeVector(t, r)
			case "recipient-set":
				replayRecipientSetVector(t, r)
			case "reject":
				replayRejectVector(t, r)
			default:
				t.Fatalf("unknown outcome %q", r["outcome"])
			}
		})
	}
}

// An `open` record is a sealed document plus identities that open it. When
// it carries seal inputs, sealing with them must reproduce the document
// byte for byte. A record with `document-sha256` instead of `document`
// names its bytes by digest; the document is then the reseal output.
func replayOpenVector(t *testing.T, r vectorRecord) {
	var wire []byte
	if _, ok := r["document"]; ok {
		wire = r.hex(t, "document")
	}

	if _, ok := r["file-key"]; ok {
		resealed := r.reseal(t)
		switch {
		case wire != nil:
			if !bytes.Equal(resealed, wire) {
				t.Fatalf("sealing with the record's inputs gives different bytes:\n got %x\nwant %x", resealed, wire)
			}
		default:
			sum := sha256.Sum256(resealed)
			if !bytes.Equal(sum[:], r.hex(t, "document-sha256")) {
				t.Fatalf("sealed document digest: got %x, want %s", sum, r["document-sha256"])
			}
			wire = resealed
		}
	}
	if wire == nil {
		t.Fatal("record has neither a document nor seal inputs")
	}

	doc, err := parseWithoutPanicking(t, wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out, err := doc.MarshalText()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, wire) {
		t.Fatalf("document changed on re-serialization:\n got %x\nwant %x", out, wire)
	}
	checkRecipientFields(t, r, doc)

	oracle, x25519 := r.identities(t)
	got, err := doc.Open(oracle, x25519)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, r.plaintext(t)) {
		t.Fatalf("plaintext: got %x, want %x", got, r.plaintext(t))
	}
}

// A `normalize` record is a document in a non-canonical spelling that a
// reader accepts and re-serializes as `normalized`.
func replayNormalizeVector(t *testing.T, r vectorRecord) {
	doc, err := parseWithoutPanicking(t, r.hex(t, "document"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out, err := doc.MarshalText()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := r.hex(t, "normalized"); !bytes.Equal(out, want) {
		t.Fatalf("normalized form:\n got %x\nwant %x", out, want)
	}

	oracle, x25519 := r.identities(t)
	got, err := doc.Open(oracle, x25519)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, r.plaintext(t)) {
		t.Fatalf("plaintext: got %x, want %x", got, r.plaintext(t))
	}
}

func replayRecipientSetVector(t *testing.T, r vectorRecord) {
	wire := r.hex(t, "document")
	doc, err := parseWithoutPanicking(t, wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Sealed() {
		t.Fatal("a recipient set parsed as sealed")
	}
	out, err := doc.MarshalText()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, wire) {
		t.Fatalf("recipient set changed on re-serialization:\n got %s\nwant %s", out, wire)
	}
	checkRecipientFields(t, r, doc)
}

// A `reject` record must fail at its `stage`: `parse`, or `open` for a
// document that is well-formed but must not release plaintext.
func replayRejectVector(t *testing.T, r vectorRecord) {
	doc, err := parseWithoutPanicking(t, r.hex(t, "document"))

	switch r["stage"] {
	case "parse":
		if err == nil {
			t.Fatal("parse accepted the document, want rejection")
		}
	case "open":
		if err != nil {
			t.Fatalf("parse rejected a document that must fail only at open: %v", err)
		}
		oracle, x25519 := r.identities(t)
		if _, err := doc.Open(oracle, x25519); err == nil {
			t.Fatal("open released plaintext, want rejection")
		}
	default:
		t.Fatalf("unknown stage %q", r["stage"])
	}
}
