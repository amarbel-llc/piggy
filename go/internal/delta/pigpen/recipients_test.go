package pigpen

import (
	"bytes"
	"strings"
	"testing"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

func bareID(t *testing.T, format string, data []byte) markl.Id {
	t.Helper()
	var id markl.Id
	if err := id.SetMarklId(format, data); err != nil {
		t.Fatal(err)
	}
	return id
}

func purposedID(t *testing.T, purpose, format string, data []byte) markl.Id {
	t.Helper()
	id := bareID(t, format, data)
	if err := id.SetPurposeId(purpose); err != nil {
		t.Fatal(err)
	}
	return id
}

func idTexts(ids []markl.Id) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.StringWithFormat()
	}
	return out
}

func recipientFixtures(t *testing.T) (x, p, sshAuth, foreign markl.Id) {
	t.Helper()
	xpub, _ := newX25519(t)
	ppub, _ := newP256(t)
	x = mustRecipientID(t, formatAgeX25519, xpub)
	p = mustRecipientID(t, formatPivyP256, ppub)
	sshAuth = purposedID(t, markl.PurposePiggyPivAuthV1, markl.FormatIdSshEd25519Pub, fixedBytes(32, 0xc0))
	foreign = purposedID(t, "papi-pigpen-self-sig-v1", markl.FormatIdEcdsaP256Sig, fixedBytes(64, 0xd0))
	return x, p, sshAuth, foreign
}

func TestEncryptionRecipientsSkipsNonEncryptionLines(t *testing.T) {
	x, p, sshAuth, foreign := recipientFixtures(t)
	doc := NewRecipientSet([]Recipient{{ID: p}, {ID: sshAuth}, {ID: foreign}, {ID: x}})

	got := idTexts(doc.EncryptionRecipients())
	want := []string{p.StringWithFormat(), x.StringWithFormat()}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("encryption recipients:\n got %v\nwant %v", got, want)
	}
}

func TestEncryptionRecipientsPromotesABareId(t *testing.T) {
	xpub, _ := newX25519(t)
	doc := NewRecipientSet([]Recipient{{ID: bareID(t, formatAgeX25519, xpub)}})

	got := doc.EncryptionRecipients()
	if len(got) != 1 || got[0].GetPurposeId() != markl.PurposePiggyRecipientV1 {
		t.Fatalf("a bare recipient id was not promoted to piggy-recipient-v1: %v", idTexts(got))
	}
}

func TestParseRecipientsReadsBothFileForms(t *testing.T) {
	x, p, sshAuth, foreign := recipientFixtures(t)
	want := strings.Join([]string{p.StringWithFormat(), x.StringWithFormat()}, " ")

	pigpenForm, err := NewRecipientSet([]Recipient{
		{ID: p, Comment: "yubikey"}, {ID: sshAuth}, {ID: foreign}, {ID: x},
	}).MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	// RFC 0003 lines: a comment line, a blank line, leading whitespace, an
	// inline comment, a bare-format id, and an ssh-auth entry.
	bareX := bareID(t, formatAgeX25519, x.GetBytes())
	rfc0003Form := "# recipients\n\n" +
		"  " + p.StringWithFormat() + "  # yubikey\n" +
		sshAuth.StringWithFormat() + "\n" +
		bareX.StringWithFormat() + "\n"

	for label, raw := range map[string][]byte{
		"pigpen recipient set": pigpenForm,
		"rfc 0003 lines":       []byte(rfc0003Form),
	} {
		got, err := ParseRecipients(raw)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if joined := strings.Join(idTexts(got), " "); joined != want {
			t.Errorf("%s:\n got %s\nwant %s", label, joined, want)
		}
	}
}

func TestParseRecipientsAcceptsASealedDocument(t *testing.T) {
	x, _, _, _ := recipientFixtures(t)
	sealed, err := Seal([]byte("store key"), []markl.Id{x}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecipients(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].StringWithFormat() != x.StringWithFormat() {
		t.Fatalf("recipients of a sealed document: %v", idTexts(got))
	}
}

func TestParseRecipientsRejectsWhatItCannotResolve(t *testing.T) {
	_, _, _, foreign := recipientFixtures(t)
	for label, raw := range map[string]string{
		"a pointer document":                   "---\n- kind=\"papi-http\"\n- locator=\"https://example.com\"\n! pigpen-pointer-v1\n---\n",
		"an rfc 0003 line in a foreign format": foreign.StringWithFormat() + "\n",
		"an rfc 0003 line that is not an id":   "not-a-markl-id\n",
	} {
		_, err := ParseRecipients([]byte(raw))
		if err == nil {
			t.Errorf("%s: accepted, want rejection", label)
			continue
		}
		if label == "a pointer document" && !strings.Contains(err.Error(), "RFC 0010") {
			t.Errorf("pointer rejection does not point at RFC 0010: %v", err)
		}
	}
}

func TestCanonicalRecipientSetIsOrderAndSpellingIndependent(t *testing.T) {
	x, p, _, _ := recipientFixtures(t)
	bareX := bareID(t, formatAgeX25519, x.GetBytes())

	canonical := CanonicalRecipientSet([]markl.Id{x, p})
	for label, ids := range map[string][]markl.Id{
		"reordered":         {p, x},
		"a bare spelling":   {p, bareX},
		"a duplicate entry": {x, p, bareX},
	} {
		if !bytes.Equal(CanonicalRecipientSet(ids), canonical) {
			t.Errorf("%s: canonical form differs", label)
		}
		if !SameRecipientSet(ids, []markl.Id{x, p}) {
			t.Errorf("%s: SameRecipientSet disagrees with the canonical form", label)
		}
	}

	if SameRecipientSet([]markl.Id{x}, []markl.Id{x, p}) {
		t.Error("a subset compared equal")
	}
	if !bytes.HasSuffix(canonical, []byte("\n")) || bytes.Count(canonical, []byte("\n")) != 2 {
		t.Errorf("canonical form is not one id per line with a trailing newline: %q", canonical)
	}
	if got := CanonicalRecipientSet(nil); len(got) != 0 {
		t.Errorf("the empty set is not empty: %q", got)
	}
}

// RFC 0008 §2.3: SSH-auth and unknown-purpose lines may sit in a sealed
// document. They carry no wrap and are not a mixed state.
func TestSealedDocumentMayCarryNonEncryptionLines(t *testing.T) {
	xpub, xident := newX25519(t)
	_, _, sshAuth, foreign := recipientFixtures(t)
	x := mustRecipientID(t, formatAgeX25519, xpub)
	plaintext := []byte("sealed beside an ssh-auth line")

	in := sealInputs{
		fileKey:      fixedBytes(fileKeyLen, 0x10),
		payloadNonce: fixedBytes(payloadNonceLen, 0x40),
		ephemeral:    [][]byte{fixedBytes(32, 0x70)},
	}
	doc, err := sealWith(plaintext, []markl.Id{x}, in)
	if err != nil {
		t.Fatal(err)
	}
	doc.Recipients = append(doc.Recipients, Recipient{ID: sshAuth}, Recipient{ID: foreign})
	canon, err := doc.canonicalHeader()
	if err != nil {
		t.Fatal(err)
	}
	doc.MAC = headerMAC(in.fileKey, canon)

	wire, err := doc.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDocument(wire)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, wire)
	}
	got, err := parsed.Open(nil, []X25519Identity{xident})
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("open: %v / %q", err, got)
	}
	if n := len(parsed.EncryptionRecipients()); n != 1 {
		t.Fatalf("encryption recipients of the sealed document: %d, want 1", n)
	}
}

func TestSealedDocumentNeedsAWrappedRecipient(t *testing.T) {
	_, _, sshAuth, _ := recipientFixtures(t)
	wire := sealedVector(t, sealedByGo)
	doc, err := ParseDocument(wire)
	if err != nil {
		t.Fatal(err)
	}
	// Swap the only (wrapped) recipient line for an unwrapped ssh-auth line.
	start := bytes.Index(wire, []byte("- "))
	end := start + bytes.IndexByte(wire[start:], '\n')
	_ = doc
	tampered := append(append(bytes.Clone(wire[:start]), "- "+sshAuth.StringWithFormat()...), wire[end:]...)
	if _, err := ParseDocument(tampered); err == nil {
		t.Fatal("a sealed document with no wrapped recipient was accepted")
	}
}
