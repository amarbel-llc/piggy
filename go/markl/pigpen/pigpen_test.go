package pigpen

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/amarbel-llc/piggy/go/markl/pkgs/markl"
)

// --- helpers -------------------------------------------------------------

func mustRecipientID(t *testing.T, format string, pub []byte) markl.Id {
	t.Helper()
	var id markl.Id
	if err := id.SetMarklId(format, pub); err != nil {
		t.Fatalf("SetMarklId(%s): %v", format, err)
	}
	if err := id.SetPurposeId(purposeRecipient); err != nil {
		t.Fatalf("SetPurposeId: %v", err)
	}
	return id
}

func newX25519(t *testing.T) (pub []byte, ident X25519Identity) {
	t.Helper()
	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub = sk.PublicKey().Bytes()
	return pub, X25519Identity{Public: pub, Secret: sk.Bytes()}
}

// newP256 returns the compressed recipient pubkey and a software oracle
// standing in for the card.
func newP256(t *testing.T) (compressed []byte, oracle ECDHOracle) {
	t.Helper()
	sk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), sk.PublicKey().Bytes())
	compressed = elliptic.MarshalCompressed(elliptic.P256(), x, y)
	return compressed, &softwareP256Oracle{sk: sk}
}

// softwareP256Oracle implements ECDHOracle in pure software — the card
// stand-in for the prototype. A real oracle forwards to piggy-agent.
type softwareP256Oracle struct{ sk *ecdh.PrivateKey }

func (o *softwareP256Oracle) ECDH(_ markl.Id, partnerEpk []byte) ([]byte, error) {
	epub, err := p256PublicFromCompressed(partnerEpk)
	if err != nil {
		return nil, err
	}
	return o.sk.ECDH(epub) // 32-byte X-coordinate
}

// --- tests ---------------------------------------------------------------

func TestRecipientSetRoundTrip(t *testing.T) {
	pub, _ := newX25519(t)
	r := Recipient{ID: mustRecipientID(t, formatAgeX25519, pub), Comment: "laptop"}
	d := NewRecipientSet([]Recipient{r})

	out, err := d.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if d.Sealed() {
		t.Fatal("recipient set should not be Sealed()")
	}

	got, err := ParseDocument(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(got.Recipients) != 1 || got.Sealed() {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Recipients[0].Comment != "laptop" {
		t.Fatalf("comment lost: %q", got.Recipients[0].Comment)
	}
	if got.Recipients[0].ID.StringWithFormat() != r.ID.StringWithFormat() {
		t.Fatalf("id mismatch: %s vs %s", got.Recipients[0].ID.StringWithFormat(), r.ID.StringWithFormat())
	}
}

func TestSealOpenX25519(t *testing.T) {
	pub, ident := newX25519(t)
	id := mustRecipientID(t, formatAgeX25519, pub)
	plaintext := []byte("attack at dawn")

	d, err := Seal(plaintext, []markl.Id{id}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Sealed() {
		t.Fatal("sealed doc should be Sealed()")
	}

	// Exercise the full wire round-trip, not just the in-memory object.
	wire, err := d.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDocument(wire)
	if err != nil {
		t.Fatalf("parse sealed: %v\n%s", err, wire)
	}

	got, err := parsed.Open(nil, []X25519Identity{ident})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
}

func TestSealOpenP256ViaOracle(t *testing.T) {
	compressed, oracle := newP256(t)
	id := mustRecipientID(t, formatPivyP256, compressed)
	plaintext := []byte("piggy rfc0008 pigpen p256")

	d, err := Seal(plaintext, []markl.Id{id}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := d.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDocument(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, err := parsed.Open(oracle, nil)
	if err != nil {
		t.Fatalf("open via oracle: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
}

func TestMultiRecipientAnyOneOpens(t *testing.T) {
	xpub, xident := newX25519(t)
	ppub, oracle := newP256(t)
	ids := []markl.Id{
		mustRecipientID(t, formatAgeX25519, xpub),
		mustRecipientID(t, formatPivyP256, ppub),
	}
	plaintext := []byte("either key suffices")

	d, err := Seal(plaintext, ids, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Open with only the x25519 identity (no oracle).
	if got, err := d.Open(nil, []X25519Identity{xident}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("x25519 open: %v / %q", err, got)
	}
	// Open with only the P-256 oracle (no x25519 identity).
	if got, err := d.Open(oracle, nil); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("p256 open: %v / %q", err, got)
	}
}

func TestMACTamperRejected(t *testing.T) {
	pub, ident := newX25519(t)
	id := mustRecipientID(t, formatAgeX25519, pub)
	d, err := Seal([]byte("secret"), []markl.Id{id}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a payload byte after the nonce; the STREAM tag (and thus open)
	// must fail.
	d.Payload[payloadNonceLen] ^= 0xff
	if _, err := d.Open(nil, []X25519Identity{ident}); err == nil {
		t.Fatal("expected open to fail on tampered payload")
	}
}

func TestRejectAtRefWithBody(t *testing.T) {
	raw := []byte("---\n@ blake2b256-abc\n! pigpen-v1\n---\n\ninline\n")
	if _, err := ParseDocument(raw); err == nil {
		t.Fatal("expected rejection of @-ref with inline body")
	}
}

func TestCommentWithDelimitersRoundTrip(t *testing.T) {
	pub, _ := newX25519(t)
	id := mustRecipientID(t, formatAgeX25519, pub)
	// A comment may contain the wrap delimiter " < ", a leading '#', or an
	// inner "  # " — none of these must corrupt the round-trip (#1/#3).
	for _, c := range []string{"a < b", "#1 backup", "has  # inner", "plain"} {
		d := NewRecipientSet([]Recipient{{ID: id, Comment: c}})
		out, err := d.MarshalText()
		if err != nil {
			t.Fatalf("marshal %q: %v", c, err)
		}
		got, err := ParseDocument(out)
		if err != nil {
			t.Fatalf("parse %q: %v\n%s", c, err, out)
		}
		if got.Recipients[0].Comment != c {
			t.Fatalf("comment %q corrupted to %q", c, got.Recipients[0].Comment)
		}
	}
}

func TestEmptyDescriptionAbsentFromCanonicalHeader(t *testing.T) {
	pub, _ := newX25519(t)
	id := mustRecipientID(t, formatAgeX25519, pub)
	d := NewRecipientSet([]Recipient{{ID: id}})
	d.Description = "" // empty — must not render a "# " line (#4)
	canon, err := d.canonicalHeader()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canon, []byte("# ")) {
		t.Fatalf("empty description leaked into canonical header: %s", canon)
	}
}

func TestNewlineInCommentRejected(t *testing.T) {
	pub, _ := newX25519(t)
	id := mustRecipientID(t, formatAgeX25519, pub)
	// A newline would break the single-line metadata framing (#2).
	d := NewRecipientSet([]Recipient{{ID: id, Comment: "line1\nline2"}})
	if _, err := d.MarshalText(); err == nil {
		t.Fatal("expected marshal to reject newline in comment")
	}
}
