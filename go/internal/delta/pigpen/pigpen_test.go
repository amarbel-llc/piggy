package pigpen

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"code.linenisgreat.com/piggy/go/internal/alfa/blech32"
	"code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

// --- cross-language interop vectors (piggy#210) --------------------------
//
// Byte-exact wire vectors SHARED with the Rust impl's document.rs tests
// (identical hex — keep both copies in lockstep). interopSecret is a fixed
// x25519 recipient; sealedByRust/sealedByGo are the same plaintext sealed to
// it by each impl (differing only in ephemeral keys); recipientSet is a
// payload-less set both impls serialize byte-identically. Each impl opens
// BOTH sealed vectors, proving mutual read/decrypt compatibility.
const (
	interopSecret    = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	interopPlaintext = "pigpen cross-language interop vector"
	sealedByRust     = "2d2d2d0a2d2070696767792d726563697069656e742d7631406167655f7832353531395f7075622d7137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713076646d6565203c2070696770656e2d777261702d76314070696770656e5f777261705f7832353531392d6339776d35336d61706c656b3970717036746e63307a71787333646c636a77336e6c64336436376d7965763573796b616e676332797a6a65353577646b6e36793936656d3763386b36787a3632736368673976797a6b773766617233757566306373366a3637677570656e397a0a212070696770656e2d76314070696770656e5f6865616465725f6d61632d673567656b6a347038653430656c346b6c377a6679746734753767687334736b6468716e333332727a37733578307265633571733771666430720a2d2d2d0a0ac7f53412ca8bc1b9f172e5f324bf00cd58cd1e0abde0f3f63e8645efcdefc224406b9b225588ba8f25ddac4c4b674156f4fb241ca70c8a94282f6c7bdcda5129190b460a"
	sealedByGo       = "2d2d2d0a2d2070696767792d726563697069656e742d7631406167655f7832353531395f7075622d7137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713076646d6565203c2070696770656e2d777261702d76314070696770656e5f777261705f7832353531392d34673772716e67776e30386b6368306c787a7732397074797435636d72757339787968767839756530386573396463656433736d6479713879783061656761677a377a7a767a74323034333779343366707a7a7077633767356a35393267713965366d6e7936676161773735670a212070696770656e2d76314070696770656e5f6865616465725f6d61632d6c687a686b7639757165336a737534366b7764717874346737343974676d6d647272737867666737756835716b38676773657a737268676832750a2d2d2d0a0a53f7272c5a9f2895feb7b1992c5c51b8bfe1b06b422e934a43a6ed153cf1524631a96dbed8493519836e1fe8748afa9e9afe18eef52d869f00be1e0c9ad051f05df3aae4"
	recipientSet     = "2d2d2d0a232073686172656420696e7465726f7020766563746f720a2d2070696767792d726563697069656e742d7631406167655f7832353531395f7075622d7137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713076646d6565202023206c6170746f70203c206261636b75700a212070696770656e2d76310a2d2d2d0a"
)

func interopIdentity(t *testing.T) X25519Identity {
	t.Helper()
	secret, err := hex.DecodeString(interopSecret)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	return X25519Identity{Public: sk.PublicKey().Bytes(), Secret: secret}
}

func TestInteropOpensBothImplsSealedVectors(t *testing.T) {
	ident := interopIdentity(t)
	for _, tc := range []struct{ label, hexv string }{
		{"rust", sealedByRust},
		{"go", sealedByGo},
	} {
		wire, err := hex.DecodeString(tc.hexv)
		if err != nil {
			t.Fatalf("decode %s vector: %v", tc.label, err)
		}
		doc, err := ParseDocument(wire)
		if err != nil {
			t.Fatalf("parse %s-sealed vector: %v", tc.label, err)
		}
		got, err := doc.Open(nil, []X25519Identity{ident})
		if err != nil {
			t.Fatalf("open %s-sealed vector: %v", tc.label, err)
		}
		if string(got) != interopPlaintext {
			t.Fatalf("%s-sealed plaintext: got %q", tc.label, got)
		}
	}
}

func TestInteropRecipientSetVectorMatches(t *testing.T) {
	wire, err := hex.DecodeString(recipientSet)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseDocument(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Recipients) != 1 {
		t.Fatalf("recipients: %d", len(doc.Recipients))
	}
	if doc.Description != "shared interop vector" {
		t.Fatalf("description: %q", doc.Description)
	}
	if doc.Recipients[0].Comment != "laptop < backup" {
		t.Fatalf("comment: %q", doc.Recipients[0].Comment)
	}
	// Re-serialization is byte-identical to the shared vector — the exact
	// bytes the Rust impl produces (verified equal when captured).
	out, err := doc.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(out) != recipientSet {
		t.Fatalf("re-serialization differs from shared vector:\n got %s\nwant %s",
			hex.EncodeToString(out), recipientSet)
	}
}

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

// failingOracle cannot answer (agent unreachable, card refused) and counts
// how often it was asked.
type failingOracle struct{ calls int }

func (o *failingOracle) ECDH(markl.Id, []byte) ([]byte, error) {
	o.calls++
	return nil, errors.New("agent unreachable")
}

func TestOracleFailureDoesNotStopASoftwareRecipientFromOpening(t *testing.T) {
	ppub, _ := newP256(t)
	xpub, xident := newX25519(t)
	// The P-256 recipient comes first, so the oracle is asked first.
	d, err := Seal([]byte("either key suffices"), []markl.Id{
		mustRecipientID(t, formatPivyP256, ppub),
		mustRecipientID(t, formatAgeX25519, xpub),
	}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.Open(&failingOracle{}, []X25519Identity{xident})
	if err != nil || string(got) != "either key suffices" {
		t.Fatalf("open: %v / %q", err, got)
	}
}

func TestARepeatedRecipientKeyCostsOneOracleCall(t *testing.T) {
	ppub, _ := newP256(t)
	d, err := Seal([]byte("secret"), []markl.Id{mustRecipientID(t, formatPivyP256, ppub)}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d.Recipients = append(d.Recipients, d.Recipients[0], d.Recipients[0])

	oracle := &failingOracle{}
	if _, err := d.Open(oracle, nil); err == nil {
		t.Fatal("opened with an oracle that cannot answer")
	} else if !strings.Contains(err.Error(), "agent unreachable") {
		t.Errorf("error %q does not carry the oracle's failure", err)
	}
	if oracle.calls != 1 {
		t.Fatalf("the oracle was asked %d times for one key, want 1", oracle.calls)
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

func TestNonUTF8MetadataRejected(t *testing.T) {
	// A non-UTF-8 metadata body must be rejected, not preserved, so the Go and
	// Rust parsers agree on the same input (#210).
	raw := []byte("---\n# \xff\xfe not utf8\n! pigpen-v1\n---\n")
	if _, err := ParseDocument(raw); err == nil {
		t.Fatal("expected rejection of non-UTF-8 metadata body")
	}
}

// --- explicit-input seal (RFC 0009 §8) -----------------------------------

type countingReader struct{ next byte }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		r.next++
		p[i] = r.next
	}
	return len(p), nil
}

func fixedBytes(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

// fixedP256Scalar is a valid P-256 private scalar for any seed: the high
// byte stays far below the group order.
func fixedP256Scalar(seed byte) []byte {
	out := fixedBytes(32, seed)
	out[0] = 0x01
	return out
}

func TestSealWithExplicitInputsIsDeterministic(t *testing.T) {
	xpub, xident := newX25519(t)
	ppub, oracle := newP256(t)
	recipients := []markl.Id{
		mustRecipientID(t, formatAgeX25519, xpub),
		mustRecipientID(t, formatPivyP256, ppub),
	}
	plaintext := []byte("the same inputs give the same bytes")
	inputs := func() sealInputs {
		return sealInputs{
			fileKey:      fixedBytes(fileKeyLen, 0x10),
			payloadNonce: fixedBytes(payloadNonceLen, 0x40),
			ephemeral:    [][]byte{fixedBytes(32, 0x70), fixedP256Scalar(0xa0)},
		}
	}

	marshal := func(in sealInputs) []byte {
		t.Helper()
		d, err := sealWith(plaintext, recipients, in)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := d.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}

	first, second := marshal(inputs()), marshal(inputs())
	if !bytes.Equal(first, second) {
		t.Fatal("the same explicit inputs produced different documents")
	}

	changed := inputs()
	changed.ephemeral[0] = fixedBytes(32, 0x71)
	if bytes.Equal(first, marshal(changed)) {
		t.Fatal("changing an ephemeral scalar did not change the document")
	}

	doc, err := ParseDocument(first)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := doc.Open(nil, []X25519Identity{xident}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("x25519 open: %v / %q", err, got)
	}
	if got, err := doc.Open(oracle, nil); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("p256 open: %v / %q", err, got)
	}
}

func TestSealWithRejectsMismatchedInputs(t *testing.T) {
	xpub, _ := newX25519(t)
	recipients := []markl.Id{mustRecipientID(t, formatAgeX25519, xpub)}
	good := sealInputs{
		fileKey:      fixedBytes(fileKeyLen, 0x10),
		payloadNonce: fixedBytes(payloadNonceLen, 0x40),
		ephemeral:    [][]byte{fixedBytes(32, 0x70)},
	}

	for _, tc := range []struct {
		label  string
		mutate func(*sealInputs)
	}{
		{"no ephemeral scalars", func(in *sealInputs) { in.ephemeral = nil }},
		{"too many ephemeral scalars", func(in *sealInputs) {
			in.ephemeral = append(in.ephemeral, fixedBytes(32, 0x71))
		}},
		{"short file key", func(in *sealInputs) { in.fileKey = in.fileKey[:fileKeyLen-1] }},
		{"short payload nonce", func(in *sealInputs) { in.payloadNonce = in.payloadNonce[:payloadNonceLen-1] }},
	} {
		in := sealInputs{
			fileKey:      bytes.Clone(good.fileKey),
			payloadNonce: bytes.Clone(good.payloadNonce),
			ephemeral:    [][]byte{bytes.Clone(good.ephemeral[0])},
		}
		tc.mutate(&in)
		if _, err := sealWith([]byte("x"), recipients, in); err == nil {
			t.Errorf("%s: accepted, want rejection", tc.label)
		}
	}
}

// Seal with a caller-supplied reader still round-trips. It is NOT
// asserted to be reproducible: measured on go 1.26 (2026-10-05), two
// seals fed the same deterministic reader differ, because crypto/ecdh
// does not draw ephemeral keys from the reader. Reproducible output is
// sealWith's job.
func TestSealWithCallerReaderRoundTrips(t *testing.T) {
	xpub, xident := newX25519(t)
	recipients := []markl.Id{mustRecipientID(t, formatAgeX25519, xpub)}
	plaintext := []byte("round trip")

	d, err := Seal(plaintext, recipients, &countingReader{})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := d.Open(nil, []X25519Identity{xident}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("open: %v / %q", err, got)
	}
}

// --- markl-codec strictness (RFC 0008 §2.4, §2.6, §5) --------------------

func sealedVector(t *testing.T, hexv string) []byte {
	t.Helper()
	wire, err := hex.DecodeString(hexv)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// Moving the wrap and MAC ids onto the markl codec must not move a byte:
// both implementations' sealed vectors re-serialize exactly.
func TestSealedVectorsReserializeByteIdentically(t *testing.T) {
	for _, tc := range []struct{ label, hexv string }{
		{"rust", sealedByRust},
		{"go", sealedByGo},
	} {
		wire := sealedVector(t, tc.hexv)
		doc, err := ParseDocument(wire)
		if err != nil {
			t.Fatalf("parse %s-sealed vector: %v", tc.label, err)
		}
		out, err := doc.MarshalText()
		if err != nil {
			t.Fatalf("marshal %s-sealed vector: %v", tc.label, err)
		}
		if !bytes.Equal(out, wire) {
			t.Fatalf("%s-sealed vector changed on re-serialization:\n got %x\nwant %x",
				tc.label, out, wire)
		}
	}
}

func TestWrapLockMustCarryTheWrapPurpose(t *testing.T) {
	wire := sealedVector(t, sealedByGo)
	lock := []byte(" < " + markl.PurposePigpenWrapV1 + "@")
	if !bytes.Contains(wire, lock) {
		t.Fatal("vector has no wrap lock to rewrite")
	}

	for _, tc := range []struct{ label, replacement string }{
		{"recipient purpose", " < " + markl.PurposePiggyRecipientV1 + "@"},
		{"doc purpose", " < " + markl.PurposePigpenDocV1 + "@"},
		{"unknown purpose", " < someone-elses-wrap-v9@"},
		{"no purpose", " < "},
	} {
		tampered := bytes.Replace(wire, lock, []byte(tc.replacement), 1)
		if _, err := ParseDocument(tampered); err == nil {
			t.Errorf("%s: wrap lock accepted, want rejection", tc.label)
		}
	}
}

func TestWrapLockMustMatchTheRecipientFamily(t *testing.T) {
	xpub, _ := newX25519(t)
	ppub, _ := newP256(t)

	sealedToP256, err := Seal([]byte("x"), []markl.Id{mustRecipientID(t, formatPivyP256, ppub)}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256Wrap := sealedToP256.Recipients[0].Wrap

	// An X25519 recipient carrying a P-256-shaped wrap cannot serialize...
	crossed := &Document{
		Recipients: []Recipient{{ID: mustRecipientID(t, formatAgeX25519, xpub), Wrap: p256Wrap}},
		Payload:    sealedToP256.Payload,
		MAC:        sealedToP256.MAC,
	}
	if _, err := crossed.MarshalText(); err == nil {
		t.Fatal("marshal accepted a P-256 wrap on an X25519 recipient")
	}

	// ...and is rejected on parse when written by hand.
	wire, err := sealedToP256.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	p256Recipient := sealedToP256.Recipients[0].ID.StringWithFormat()
	x25519Recipient := mustRecipientID(t, formatAgeX25519, xpub).StringWithFormat()
	tampered := bytes.Replace(wire, []byte(p256Recipient), []byte(x25519Recipient), 1)
	if _, err := ParseDocument(tampered); err == nil {
		t.Fatal("parse accepted a P-256 wrap on an X25519 recipient")
	}
}

// An empty id is the markl null value, not a recipient, a wrap or a MAC.
// It must be a parse error (never a panic) and must not serialize.
func TestEmptyIdsAreRejectedNotPanickedOn(t *testing.T) {
	wire := sealedVector(t, sealedByGo)
	doc, err := ParseDocument(wire)
	if err != nil {
		t.Fatal(err)
	}
	recipient := doc.Recipients[0].ID.StringWithFormat()
	goodMAC, err := encodeMAC(doc.MAC)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		label string
		raw   []byte
	}{
		{"empty MAC lock", bytes.Replace(wire, []byte(goodMAC), nil, 1)},
		{"empty recipient with a wrap", bytes.Replace(wire, []byte(recipient), nil, 1)},
		{"empty recipient", []byte("---\n- \n! pigpen-v1\n---\n")},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: parse panicked: %v", tc.label, r)
				}
			}()
			if _, err := ParseDocument(tc.raw); err == nil {
				t.Errorf("%s: accepted, want rejection", tc.label)
			}
		}()
	}

	emptyWrap := &Document{
		Recipients: []Recipient{{ID: doc.Recipients[0].ID, Wrap: []byte{}}},
		Payload:    doc.Payload,
		MAC:        doc.MAC,
	}
	if _, err := emptyWrap.MarshalText(); err == nil {
		t.Error("marshal accepted an empty wrap")
	}

	emptyMAC := &Document{Recipients: doc.Recipients, Payload: doc.Payload, MAC: []byte{}}
	if _, err := emptyMAC.MarshalText(); err == nil {
		t.Error("marshal accepted an empty header MAC")
	}
}

func TestSecondTypeLineRejected(t *testing.T) {
	wire := sealedVector(t, sealedByGo)
	boundary := []byte("\n---\n")
	for _, extra := range []string{"\n! " + typeTag, "\n! " + typeTag + "@"} {
		doubled := bytes.Replace(wire, boundary, append([]byte(extra), boundary...), 1)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("second type line %q: parse panicked: %v", extra, r)
				}
			}()
			if _, err := ParseDocument(doubled); err == nil {
				t.Errorf("second type line %q accepted, want rejection", extra)
			}
		}()
	}
}

func TestHeaderMACLockIsBareAndFixedSize(t *testing.T) {
	wire := sealedVector(t, sealedByGo)
	typeLine := []byte("! " + typeTag + "@")
	if !bytes.Contains(wire, typeLine) {
		t.Fatal("vector has no MAC lock to rewrite")
	}

	// A purpose on the MAC lock is not the RFC 0008 §2.6 wire form.
	withPurpose := bytes.Replace(
		wire, typeLine, []byte("! "+typeTag+"@"+markl.PurposePigpenDocV1+"@"), 1,
	)
	if _, err := ParseDocument(withPurpose); err == nil {
		t.Error("MAC lock carrying a purpose accepted, want rejection")
	}

	// A MAC of the wrong length is malformed at parse, not only at open.
	short, err := blech32.Encode(markl.FormatIdPigpenHeaderMac, make([]byte, 31))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseDocument(wire)
	if err != nil {
		t.Fatal(err)
	}
	goodMAC, err := encodeMAC(doc.MAC)
	if err != nil {
		t.Fatal(err)
	}
	truncated := bytes.Replace(wire, []byte(goodMAC), short, 1)
	if _, err := ParseDocument(truncated); err == nil {
		t.Error("31-byte MAC accepted, want rejection")
	}
}
