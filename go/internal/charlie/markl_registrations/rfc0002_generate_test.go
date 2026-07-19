//go:build test && rfc0002_generate

package markl_registrations_test

// To regenerate the on-disk RFC 0002 conformance fixture, run:
//
//	just codemod-rfc0002-fixture
//
// or directly:
//
//	cd go/markl && go test -tags 'test rfc0002_generate' \
//	  -run TestGenerateRFC0002Vectors ./internal/charlie/markl_registrations/...
//
// The default test suite never invokes this generator. The committed
// JSON file is the canonical artifact; the round-trip test
// (TestRFC0002VectorsRoundTrip) verifies every entry on every CI run.
//
// SCOPE: piggy-scoped (piggy purposes + every registered format). See
// the rfc0002FixturePath doc in rfc0002_fixture_test.go and #187 for
// the cross-domain assembly question.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"

	blech32 "github.com/amarbel-llc/piggy/go/internal/alfa/blech32"
	markl "github.com/amarbel-llc/piggy/go/internal/bravo/markl"
	markl_registrations "github.com/amarbel-llc/piggy/go/internal/charlie/markl_registrations"
)

// rfc0002StablePurposes lists exactly the purpose IDs piggy registers
// canonically (ADR 0006). go/markl owns ONLY piggy's purposes; the
// dodder/madder/papi purposes whose vocabulary constants the framework
// carries are registered consumer-side by those domains, so they are
// out of scope for piggy's own fixture (see #187).
var rfc0002StablePurposes = []string{
	markl.PurposePiggyPivAuthV1,
	markl.PurposePiggyPivSigV1,
	markl.PurposePiggyPivCardAuthV1,
	markl.PurposePiggyRecipientV1,
}

// rfc0002StableFormats lists every format ID piggy registers. Sizes are
// resolved from the registry at generation time (and pinned in the
// committed fixture by each vector's payload length). The #86
// ssh_ed25519_pub / ssh_ecdsa_nistp384_pub formats — absent from
// madder's cross-domain fixture — get their first vector coverage here.
var rfc0002StableFormats = []string{
	markl.FormatIdHashSha256,
	markl.FormatIdHashBlake2b256,
	markl.FormatIdEd25519Pub,
	markl.FormatIdEd25519Sec,
	markl.FormatIdEd25519Sig,
	markl.FormatIdEd25519SSH,
	markl.FormatIdEcdsaP256Pub,
	markl.FormatIdEcdsaP256Sig,
	markl.FormatIdEcdsaP256SSH,
	markl.FormatIdSshEcdsaNistp256Pub,
	markl.FormatIdSshEd25519Pub,
	markl.FormatIdSshEcdsaNistp384Pub,
	markl.FormatIdAgeX25519Pub,
	markl.FormatIdAgeX25519Sec,
	markl.FormatIdPivyEcdhP256Pub,
	markl.FormatIdNonceSec,
}

func TestGenerateRFC0002Vectors(t *testing.T) {
	fixture := buildRFC0002Fixture(t)

	bites, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	bites = append(bites, '\n')

	if err := os.WriteFile(rfc0002FixturePath, bites, 0o644); err != nil {
		t.Fatalf("write %s: %v", rfc0002FixturePath, err)
	}

	t.Logf("wrote %d valid + %d invalid vectors to %s",
		len(fixture.Vectors), len(fixture.Invalid), rfc0002FixturePath)
}

func buildRFC0002Fixture(t *testing.T) rfc0002Fixture {
	t.Helper()

	var fixture rfc0002Fixture

	// Per-format vectors: every registered format produces one
	// purpose-less round-trip with a deterministic non-trivial payload
	// (sequence 0x00..size-1). Hash formats additionally get an
	// all-zeros vector — that pattern doubles as the format's "null"
	// state so it's load-bearing for null-comparison logic.
	for _, formatId := range rfc0002StableFormats {
		size := sizeOfFormat(t, formatId)

		fixture.Vectors = append(
			fixture.Vectors,
			makeFormatVector(t, formatId, "non_trivial", sequencePayload(size)),
		)

		if formatId == markl.FormatIdHashSha256 || formatId == markl.FormatIdHashBlake2b256 {
			fixture.Vectors = append(
				fixture.Vectors,
				makeFormatVector(t, formatId, "all_zeros", make([]byte, size)),
			)
		}
	}

	// Purpose-bearing vectors: for each stable purpose × compatible
	// format, one round-trip with the same deterministic payload. This
	// pins both the (purpose, format) compatibility table and the
	// wire-level purpose@format-data shape.
	for _, purposeId := range rfc0002StablePurposes {
		formatIds := purposeFormatIds(purposeId)
		if len(formatIds) == 0 {
			t.Fatalf("no compatible formats registered for purpose %q",
				purposeId)
		}
		sort.Strings(formatIds)

		for _, formatId := range formatIds {
			payload := sequencePayload(sizeOfFormat(t, formatId))

			fixture.Vectors = append(
				fixture.Vectors,
				makePurposeVector(t, purposeId, formatId, payload),
			)
		}
	}

	// One vector bearing a purpose absent from every registry, pinning
	// RFC §6.6's opaque-carry rule: decoders MUST round-trip unknown
	// purposes rather than reject them (madder#255). The purpose id is
	// lexically valid per §2.1 but deliberately never registered.
	fixture.Vectors = append(
		fixture.Vectors,
		makePurposeVector(
			t,
			"example-unregistered-purpose-v1",
			markl.FormatIdHashSha256,
			sequencePayload(32),
		),
	)

	// General-identifier purposes (piggy#219, RFC 0002 §2.1 general
	// class): unregistered, opaque identifiers from a consumer's own type
	// system — including the `/`-bearing object-id shape hyphence RFC
	// 0003 spells as `one/uno@<digest>` (an object pinned to a version)
	// and the bare short shape `md@<digest>` (a type pinned to its
	// definition). Neither is registered here; both must round-trip
	// opaquely exactly like example-unregistered-purpose-v1 above.
	fixture.Vectors = append(
		fixture.Vectors,
		makePurposeVector(
			t,
			"one/uno",
			markl.FormatIdHashBlake2b256,
			sequencePayload(32),
		),
		makePurposeVector(
			t,
			"md",
			markl.FormatIdHashBlake2b256,
			sequencePayload(32),
		),
	)

	// Invalid vectors. Each derives from a known-good vector by a
	// single targeted mutation, so the failure category is unambiguous.
	fixture.Invalid = buildInvalidVectors(t)

	return fixture
}

// sequencePayload returns a size-byte slice [0x00, 0x01, ..., size-1]
// truncated mod 256. Deterministic across runs and visually obvious in
// hex output, so JSON diffs are readable.
func sequencePayload(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// purposeFormatIds returns the registered compatible format IDs for a
// purpose by id. markl.Purpose doesn't expose its format-id set
// publicly, so we look up the shadow opts in markl_registrations
// (which is the registration source of truth anyway).
func purposeFormatIds(purposeId string) []string {
	for _, opts := range markl_registrations.AllPurposes {
		if opts.Id == purposeId {
			return append([]string{}, opts.FormatIds...)
		}
	}
	return nil
}

// sizeOfFormat resolves a format ID through markl's registry and
// returns its declared payload size in bytes.
func sizeOfFormat(t *testing.T, formatId string) int {
	t.Helper()
	format, err := markl.GetFormatOrError(formatId)
	if err != nil {
		t.Fatalf("GetFormatOrError(%q): %v", formatId, err)
	}
	return format.GetSize()
}

func makeFormatVector(
	t *testing.T,
	formatId, suffix string,
	payload []byte,
) rfc0002Vector {
	t.Helper()

	var id markl.Id
	if err := id.SetMarklId(formatId, payload); err != nil {
		t.Fatalf("SetMarklId(%q, %d bytes): %v", formatId, len(payload), err)
	}
	encoded, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText(%q): %v", formatId, err)
	}

	return rfc0002Vector{
		Name:       fmt.Sprintf("format/%s/%s", formatId, suffix),
		Format:     formatId,
		PayloadHex: hex.EncodeToString(payload),
		Encoded:    string(encoded),
	}
}

func makePurposeVector(
	t *testing.T,
	purposeId, formatId string,
	payload []byte,
) rfc0002Vector {
	t.Helper()

	var id markl.Id
	if err := id.SetPurposeId(purposeId); err != nil {
		t.Fatalf("SetPurposeId(%q): %v", purposeId, err)
	}
	if err := id.SetMarklId(formatId, payload); err != nil {
		t.Fatalf("SetMarklId(%q, %d bytes) under %q: %v",
			formatId, len(payload), purposeId, err)
	}
	encoded, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	return rfc0002Vector{
		Name:       fmt.Sprintf("purpose/%s/%s", purposeId, formatId),
		Purpose:    purposeId,
		Format:     formatId,
		PayloadHex: hex.EncodeToString(payload),
		Encoded:    string(encoded),
	}
}

func buildInvalidVectors(t *testing.T) []rfc0002InvalidVector {
	t.Helper()

	// Build a known-good vector to mutate.
	payload := sequencePayload(32)
	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdHashSha256, payload); err != nil {
		t.Fatalf("SetMarklId: %v", err)
	}
	good, err := id.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	out := []rfc0002InvalidVector{}

	// Mixed case: lowercase the HRP, uppercase the data.
	{
		sep := bytes.LastIndexByte(good, '-')
		mixed := append([]byte{}, good[:sep+1]...)
		for _, c := range good[sep+1:] {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			mixed = append(mixed, c)
		}
		out = append(out, rfc0002InvalidVector{
			Name:    "mixed_case",
			Encoded: string(mixed),
			Error:   "MixedCase",
		})
	}

	// Missing separator: drop every '-'.
	{
		noDash := bytes.ReplaceAll(good, []byte{'-'}, nil)
		out = append(out, rfc0002InvalidVector{
			Name:    "missing_separator",
			Encoded: string(noDash),
			Error:   "SeparatorMissing",
		})
	}

	// Wrong checksum: flip the last data byte to a different charset
	// character. The checksum is over the previous bytes; flipping the
	// last char invalidates the parity.
	{
		flipped := append([]byte{}, good...)
		last := flipped[len(flipped)-1]
		// Pick a different valid charset character.
		const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
		var alt byte
		for i := 0; i < len(charset); i++ {
			if charset[i] != last {
				alt = charset[i]
				break
			}
		}
		flipped[len(flipped)-1] = alt
		out = append(out, rfc0002InvalidVector{
			Name:    "wrong_checksum",
			Encoded: string(flipped),
			Error:   "InvalidChecksum",
		})
	}

	// Charset violation: replace a data character with 'b' (excluded
	// from blech32's alphabet).
	{
		sep := bytes.LastIndexByte(good, '-')
		bad := append([]byte{}, good...)
		bad[sep+1] = 'b'
		out = append(out, rfc0002InvalidVector{
			Name:    "charset_violation",
			Encoded: string(bad),
			Error:   "InvalidCharacter",
		})
	}

	// Wrong size: encode a 31-byte payload with the sha256 HRP via
	// blech32 directly. Decoded payload won't match the format's
	// declared 32 bytes; the SetMarklId path owns this rejection.
	{
		short := sequencePayload(31)
		bad, err := blech32.Encode(markl.FormatIdHashSha256, short)
		if err != nil {
			t.Fatalf("blech32.Encode: %v", err)
		}
		out = append(out, rfc0002InvalidVector{
			Name:    "wrong_size_for_format",
			Encoded: string(bad),
			Error:   "WrongSize",
		})
	}

	// Incompatible (purpose, format): a piggy-recipient-v1 purpose
	// (accepts only pivy_ecdh_p256_pub / age_x25519_pub) carrying an
	// ed25519_sig format. Uses a REGISTERED piggy purpose so the
	// compatibility check errors rather than GetPurpose panicking on an
	// unregistered id.
	{
		const purposeId = markl.PurposePiggyRecipientV1
		sig := sequencePayload(64)
		body, err := blech32.Encode(markl.FormatIdEd25519Sig, sig)
		if err != nil {
			t.Fatalf("blech32.Encode: %v", err)
		}
		bad := purposeId + "@" + string(body)
		out = append(out, rfc0002InvalidVector{
			Name:    "incompatible_purpose_format",
			Encoded: bad,
			Error:   "IncompatiblePurposeAndFormat",
		})
	}

	// Invalid purpose charset: a purpose containing whitespace has no
	// bare-text-form spelling (RFC 0002 §2.1 purpose-char excludes
	// whitespace; §2.2 — markl's own text form has no quoting
	// mechanism). Embedding grammars that need such a purpose (trellis,
	// hyphence) quote it on their own side before it ever reaches markl.
	{
		bad := "my thing@" + string(good)
		out = append(out, rfc0002InvalidVector{
			Name:    "purpose_contains_whitespace",
			Encoded: bad,
			Error:   "InvalidPurposeCharset",
		})
	}

	// Sanity: all invalid vectors must actually fail to round-trip
	// through Set(), which is the markl-level decoder that runs both
	// blech32 validation and (purpose, format) compatibility.
	for i, v := range out {
		var probe markl.Id
		if err := probe.Set(v.Encoded); err == nil {
			t.Errorf("invalid vector #%d (%s) was accepted by Set: %q",
				i, v.Name, v.Encoded)
		}
	}

	return out
}
