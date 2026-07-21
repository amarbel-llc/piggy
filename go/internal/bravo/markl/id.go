package markl

import (
	"bytes"
	"fmt"
	"slices"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"code.linenisgreat.com/piggy/go/internal/alfa/blech32"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
)

var (
	_ domain_interfaces.MarklId        = Id{}
	_ domain_interfaces.MarklIdMutable = &Id{}
)

type Id struct {
	purposeId string
	format    domain_interfaces.MarklFormat
	data      []byte
}

func (id Id) String() string {
	emptyFormat := id.format == nil
	emptyData := len(id.data) == 0
	var hrp string

	switch {
	case emptyFormat && emptyData:
		return ""

	case emptyData:
		return ""

	case emptyFormat:
		hrp = "!error-empty_format"
		fallthrough

	default:
		if hrp == "" {
			hrp = id.format.GetMarklFormatId()
		}

		bites, err := blech32.Encode(hrp, id.data)
		errors.PanicIfError(err)
		return string(bites)
	}
}

// StringWithFormat returns the RFC 0002 §3 wire-form string for the
// markl ID — identical to MarshalText output. The blech32 checksum
// binds to (format, data); the purpose, when present, is prepended
// textually after blech32 encoding so that the same (format, data)
// under different purposes shares an identical blech32 body.
func (id Id) StringWithFormat() string {
	if id.format == nil && len(id.data) == 0 {
		return ""
	}

	if len(id.data) == 0 {
		return ""
	}

	bites, err := blech32.Encode(id.format.GetMarklFormatId(), id.data)
	errors.PanicIfError(err)

	bitesString := string(bites)

	if id.purposeId != "" {
		// spellPurpose quotes when the value falls outside RFC 0011
		// §2.1's bare inclusion set; the digest slot is never quoted
		// (§2.2), so it is concatenated as-is.
		return fmt.Sprintf("%s@%s", spellPurpose(id.purposeId), bitesString)
	}

	return bitesString
}

func (id Id) GetPurposeId() string {
	return id.purposeId
}

// SetPurposeId sets the Id's purpose from a VALUE — not a wire slot.
//
// RFC 0011 constrains no purpose value: any rune sequence is a legal
// purpose, because the quoted spelling (§2.1) can carry anything the
// bare inclusion set cannot, `@` included (piggy#227). The spelling is
// decided at marshal time by spellPurpose, so nothing is rejected here.
//
// Callers holding WIRE bytes — a slot parsed out of a markl-id text
// form, bare or quoted — want SetPurposeFromWireSlot instead, which
// unquotes first. Passing wire bytes here would store the quote
// characters as part of the value.
func (id *Id) SetPurposeId(value string) error {
	id.purposeId = value
	return nil
}

func (id Id) IsEmpty() bool {
	return len(id.data) == 0
}

func (id Id) GetSize() int {
	return len(id.data)
}

func (id Id) GetBytes() []byte {
	return id.data
}

func (id Id) GetMarklFormat() domain_interfaces.MarklFormat {
	return id.format
}

func (id Id) IsNull() bool {
	if len(id.data) == 0 {
		return true
	} else if id.format == nil {
		panic("empty type")
	}

	formatHash, ok := formatHashes[id.format.GetMarklFormatId()]

	// this is not an Id for a hash, so it can never be null with non-zero data
	// contents
	if !ok {
		return false
	}

	if bytes.Equal(id.data, formatHash.null.GetBytes()) {
		return true
	}

	return false
}

// Set parses a markl ID per the RFC 0002 §4 algorithm. The wire form
// is `[purpose@]<blech32(format, data)>`: the purpose, when present,
// is textual decoration prepended after blech32 encoding, so Set
// splits on the first `@` first and then blech32-decodes the body
// against HRP=format. The checksum binds to (format, data) only.
//
// An empty value resets the Id to its null state, matching
// MarshalText's symmetric output.
func (id *Id) Set(value string) (err error) {
	if value == "" {
		id.Reset()
		return err
	}

	purpose, body, hasPurpose := splitPurposeSlot(value)

	if hasPurpose {
		if err = id.setWithPurpose(purpose, body); err != nil {
			err = errors.Wrap(err)
			return err
		}
	} else {
		if err = id.setWithoutPurpose(value); err != nil {
			err = errors.Wrap(err)
			return err
		}
	}

	return err
}

func (id *Id) setWithPurpose(purpose, body string) (err error) {
	// The caller located the join with splitPurposeSlot, which is
	// quote-aware: §2.2 permits a QUOTED purpose to contain '@'
	// (piggy#227), so the join is not simply the first one.
	if err = id.SetPurposeFromWireSlot(purpose); err != nil {
		err = errors.Wrap(err)
		return err
	}

	if err = id.setWithoutPurpose(body); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

func (id *Id) setWithoutPurpose(value string) (err error) {
	var formatId string
	var data []byte

	if formatId, data, err = blech32.DecodeString(value); err != nil {
		err = errors.Wrapf(err, "Value: %q", value)
		return err
	}

	if err = id.SetMarklId(formatId, data); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

func (id *Id) SetDigest(digest domain_interfaces.MarklId) (err error) {
	if err = id.SetPurposeId(digest.GetPurposeId()); err != nil {
		err = errors.Wrap(err)
		return err
	}

	if err = id.SetMarklId(
		digest.GetMarklFormat().GetMarklFormatId(),
		digest.GetBytes(),
	); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

func (id *Id) ReloadFormat() error {
	if id.format == nil {
		return nil
	}

	format, err := GetFormatOrError(id.format.GetMarklFormatId())
	if err != nil {
		return errors.Wrap(err)
	}

	id.format = format

	return nil
}

func (id *Id) setFormatId(formatId string) (err error) {
	if id.format, err = GetFormatOrError(formatId); err != nil {
		err = errors.Wrap(err)
		return err
	}

	if err = validatePurposeAndFormatId(id.purposeId, formatId); err != nil {
		err = errors.Wrap(err)
		return err
	}

	return err
}

func (id *Id) SetMarklId(formatId string, bites []byte) (err error) {
	if formatId == "" && len(bites) == 0 {
		id.Reset()
		return err
	}

	if err = id.setFormatId(formatId); err != nil {
		// setFormatId may have partially mutated id.format — reset to
		// preserve the ADR-0001 invariant (never format-set with empty
		// data in an observable state).
		id.Reset()
		err = errors.Wrap(err)
		return err
	}

	if err = id.setData(bites); err != nil {
		// Same rationale: setData rejected the bytes after setFormatId
		// already pinned a format; clear both to leave the Id in the
		// null state.
		id.Reset()
		err = errors.Wrap(err)
		return err
	}

	return err
}

// resetDataForFormat is the sole mutation primitive for id.data. It pins
// id.format to format and returns a writable buffer of exactly
// format.GetSize() bytes. Callers fill the buffer in place — since its
// length equals format.GetSize() by construction, the ADR-0001 invariant
// cannot be broken by length mismatch.
//
// Panics (wrapping ErrNilFormat) when format is nil: a non-empty Id has no
// meaningful interpretation without a format, and every call site in this
// package can produce one.
func (id *Id) resetDataForFormat(format domain_interfaces.MarklFormat) []byte {
	if format == nil {
		panic(errors.WrapSkip(1, ErrNilFormat))
	}

	id.format = format
	size := format.GetSize()
	id.data = slices.Grow(id.data[:0], size)[:size]

	return id.data
}

func (id *Id) setData(bites []byte) (err error) {
	// empty is permitted — it represents the null/unset Id state
	if len(bites) == 0 {
		return err
	}

	// ADR-0001: an Id with non-empty data must have a format, and
	// len(data) must equal format.GetSize().
	if id.format == nil {
		err = errors.Errorf(
			"cannot set %d bytes on Id with nil format",
			len(bites),
		)

		return err
	}

	expected := id.format.GetSize()
	actual := len(bites)

	if actual != expected {
		err = errors.Errorf(
			"wrong size for bytes: expected %d, but got %d",
			expected,
			actual,
		)

		return err
	}

	copy(id.resetDataForFormat(id.format), bites)

	return err
}

func (id *Id) Reset() {
	id.format = nil
	id.data = id.data[:0]
	id.purposeId = ""
}

func (id *Id) ResetWithPurpose(purpose string) {
	id.format = nil
	id.data = id.data[:0]
	errors.PanicIfError(id.SetPurposeId(purpose))
}

func (id *Id) ResetWith(src Id) {
	id.purposeId = src.purposeId
	id.format = src.format
	if len(src.data) == 0 {
		id.data = id.data[:0]
		return
	}
	errors.PanicIfError(id.setData(src.data))
}

func (id *Id) ResetWithOrDefaultPurpose(src Id, purpose string) {
	if src.IsEmpty() {
		id.ResetWithPurpose(purpose)
	} else {
		id.ResetWith(src)
	}
}

func (id *Id) ResetWithMarklId(src domain_interfaces.MarklId) {
	marklType := src.GetMarklFormat()
	bites := src.GetBytes()

	var marklTypeId string

	if marklType == nil && len(bites) > 0 {
		panic(
			fmt.Sprintf(
				"markl id with empty format but populated bytes: (bites: %x)",
				bites,
			),
		)
	} else if marklType != nil {
		marklTypeId = marklType.GetMarklFormatId()
	}

	errors.PanicIfError(
		id.SetPurposeId(src.GetPurposeId()),
	)

	errors.PanicIfError(
		id.SetMarklId(marklTypeId, bites),
	)
}

func (id *Id) GetBlobId() domain_interfaces.MarklId {
	return id
}
