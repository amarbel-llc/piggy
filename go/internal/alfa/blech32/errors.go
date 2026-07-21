package blech32

import (
	"fmt"

	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
)

type (
	pkgErrDisamb struct{}
	pkgError     = errors.Typed[pkgErrDisamb]
)

func newPkgError(text string) pkgError {
	return errors.NewWithType[pkgErrDisamb](text)
}

var (
	ErrEmptyHRP         = newPkgError("empty HRP")
	ErrSeparatorMissing = newPkgError(
		fmt.Sprintf("separator (%q) missing", string(separator)),
	)
	ErrInvalidChecksum = newPkgError("invalid checksum")
	ErrMixedCase       = newPkgError("mixed case")

	// ErrUppercase signals an all-uppercase input. RFC 0011 §3.5
	// (linenisgreat/madder#273 ruling 6) narrows bech32's
	// all-lower-or-all-upper rule to LOWERCASE ONLY, so uppercase is now
	// its own rejection rather than an accepted alternate spelling.
	//
	// Rationale worth keeping: bech32 permits uppercase to enable QR
	// alphanumeric mode, but that mode's charset (0-9, A-Z, space,
	// $%*+-./:) has no lowercase, no `@`, and no `_` — so a markl-id can
	// never be QR-alphanumeric-encoded regardless of payload case. The
	// uppercase allowance buys markl-ids nothing, and costs one spelling
	// per identifier.
	ErrUppercase = newPkgError("uppercase: markl-ids are lowercase only")
)

type errInvalidHRPCharacter struct {
	pos  int
	char rune
}

func (err errInvalidHRPCharacter) Error() string {
	return fmt.Sprintf(
		"invalid character in human-readable part: s[%d]=%d",
		err.pos,
		err.char,
	)
}

func (err errInvalidHRPCharacter) Is(target error) bool {
	_, ok := target.(errInvalidHRPCharacter)
	return ok
}

func (err errInvalidHRPCharacter) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type errDataPortionTooShort struct {
	expected int
	actual   int
	data     string
}

func (err errDataPortionTooShort) Error() string {
	return fmt.Sprintf(
		"separator `-` at invalid position because data+checksum portion is too short. Should be at least %d but was %d (%q)",
		err.expected,
		err.actual,
		err.data,
	)
}

func (err errDataPortionTooShort) Is(target error) bool {
	_, ok := target.(errDataPortionTooShort)
	return ok
}

func (err errDataPortionTooShort) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type errInvalidCharacterInData struct {
	pos  int
	char rune
}

func (err errInvalidCharacterInData) Error() string {
	return fmt.Sprintf(
		"invalid character %q found at position %d. expected one of %q",
		string([]rune{err.char}),
		err.pos,
		charsetString,
	)
}

func (err errInvalidCharacterInData) Is(target error) bool {
	_, ok := target.(errInvalidCharacterInData)
	return ok
}

func (err errInvalidCharacterInData) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}
