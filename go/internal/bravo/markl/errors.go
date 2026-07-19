package markl

import (
	"bytes"
	"fmt"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
	"golang.org/x/exp/constraints"
)

// ErrInvalidPurposeCharset signals that a purpose id contains a code
// point the RFC 0002 §2.1 `purpose-char` grammar excludes: the literal
// `@` (reserved as the purpose/digest join rune, piggy#219) or any
// Unicode whitespace code point (a purpose containing whitespace has no
// bare-text-form spelling — see RFC 0002 §2.2). Beyond those two
// exclusions the charset is open — general identifiers (piggy#219),
// including `/` (e.g. `one/uno`), are legal.
type ErrInvalidPurposeCharset struct {
	PurposeId string
	Rune      rune
}

func (err ErrInvalidPurposeCharset) Error() string {
	return fmt.Sprintf(
		"invalid purpose id %q: contains %q, but a purpose must not contain %q or whitespace",
		err.PurposeId,
		err.Rune,
		'@',
	)
}

func (err ErrInvalidPurposeCharset) Is(target error) bool {
	_, ok := target.(ErrInvalidPurposeCharset)
	return ok
}

func (err ErrInvalidPurposeCharset) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type (
	pkgErrDisamb struct{}
	pkgError     = errors.Typed[pkgErrDisamb]
)

func newPkgError(text string) pkgError {
	return errors.NewWithType[pkgErrDisamb](text)
}

var ErrEmptyType = newPkgError("type is empty")

// ErrLegacyCombinedHRPWireForm signals that a markl-id wire string
// failed checksum verification under the canonical split-HRP rule
// (RFC 0002 §3.3) but verifies under the legacy combined-HRP form
// (RFC 0002 §9.1) where the entire `<purpose>@<format>` string was
// used as the blech32 HRP.
//
// The combined-HRP form shipped briefly between commits `8dc78c7`
// and the #159 revert (`fd53684`); see madder#167 for the broader
// migration story. UnmarshalText returns this in place of the bare
// blech32 ErrInvalidChecksum so callers can distinguish a legacy
// pre-v0.3.16 file from genuine corruption.
//
// Recovery — two shapes, pick one:
//
//  1. Programmatic: build a fresh markl.Id and re-marshal —
//
//     var id markl.Id
//     _ = id.SetPurposeId(legacy.Purpose)
//     _ = id.SetMarklId(legacy.FormatId, legacy.Data)
//     canonical, _ := id.MarshalText()
//
//  2. Splice: the legacy and canonical bodies differ only in the
//     last 6 chars (the checksum). Replace them with
//     SplitHRPChecksum:
//
//     body := legacy.Raw // (or just the post-`@` section)
//     canonical := body[:len(body)-6] + legacy.SplitHRPChecksum
//
// Sensitivity (#169 coupling): for `*_sec` formats, Data is the
// secret. Error() MUST NOT render Data; Raw rendering will be
// redacted when #169 ships. SplitHRPChecksum is derived public
// material and is safe to render unredacted.
type ErrLegacyCombinedHRPWireForm struct {
	Purpose          string
	FormatId         string
	Data             []byte
	SplitHRPChecksum string
	Raw              string
}

func (err ErrLegacyCombinedHRPWireForm) Error() string {
	return fmt.Sprintf(
		"legacy combined-HRP wire form for purpose %q: %q -- written by pre-v0.3.16 madder, see madder#167 for migration",
		err.Purpose,
		err.Raw,
	)
}

func (err ErrLegacyCombinedHRPWireForm) Is(target error) bool {
	_, ok := target.(ErrLegacyCombinedHRPWireForm)
	return ok
}

func (err ErrLegacyCombinedHRPWireForm) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

// ErrNilFormat signals that an Id mutation requires a non-nil MarklFormat
// but received nil. Raised via panic from resetDataForFormat — the sole
// mutation primitive — so any in-package bug that tries to populate an Id
// without first supplying a format surfaces at the point of mutation.
var ErrNilFormat = newPkgError("markl format is nil")

// ErrEd25519SeedNotPrivateKey signals that Ed25519GetPublicKey received a
// 32-byte value. RFC 8032 uses a 32-byte seed as the canonical private key,
// but Go's crypto/ed25519 uses a 64-byte representation (seed ‖ pubkey) —
// and so does madder (see FormatSec{Id: FormatIdEd25519Sec, Size:
// ed25519.PrivateKeySize}). Callers with a seed must explicitly expand it
// via ed25519.NewKeyFromSeed before presenting it as a private-key MarklId.
var ErrEd25519SeedNotPrivateKey = newPkgError(
	"ed25519 input is seed-sized (32 bytes); expected full private key (64 bytes)",
)

func MakeErrEmptyType(id domain_interfaces.MarklId) error {
	if id.GetMarklFormat() == nil {
		return errors.WrapSkip(1, ErrEmptyType)
	}

	return nil
}

func AssertIdIsNull(id domain_interfaces.MarklId) error {
	if !id.IsNull() {
		cloned, _ := Clone(id) //repool:owned
		return errors.WrapSkip(1, errIsNotNull{id: cloned})
	}

	return nil
}

type errIsNotNull struct {
	id domain_interfaces.MarklId
}

func (err errIsNotNull) Error() string {
	return fmt.Sprintf("blob id is not null %q", err.id)
}

func (err errIsNotNull) Is(target error) bool {
	_, ok := target.(errIsNotNull)
	return ok
}

func (err errIsNotNull) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

func AssertIdIsNotNull(id domain_interfaces.MarklId) error {
	if id.IsNull() {
		return errors.WrapSkip(1, ErrIsNull{Purpose: id.GetPurposeId()})
	}

	return nil
}

func AssertIdIsNotNullWithPurpose(id domain_interfaces.MarklId, purpose string) error {
	if id.IsNull() {
		return errors.WrapSkip(1, ErrIsNull{Purpose: purpose})
	}

	return nil
}

func IsErrNull(target error) bool {
	return errors.Is(target, ErrIsNull{})
}

type ErrIsNull struct {
	Purpose string
}

func (err ErrIsNull) Error() string {
	return fmt.Sprintf("markl id is null for purpose %q", err.Purpose)
}

func (err ErrIsNull) Is(target error) bool {
	_, ok := target.(ErrIsNull)
	return ok
}

func (err ErrIsNull) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type ErrNotEqual struct {
	Expected, Actual domain_interfaces.MarklId
}

func AssertEqual(expected, actual domain_interfaces.MarklId) (err error) {
	if Equals(expected, actual) {
		return err
	}

	err = ErrNotEqual{
		Expected: expected,
		Actual:   actual,
	}

	return err
}

func (err ErrNotEqual) Error() string {
	return fmt.Sprintf(
		"expected digest %q but got %q",
		err.Expected,
		err.Actual,
	)
}

func (err ErrNotEqual) Is(target error) bool {
	_, ok := target.(ErrNotEqual)
	return ok
}

func (err ErrNotEqual) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

func (err ErrNotEqual) IsDifferentHashTypes() bool {
	return err.Expected.GetMarklFormat() != err.Actual.GetMarklFormat()
}

type ErrNotEqualBytes struct {
	Expected, Actual []byte
}

func MakeErrNotEqualBytes(expected, actual []byte) (err error) {
	if bytes.Equal(expected, actual) {
		return err
	}

	err = ErrNotEqualBytes{
		Expected: expected,
		Actual:   actual,
	}

	return err
}

func (err ErrNotEqualBytes) Error() string {
	return fmt.Sprintf(
		"expected digest %x but got %x",
		err.Expected,
		err.Actual,
	)
}

func (err ErrNotEqualBytes) Is(target error) bool {
	_, ok := target.(ErrNotEqualBytes)
	return ok
}

func (err ErrNotEqualBytes) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type errLength[INTEGER constraints.Integer] [2]INTEGER

func MakeErrLength[INTEGER constraints.Integer](
	expected, actual INTEGER,
) error {
	if expected != actual {
		return errLength[INTEGER]{expected, actual}
	} else {
		return nil
	}
}

func (err errLength[_]) Error() string {
	return fmt.Sprintf(
		"expected digest to have length %d, but got %d",
		err[0],
		err[1],
	)
}

func (err errLength[_]) Is(target error) bool {
	type marker interface{ isErrLength() }
	_, ok := target.(marker)
	return ok
}

func (err errLength[_]) isErrLength() {}

func (err errLength[_]) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type errWrongHasher struct {
	expected, actual string
}

func MakeErrWrongHasher(expected, actual string) error {
	if expected != actual {
		return errWrongHasher{expected: expected, actual: actual}
	}

	return nil
}

func (err errWrongHasher) Error() string {
	return fmt.Sprintf(
		"wrong hash algorithm: expected %q but got %q",
		err.expected,
		err.actual,
	)
}

func (err errWrongHasher) Is(target error) bool {
	_, ok := target.(errWrongHasher)
	return ok
}

func (err errWrongHasher) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

func MakeErrWrongType(expected, actual string) error {
	if expected != actual {
		return errWrongType{expected: expected, actual: actual}
	}

	return nil
}

type errWrongType struct {
	expected, actual string
}

func (err errWrongType) Error() string {
	return fmt.Sprintf(
		"wrong type. expected %q but got %q",
		err.expected,
		err.actual,
	)
}

func (err errWrongType) Is(target error) bool {
	_, ok := target.(errWrongType)
	return ok
}

func (err errWrongType) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}

type ErrFormatOperationNotSupported struct {
	Format        domain_interfaces.MarklFormat
	FormatId      string
	OperationName string
}

func (err ErrFormatOperationNotSupported) Error() string {
	if err.Format == nil {
		return fmt.Sprintf(
			"nil format with id %q does not support operation %q",
			err.FormatId,
			err.OperationName,
		)
	} else {
		return fmt.Sprintf(
			"format (%T) with id %q does not support operation %q",
			err.Format,
			err.Format.GetMarklFormatId(),
			err.OperationName,
		)
	}
}

func (err ErrFormatOperationNotSupported) Is(target error) bool {
	_, ok := target.(ErrFormatOperationNotSupported)
	return ok
}

func (err ErrFormatOperationNotSupported) GetErrorType() pkgErrDisamb {
	return pkgErrDisamb{}
}
