package age

import (
	"crypto/ed25519"
	"io"
	"sync"

	domain_interfaces "github.com/amarbel-llc/piggy/go/pkgs/domain_interfaces"
	markl "github.com/amarbel-llc/piggy/go/pkgs/markl"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/age"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/bech32"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/interfaces"
)

// AgeX25519Generate mints a fresh age x25519 identity and returns its
// raw 32-byte secret scalar (the bech32 AGE-SECRET-KEY- payload).
func AgeX25519Generate(_ io.Reader) (bites []byte, err error) {
	var ageId age.Identity

	// TODO add support for injecting rand reader
	if err = ageId.GenerateIfNecessary(); err != nil {
		err = errors.Wrap(err)
		return bites, err
	}

	bech32String := ageId.String()

	if _, bites, err = bech32.Decode(bech32String); err != nil {
		err = errors.Wrap(err)
		return bites, err
	}

	return bites, err
}

// TODO verify if this is correct
func AgeX25519GetPublicKey(
	private domain_interfaces.MarklId,
) (bites []byte, err error) {
	// the ed25519 package includes a public key suffix, so we need to
	// reconstruct their version of a private key for a public key value
	privateKey := ed25519.PrivateKey(private.GetBytes())
	bites = privateKey.Public().(ed25519.PublicKey)

	return bites, err
}

// AgeX25519GetIOWrapper builds an age IOWrapper that decrypts to the
// x25519 identity whose raw secret scalar is carried by private. The
// secret is re-encoded as an AGE-SECRET-KEY- bech32 string and handed to
// dewey/age. The age secret never leaves the process.
func AgeX25519GetIOWrapper(
	private domain_interfaces.MarklId,
) (ioWrapper interfaces.IOWrapper, err error) {
	var ageId age.Identity

	var bech32String string

	if bech32String, err = bech32.Encode(
		"AGE-SECRET-KEY-",
		private.GetBytes(),
	); err != nil {
		err = errors.Wrap(err)
		return ioWrapper, err
	}

	if err = ageId.Set(bech32String); err != nil {
		err = errors.Wrap(err)
		return ioWrapper, err
	}

	ioWrapper = &ageId

	return ioWrapper, err
}

var ageX25519SecFormatOnce sync.Once

// RegisterAgeX25519SecFormat swaps the real age-backed Generate +
// GetIOWrapper over the core's erroring age_x25519_sec stub (idempotent
// via sync.Once). Fired at init() below — it needs no connected signer
// (the secret machinery is self-contained), matching madder's always-on
// age recipient before the dep-light split. Adapted from madder's direct
// formats-map registration to the exported markl.SwapFormat seam over the
// stub installed by the blank-imported markl_registrations.
func RegisterAgeX25519SecFormat() {
	ageX25519SecFormatOnce.Do(func() {
		errors.PanicIfError(markl.SwapFormat(
			markl.FormatIdAgeX25519Sec,
			markl.FormatSec{
				Id:           markl.FormatIdAgeX25519Sec,
				Size:         32,
				Generate:     AgeX25519Generate,
				GetIOWrapper: AgeX25519GetIOWrapper,
			},
		))
	})
}

func init() {
	RegisterAgeX25519SecFormat()
}
