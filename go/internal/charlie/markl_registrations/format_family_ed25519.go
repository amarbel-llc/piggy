package markl_registrations

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"

	"github.com/amarbel-llc/piggy/go/internal/0/domain_interfaces"
	markl "github.com/amarbel-llc/piggy/go/internal/bravo/markl"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

func Ed25519GeneratePrivateKey(rand io.Reader) (bites []byte, err error) {
	if _, bites, err = ed25519.GenerateKey(rand); err != nil {
		err = errors.Wrap(err)
		return bites, err
	}

	return bites, err
}

func Ed25519GetPublicKey(private domain_interfaces.MarklId) (bites []byte, err error) {
	privateBytes := private.GetBytes()

	switch len(privateBytes) {
	case ed25519.SeedSize:
		// RFC 8032 uses a 32-byte seed as the canonical private key, but
		// Go's crypto/ed25519 uses a 64-byte representation (seed ‖ pubkey)
		// and madder stores the 64-byte form (FormatSec.Size ==
		// ed25519.PrivateKeySize). Callers holding a seed must expand it
		// explicitly via ed25519.NewKeyFromSeed rather than relying on
		// implicit conversion here — otherwise they'll drift against
		// Ed25519Sign, which panics on non-64-byte input.
		err = errors.WrapSkip(1, markl.ErrEd25519SeedNotPrivateKey)
		return bites, err

	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(privateBytes)
		pubKey := privateKey.Public()
		bites = pubKey.(ed25519.PublicKey)
		return bites, err

	default:
		err = errors.Errorf(
			"unsupported key size: %d",
			len(privateBytes),
		)
		return bites, err
	}
}

func Ed25519Verify(pub, message, sig domain_interfaces.MarklId) (err error) {
	pubBytes := pub.GetBytes()

	if len(pubBytes) != ed25519.PublicKeySize {
		err = errors.Errorf(
			"unsupported ed25519 public key size: %d (expected %d)",
			len(pubBytes), ed25519.PublicKeySize,
		)
		return err
	}

	sigBytes := sig.GetBytes()

	if len(sigBytes) != ed25519.SignatureSize {
		err = errors.Errorf(
			"unsupported ed25519 signature size: %d (expected %d)",
			len(sigBytes), ed25519.SignatureSize,
		)
		return err
	}

	if err = ed25519.VerifyWithOptions(
		ed25519.PublicKey(pubBytes),
		message.GetBytes(),
		sigBytes,
		&ed25519.Options{},
	); err != nil {
		err = errors.Err422UnprocessableEntity.Errorf(
			"invalid signature: %w. Signature: %q",
			err,
			sig.StringWithFormat(),
		)
		return err
	}

	return err
}

func Ed25519Sign(
	sec domain_interfaces.MarklId,
	mes domain_interfaces.MarklId,
	readerRand io.Reader,
) (sigBites []byte, err error) {
	if readerRand == nil {
		readerRand = rand.Reader
	}

	privateBytes := sec.GetBytes()

	switch len(privateBytes) {
	case ed25519.SeedSize:
		// Same RFC 8032 seed-vs-privkey distinction Ed25519GetPublicKey
		// catches (see #15); keep the pair symmetric so external callers
		// can errors.Is against one sentinel for either function.
		err = errors.WrapSkip(1, markl.ErrEd25519SeedNotPrivateKey)
		return sigBites, err

	case ed25519.PrivateKeySize:
		// ok

	default:
		err = errors.Errorf(
			"unsupported ed25519 private key size: %d",
			len(privateBytes),
		)
		return sigBites, err
	}

	privateKey := ed25519.PrivateKey(privateBytes)

	if sigBites, err = privateKey.Sign(
		readerRand,
		mes.GetBytes(),
		&ed25519.Options{},
	); err != nil {
		err = errors.Wrap(err)
		return sigBites, err
	}

	return sigBites, err
}
