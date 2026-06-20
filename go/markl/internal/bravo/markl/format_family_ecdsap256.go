package markl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/amarbel-llc/piggy/go/markl/internal/0/domain_interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

var ErrEcdsaP256SSHAgentNotConnected, IsErrEcdsaP256SSHAgentNotConnected = errors.MakeTypedSentinel[pkgErrDisamb](
	"ecdsa P256 SSH agent signer not connected",
)

func EcdsaP256Verify(pub, message, sig domain_interfaces.MarklId) (err error) {
	compressed := pub.GetBytes()

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return errors.Errorf("invalid compressed P-256 point")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	sigBytes := sig.GetBytes()
	if len(sigBytes) != 64 {
		return errors.Errorf("invalid ECDSA P256 signature length: %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:64])

	digest := sha256.Sum256(message.GetBytes())

	if !ecdsa.Verify(pubKey, digest[:], r, s) {
		return errors.Err422UnprocessableEntity.Errorf(
			"invalid ECDSA P256 signature: %q",
			sig.StringWithFormat(),
		)
	}

	return nil
}

// NOTE (piggy#183): parseSSHEcdsaSignatureBlob (SSH-wire ECDSA signature
// -> fixed 64-byte r‖s) lived here in madder, but its only caller is the
// agent-side signer, which moves to go/markl/agent. Keeping it here would
// pull golang.org/x/crypto/ssh into the dep-light core, so it ports to the
// agent package instead — the core stays ssh-free.

func makeStubEcdsaP256SSHFormat() {
	formats[FormatIdEcdsaP256SSH] = FormatSec{
		Id:          FormatIdEcdsaP256SSH,
		Size:        33,
		PubFormatId: FormatIdEcdsaP256Pub,
		GetPublicKey: func(_ domain_interfaces.MarklId) ([]byte, error) {
			return nil, errors.Wrap(ErrEcdsaP256SSHAgentNotConnected)
		},
		SigFormatId: FormatIdEcdsaP256Sig,
		Sign: func(
			_, _ domain_interfaces.MarklId,
			_ io.Reader,
		) ([]byte, error) {
			return nil, errors.Wrap(ErrEcdsaP256SSHAgentNotConnected)
		},
	}
}
