package markl_registrations

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"math/big"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
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

// EcdsaP384Verify mirrors EcdsaP256Verify for NIST P-384: a 49-byte
// SEC1-compressed public key, a 96-byte r‖s signature, and SHA-384.
// Backs the ssh_ecdsa_nistp384_pub format added for parity with the Rust
// piggy-markl (piggy#86).
func EcdsaP384Verify(pub, message, sig domain_interfaces.MarklId) (err error) {
	compressed := pub.GetBytes()

	x, y := elliptic.UnmarshalCompressed(elliptic.P384(), compressed)
	if x == nil {
		return errors.Errorf("invalid compressed P-384 point")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     x,
		Y:     y,
	}

	sigBytes := sig.GetBytes()
	if len(sigBytes) != 96 {
		return errors.Errorf("invalid ECDSA P384 signature length: %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:48])
	s := new(big.Int).SetBytes(sigBytes[48:96])

	digest := sha512.Sum384(message.GetBytes())

	if !ecdsa.Verify(pubKey, digest[:], r, s) {
		return errors.Err422UnprocessableEntity.Errorf(
			"invalid ECDSA P384 signature: %q",
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
	markl.RegisterFormat(markl.FormatSec{
		Id:          markl.FormatIdEcdsaP256SSH,
		Size:        33,
		PubFormatId: markl.FormatIdEcdsaP256Pub,
		GetPublicKey: func(_ domain_interfaces.MarklId) ([]byte, error) {
			return nil, errors.Wrap(markl.ErrEcdsaP256SSHAgentNotConnected)
		},
		SigFormatId: markl.FormatIdEcdsaP256Sig,
		Sign: func(
			_, _ domain_interfaces.MarklId,
			_ io.Reader,
		) ([]byte, error) {
			return nil, errors.Wrap(markl.ErrEcdsaP256SSHAgentNotConnected)
		},
	})
}
