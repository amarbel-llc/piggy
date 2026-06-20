package markl_registrations

//go:generate dagnabit export

import (
	"crypto/ed25519"

	markl "github.com/amarbel-llc/piggy/go/markl/internal/bravo/markl"
)

// Format registrations are framework infrastructure (the actual crypto
// primitives), not consumer vocabulary, so they live in this package.
// Purpose registrations and purpose-id aliases moved out to
// internal/charlie/markl_registrations as of #106 step 2/3.
func init() {
	// Ed22519
	markl.RegisterFormat(
		markl.FormatPub{
			Id:     markl.FormatIdEd25519Pub,
			Size:   ed25519.PublicKeySize,
			Verify: Ed25519Verify,
		},
	)

	markl.RegisterFormat(
		markl.FormatSec{
			Id:   markl.FormatIdEd25519Sec,
			Size: ed25519.PrivateKeySize,

			Generate: Ed25519GeneratePrivateKey,

			PubFormatId:  markl.FormatIdEd25519Pub,
			GetPublicKey: Ed25519GetPublicKey,

			SigFormatId: markl.FormatIdEd25519Sig,
			Sign:        Ed25519Sign,
		},
	)

	markl.RegisterFormat(
		markl.Format{
			Id:   markl.FormatIdEd25519Sig,
			Size: ed25519.SignatureSize,
		},
	)

	makeStubSSHFormat()

	// AgeX25519
	markl.RegisterFormat(
		markl.Format{
			Id:   markl.FormatIdAgeX25519Pub,
			Size: 32,
		},
	)

	makeStubAgeX25519SecFormat()

	// ECDSA P256
	markl.RegisterFormat(
		markl.FormatPub{
			Id:     markl.FormatIdEcdsaP256Pub,
			Size:   33,
			Verify: EcdsaP256Verify,
		},
	)

	markl.RegisterFormat(
		markl.Format{
			Id:   markl.FormatIdEcdsaP256Sig,
			Size: 64,
		},
	)

	makeStubEcdsaP256SSHFormat()

	markl.RegisterFormat(
		markl.FormatPub{
			Id:     markl.FormatIdSshEcdsaNistp256Pub,
			Size:   33,
			Verify: EcdsaP256Verify,
		},
	)

	// PivyEcdhP256
	makeStubPivyEcdhP256Format()

	// Nonce
	markl.RegisterFormat(
		markl.FormatSec{
			Id:       markl.FormatIdNonceSec,
			Size:     32,
			Generate: NonceGenerate32,
		},
	)
}
