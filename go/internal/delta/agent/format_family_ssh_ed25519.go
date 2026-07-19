package agent

import (
	"crypto"
	"crypto/ed25519"
	"io"
	"sync"

	domain_interfaces "code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

var sshFormatOnce sync.Once

// RegisterSSHEd25519Format swaps the real, agent-backed signer over the
// core's erroring ed25519_ssh stub (idempotent via sync.Once). The signer
// comes from ConnectSSHAgentSigner. Adapted from madder to call the
// exported markl.SwapFormat seam instead of writing the package-private
// formats map (the stub is registered by this package's blank import of
// markl_registrations).
func RegisterSSHEd25519Format(signer crypto.Signer) {
	sshFormatOnce.Do(func() {
		errors.PanicIfError(markl.SwapFormat(
			markl.FormatIdEd25519SSH,
			markl.FormatSec{
				Id:          markl.FormatIdEd25519SSH,
				Size:        ed25519.PublicKeySize,
				PubFormatId: markl.FormatIdEd25519Pub,
				GetPublicKey: func(_ domain_interfaces.MarklId) ([]byte, error) {
					pub, ok := signer.Public().(ed25519.PublicKey)
					if !ok {
						return nil, errors.Errorf("SSH agent signer public key is not Ed25519")
					}
					return []byte(pub), nil
				},
				SigFormatId: markl.FormatIdEd25519Sig,
				Sign: func(
					sec, mes domain_interfaces.MarklId,
					readerRand io.Reader,
				) ([]byte, error) {
					return signer.Sign(readerRand, mes.GetBytes(), &ed25519.Options{})
				},
			},
		))
	})
}
