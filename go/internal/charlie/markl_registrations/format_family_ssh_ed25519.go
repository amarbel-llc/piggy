package markl_registrations

import (
	"crypto/ed25519"
	"io"

	"code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
)

func makeStubSSHFormat() {
	markl.RegisterFormat(markl.FormatSec{
		Id:          markl.FormatIdEd25519SSH,
		Size:        ed25519.PublicKeySize,
		PubFormatId: markl.FormatIdEd25519Pub,
		GetPublicKey: func(_ domain_interfaces.MarklId) ([]byte, error) {
			return nil, errors.Wrap(markl.ErrEd25519SSHAgentNotConnected)
		},
		SigFormatId: markl.FormatIdEd25519Sig,
		Sign: func(
			_, _ domain_interfaces.MarklId,
			_ io.Reader,
		) ([]byte, error) {
			return nil, errors.Wrap(markl.ErrEd25519SSHAgentNotConnected)
		},
	})
}
