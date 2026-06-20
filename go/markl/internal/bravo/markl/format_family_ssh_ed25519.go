package markl

import (
	"crypto/ed25519"
	"io"

	"github.com/amarbel-llc/piggy/go/markl/internal/0/domain_interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
)

func makeStubSSHFormat() {
	formats[FormatIdEd25519SSH] = FormatSec{
		Id:          FormatIdEd25519SSH,
		Size:        ed25519.PublicKeySize,
		PubFormatId: FormatIdEd25519Pub,
		GetPublicKey: func(_ domain_interfaces.MarklId) ([]byte, error) {
			return nil, errors.Wrap(ErrEd25519SSHAgentNotConnected)
		},
		SigFormatId: FormatIdEd25519Sig,
		Sign: func(
			_, _ domain_interfaces.MarklId,
			_ io.Reader,
		) ([]byte, error) {
			return nil, errors.Wrap(ErrEd25519SSHAgentNotConnected)
		},
	}
}
