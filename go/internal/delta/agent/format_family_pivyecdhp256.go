package agent

import (
	"sync"

	domain_interfaces "github.com/amarbel-llc/piggy/go/internal/0/domain_interfaces"
	markl "github.com/amarbel-llc/piggy/go/internal/bravo/markl"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/interfaces"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/pivy"
)

// PivyEcdhP256GetIOWrapper builds a pivy IOWrapper that decrypts to a
// PIV slot-9D ECDH recipient (the pivy_ecdh_p256_pub pubkey carried by
// id), delegating the on-card ECDH to the agent resolved from the
// environment. Lifted verbatim (modulo imports) from madder's
// format_family_pivyecdhp256.go.
func PivyEcdhP256GetIOWrapper(
	id domain_interfaces.MarklId,
) (ioWrapper interfaces.IOWrapper, err error) {
	compressed := id.GetBytes()

	pubkey, err := pivy.DecompressP256Point(compressed)
	if err != nil {
		err = errors.Wrapf(err, "parsing P-256 public key")
		return ioWrapper, err
	}

	socketPath, err := pivy.ResolveAgentSocketPath()
	if err != nil {
		err = errors.Wrap(err)
		return ioWrapper, err
	}

	ioWrapper = &pivy.IOWrapper{
		RecipientPubkey: pubkey,
		DecryptECDH:     pivy.AgentECDHFunc(socketPath, pubkey),
	}

	return ioWrapper, err
}

var pivyEcdhP256FormatOnce sync.Once

// RegisterPivyEcdhP256Format swaps the real pivy-agent-backed
// GetIOWrapper over the core's erroring pivy_ecdh_p256 stub (idempotent
// via sync.Once). Unlike the SSH signing formats it needs no connected
// signer — PivyEcdhP256GetIOWrapper resolves the agent socket lazily at
// decrypt time — so it is fired at init() below, giving importers of this
// package the always-on pivy recipient madder's core init provided before
// the dep-light split.
func RegisterPivyEcdhP256Format() {
	pivyEcdhP256FormatOnce.Do(func() {
		errors.PanicIfError(markl.SwapFormat(
			markl.FormatIdPivyEcdhP256Pub,
			markl.FormatSec{
				Id:           markl.FormatIdPivyEcdhP256Pub,
				Size:         33,
				GetIOWrapper: PivyEcdhP256GetIOWrapper,
			},
		))
	})
}

func init() {
	RegisterPivyEcdhP256Format()
}
