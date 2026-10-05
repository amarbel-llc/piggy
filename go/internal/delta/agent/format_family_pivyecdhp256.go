package agent

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"sync"

	domain_interfaces "code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/pivy"
)

// PivyEcdhP256GetIOWrapper builds a pivy IOWrapper that encrypts to, and
// decrypts for, a PIV slot-9D ECDH recipient (the pivy_ecdh_p256_pub
// pubkey carried by id).
//
// The age stanza format is dewey's pivy.IOWrapper, unchanged, so blobs
// already written stay readable. The on-card ECDH is NOT dewey's agent
// client: it is this package's agentECDH. dewey v0.5.0's client reads
// only the reply framing of the C pivy-agent and takes piggy-agent's
// echoed extension name for the shared secret, so nothing decrypted
// through piggy-agent (confirmed by madder's bats lane over fibby at
// madder 0ee2def).
//
// The agent socket is resolved at decrypt time with ResolveAuthSock
// (PIGGY_AUTH_SOCK, then SSH_AUTH_SOCK, then PIVY_AUTH_SOCK). Building
// the wrapper and encrypting need no agent and no socket variable.
//
// A failure to reach the agent or to get a usable reply is reported as
// dewey's typed agent error, so callers keep telling it apart from a
// wrong-recipient AEAD failure with pivy.IsErrAgent.
func PivyEcdhP256GetIOWrapper(
	id domain_interfaces.MarklId,
) (ioWrapper interfaces.IOWrapper, err error) {
	compressed := bytes.Clone(id.GetBytes())

	// Check the point here. Now that the socket is resolved lazily, this
	// is the only thing that can fail at construction, and dewey's
	// DecompressP256Point alone lets 33 zero bytes through.
	if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), compressed); x == nil {
		err = errors.Errorf("%q is not a compressed P-256 point", id)
		return ioWrapper, err
	}

	pubkey, err := pivy.DecompressP256Point(compressed)
	if err != nil {
		err = errors.Wrapf(err, "parsing P-256 public key")
		return ioWrapper, err
	}

	ioWrapper = &pivy.IOWrapper{
		RecipientPubkey: pubkey,
		DecryptECDH:     agentDecryptECDH(compressed),
	}

	return ioWrapper, err
}

// agentDecryptECDH is the pivy.ECDHFunc behind the IO wrapper: resolve the
// socket now, not when the wrapper was built, and ask the agent.
func agentDecryptECDH(recipientCompressed []byte) pivy.ECDHFunc {
	return func(ephemeralPubkey []byte) ([]byte, error) {
		socketPath, err := ResolveAuthSock()
		if err != nil {
			return nil, asPivyAgentError(err)
		}

		secret, err := agentECDH(socketPath, recipientCompressed, ephemeralPubkey)
		if err != nil {
			return nil, asPivyAgentError(err)
		}

		return secret, nil
	}
}

// asPivyAgentError marks err as dewey's pivy agent error (pivy.IsErrAgent)
// while keeping its own message and chain.
func asPivyAgentError(err error) error {
	return fmt.Errorf("%w: %w", pivy.ErrAgent, err)
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
