package agent

import (
	"crypto"
	"crypto/ed25519"
	"io"
	"net"
	"os"

	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type sshAgentCryptoSigner struct {
	sshSigner ssh.Signer
	publicKey ed25519.PublicKey
}

func (s *sshAgentCryptoSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *sshAgentCryptoSigner) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {
	sig, err := s.sshSigner.Sign(rand, digest)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	return sig.Blob, nil
}

// ConnectSSHAgentSigner connects to the agent at $SSH_AUTH_SOCK and
// returns a crypto.Signer backed by the agent key whose Ed25519 public
// key matches publicKey. The returned io.Closer owns the agent
// connection; close it when done signing.
func ConnectSSHAgentSigner(
	publicKey ed25519.PublicKey,
) (crypto.Signer, io.Closer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil, errors.Errorf("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to connect to SSH agent")
	}

	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil, nil, errors.Wrapf(err, "failed to list SSH agent signers")
	}

	for _, signer := range signers {
		sshPub := signer.PublicKey()

		cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
		if !ok {
			continue
		}

		pub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			continue
		}

		if !pub.Equal(publicKey) {
			continue
		}

		return &sshAgentCryptoSigner{
			sshSigner: signer,
			publicKey: pub,
		}, conn, nil
	}

	conn.Close()

	return nil, nil, errors.Errorf(
		"no matching Ed25519 key found in SSH agent",
	)
}
