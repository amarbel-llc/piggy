package agent

import (
	"crypto/ecdsa"
	"io"
	"math/big"
	"net"
	"os"
	"sync"

	domain_interfaces "code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/pivy"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// parseSSHEcdsaSignatureBlob converts an SSH-wire ECDSA signature blob
// (two mpints, r and s) into the fixed 64-byte r‖s form the
// ecdsa_p256_sig format expects. Lifted from madder's core
// format_family_ecdsap256.go: its only caller is the agent-side signer,
// so it lives here (the dep-light core stays ssh-free — see the note in
// markl_registrations/format_family_ecdsap256.go).
func parseSSHEcdsaSignatureBlob(blob []byte) ([]byte, error) {
	var parsed struct {
		R *big.Int
		S *big.Int
	}

	if err := ssh.Unmarshal(blob, &parsed); err != nil {
		return nil, errors.Wrapf(err, "parsing SSH ECDSA signature blob")
	}

	fixed := make([]byte, 64)

	rBytes := parsed.R.Bytes()
	sBytes := parsed.S.Bytes()

	if len(rBytes) > 32 || len(sBytes) > 32 {
		return nil, errors.Errorf(
			"ECDSA signature component too large: r=%d s=%d",
			len(rBytes),
			len(sBytes),
		)
	}

	copy(fixed[32-len(rBytes):32], rBytes)
	copy(fixed[64-len(sBytes):64], sBytes)

	return fixed, nil
}

type ecdsaP256AgentSigner struct {
	agentClient agent.Agent
	key         *agent.Key
}

func (s *ecdsaP256AgentSigner) PublicKey() ssh.PublicKey {
	return s.key
}

func (s *ecdsaP256AgentSigner) Sign(
	rand io.Reader,
	data []byte,
) (*ssh.Signature, error) {
	return s.agentClient.Sign(s.key, data)
}

// ConnectEcdsaP256AgentSigner connects to $SSH_AUTH_SOCK and returns an
// ssh.Signer backed by the agent's ECDSA P-256 key whose SEC1-compressed
// ECDH point matches compressed. The returned io.Closer owns the agent
// connection.
func ConnectEcdsaP256AgentSigner(
	compressed []byte,
) (ssh.Signer, io.Closer, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil, errors.Errorf("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to connect to SSH agent")
	}

	agentClient := agent.NewClient(conn)

	keys, err := agentClient.List()
	if err != nil {
		conn.Close()
		return nil, nil, errors.Wrapf(err, "failed to list SSH agent keys")
	}

	for _, key := range keys {
		if key.Type() != "ecdsa-sha2-nistp256" {
			continue
		}

		parsed, err := parseSSHPublicKey(key)
		if err != nil {
			continue
		}

		ecdsaPub, ok := parsed.CryptoPublicKey().(*ecdsa.PublicKey)
		if !ok {
			continue
		}

		ecdhPub, err := ecdsaPub.ECDH()
		if err != nil {
			continue
		}

		signerCompressed := pivy.CompressP256Point(ecdhPub)

		if len(signerCompressed) != len(compressed) {
			continue
		}

		match := true
		for i := range compressed {
			if signerCompressed[i] != compressed[i] {
				match = false
				break
			}
		}

		if !match {
			continue
		}

		return &ecdsaP256AgentSigner{
			agentClient: agentClient,
			key:         key,
		}, conn, nil
	}

	conn.Close()

	return nil, nil, errors.Errorf(
		"no matching ECDSA P256 key found in SSH agent",
	)
}

var ecdsaP256FormatOnce sync.Once

// RegisterEcdsaP256SSHFormat swaps the real, agent-backed signer over the
// core's erroring ecdsa_p256_ssh stub (idempotent via sync.Once). The
// signer comes from ConnectEcdsaP256AgentSigner. Adapted from madder,
// which wrote the package-private formats map directly; here we go through
// the exported markl.SwapFormat seam (the stub is guaranteed registered
// by the blank import of markl_registrations in this package).
func RegisterEcdsaP256SSHFormat(signer ssh.Signer) {
	ecdsaP256FormatOnce.Do(func() {
		errors.PanicIfError(markl.SwapFormat(
			markl.FormatIdEcdsaP256SSH,
			markl.FormatSec{
				Id:          markl.FormatIdEcdsaP256SSH,
				Size:        33,
				PubFormatId: markl.FormatIdEcdsaP256Pub,
				GetPublicKey: func(id domain_interfaces.MarklId) ([]byte, error) {
					return id.GetBytes(), nil
				},
				SigFormatId: markl.FormatIdEcdsaP256Sig,
				Sign: func(
					sec, mes domain_interfaces.MarklId,
					readerRand io.Reader,
				) ([]byte, error) {
					sshSig, err := signer.Sign(readerRand, mes.GetBytes())
					if err != nil {
						return nil, errors.Wrap(err)
					}

					return parseSSHEcdsaSignatureBlob(sshSig.Blob)
				},
			},
		))
	})
}
