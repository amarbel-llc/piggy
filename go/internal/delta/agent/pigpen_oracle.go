package agent

import (
	"crypto/elliptic"
	"encoding/binary"
	"net"
	"os"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authSockEnvVars is the order an agent socket is looked up in.
// PIGGY_AUTH_SOCK overrides SSH_AUTH_SOCK for piggy's own decrypts
// (piggy#123, piggy(1) ENVIRONMENT); PIVY_AUTH_SOCK is the legacy name
// dewey's pivy package reads and is honoured last.
var authSockEnvVars = []string{"PIGGY_AUTH_SOCK", "SSH_AUTH_SOCK", "PIVY_AUTH_SOCK"}

// ResolveAuthSock returns the agent socket a decrypt should use:
// PIGGY_AUTH_SOCK, else SSH_AUTH_SOCK, else PIVY_AUTH_SOCK.
func ResolveAuthSock() (string, error) {
	for _, name := range authSockEnvVars {
		if path := os.Getenv(name); path != "" {
			return path, nil
		}
	}
	return "", errors.Errorf(
		"no agent socket: none of PIGGY_AUTH_SOCK, SSH_AUTH_SOCK or PIVY_AUTH_SOCK is set",
	)
}

const (
	ecdhExtension = "ecdh@joyent.com"

	// SSH agent protocol message numbers (draft-ietf-sshm-ssh-agent).
	sshAgentSuccess           = 6
	sshAgentExtensionResponse = 29

	p256SharedSecretSize = 32
)

// AgentECDHOracle performs the card-bound P-256 scalar multiplication
// through an ssh-agent's ecdh@joyent.com extension, which piggy-agent
// serves for the PIV slot-9D key and forwards to its upstreams. The private
// scalar never leaves the card.
//
// It satisfies pigpen's ECDHOracle interface structurally, so a sealed
// pigpen document opens with:
//
//	sock, err := agent.ResolveAuthSock()
//	plaintext, err := doc.Open(agent.AgentECDHOracle{SocketPath: sock}, nil)
//
// The extension call is implemented here, not through dewey's pivy
// client, because the two agents frame the reply differently and this
// client reads both (see parseECDHResponse).
type AgentECDHOracle struct {
	SocketPath string
}

// ECDH returns the 32-byte X-coordinate of (self_private · partnerEpk),
// where self is the recipient's pivy_ecdh_p256_pub markl id and partnerEpk
// is the SEC1-compressed ephemeral public key from the wrap.
func (oracle AgentECDHOracle) ECDH(self markl.Id, partnerEpk []byte) (secret []byte, err error) {
	format := self.GetMarklFormat()
	if format == nil || format.GetMarklFormatId() != markl.FormatIdPivyEcdhP256Pub {
		err = errors.Errorf(
			"agent ECDH needs a %s recipient, got %q",
			markl.FormatIdPivyEcdhP256Pub, self.StringWithFormat(),
		)
		return secret, err
	}

	if secret, err = agentECDH(oracle.SocketPath, self.GetBytes(), partnerEpk); err != nil {
		return nil, asAgentError(err)
	}

	return secret, nil
}

// agentECDH asks the agent at socketPath for the ECDH of the card key
// whose SEC1-compressed public half is recipientCompressed against the
// SEC1-compressed partnerEpk. It is the one ecdh@joyent.com client in this
// module: the pigpen oracle and the pivy_ecdh_p256_pub IO wrapper both
// call it.
func agentECDH(socketPath string, recipientCompressed, partnerEpk []byte) (secret []byte, err error) {
	cardKey, err := p256SSHKeyBlob(recipientCompressed)
	if err != nil {
		err = errors.Wrapf(err, "recipient key")
		return secret, err
	}

	partnerKey, err := p256SSHKeyBlob(partnerEpk)
	if err != nil {
		err = errors.Wrapf(err, "ephemeral key")
		return secret, err
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		err = errors.Wrapf(err, "connecting to the agent at %s", socketPath)
		return secret, err
	}
	defer errors.DeferredCloser(&err, conn)

	client, ok := agent.NewClient(conn).(agent.ExtendedAgent)
	if !ok {
		err = errors.Errorf("ssh agent client does not support extensions")
		return secret, err
	}

	response, err := client.Extension(ecdhExtension, ecdhRequest(cardKey, partnerKey))
	if err != nil {
		err = errors.Wrapf(err, "%s extension call", ecdhExtension)
		return secret, err
	}

	if secret, err = parseECDHResponse(response); err != nil {
		err = errors.Wrap(err)
		return secret, err
	}

	return secret, err
}

// p256SSHKeyBlob renders a SEC1-compressed P-256 point as an
// ecdsa-sha2-nistp256 SSH public-key blob, the form the extension takes
// both of its keys in.
func p256SSHKeyBlob(compressed []byte) ([]byte, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), compressed)
	if x == nil {
		return nil, errors.Errorf("not a compressed P-256 point (%d bytes)", len(compressed))
	}

	return ssh.Marshal(struct {
		KeyType string
		Curve   string
		Point   []byte
	}{
		KeyType: ssh.KeyAlgoECDSA256,
		Curve:   "nistp256",
		Point:   elliptic.Marshal(elliptic.P256(), x, y),
	}), nil
}

// ecdhRequest is the extension's contents: one outer string wrapping
// string(card key) string(partner key) uint32(flags = 0).
func ecdhRequest(cardKey, partnerKey []byte) []byte {
	inner := ssh.Marshal(struct {
		CardKey    []byte
		PartnerKey []byte
		Flags      uint32
	}{CardKey: cardKey, PartnerKey: partnerKey})

	return ssh.Marshal(struct{ Inner []byte }{Inner: inner})
}

// parseECDHResponse reads the shared secret out of either reply framing:
//
//   - SSH_AGENT_EXTENSION_RESPONSE (29), string(extension name),
//     string(secret) — what piggy-agent sends.
//   - SSH_AGENT_SUCCESS (6), string(secret) — the framing dewey's pivy
//     client was written against.
func parseECDHResponse(response []byte) ([]byte, error) {
	if len(response) == 0 {
		return nil, errors.Errorf("empty %s response", ecdhExtension)
	}

	rest := response[1:]

	switch response[0] {
	case sshAgentExtensionResponse:
		name, after, ok := readSSHString(rest)
		if !ok {
			return nil, errors.Errorf("%s response: truncated extension name", ecdhExtension)
		}
		if string(name) != ecdhExtension {
			return nil, errors.Errorf("%s response echoes extension %q", ecdhExtension, name)
		}
		rest = after

	case sshAgentSuccess:

	default:
		return nil, errors.Errorf("%s response: unexpected message type %d", ecdhExtension, response[0])
	}

	secret, after, ok := readSSHString(rest)
	if !ok {
		return nil, errors.Errorf("%s response: truncated secret", ecdhExtension)
	}
	if len(after) != 0 {
		return nil, errors.Errorf("%s response: %d trailing bytes", ecdhExtension, len(after))
	}
	if len(secret) != p256SharedSecretSize {
		return nil, errors.Errorf(
			"%s response: secret is %d bytes, want %d",
			ecdhExtension, len(secret), p256SharedSecretSize,
		)
	}

	return secret, nil
}

func readSSHString(buf []byte) (value, rest []byte, ok bool) {
	if len(buf) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(buf)
	if uint64(len(buf)-4) < uint64(n) {
		return nil, nil, false
	}
	return buf[4 : 4+n], buf[4+n:], true
}
