package agent

import (
	"crypto/ed25519"
	"net"
	"os"

	markl "github.com/amarbel-llc/piggy/go/internal/bravo/markl"
	"github.com/amarbel-llc/purse-first/libs/dewey/pkgs/errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func listAgentKeys(socketEnvVar string) (_ []*agent.Key, err error) {
	socket := os.Getenv(socketEnvVar)
	if socket == "" {
		return nil, errors.Errorf("%s not set", socketEnvVar)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to agent at %s", socketEnvVar)
	}
	defer errors.DeferredCloser(&err, conn)

	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list keys from %s", socketEnvVar)
	}

	return keys, nil
}

func parseSSHPublicKey(key *agent.Key) (ssh.CryptoPublicKey, error) {
	parsed, err := ssh.ParsePublicKey(key.Marshal())
	if err != nil {
		return nil, errors.Wrap(err)
	}

	cryptoPub, ok := parsed.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.Errorf("key does not implement CryptoPublicKey")
	}

	return cryptoPub, nil
}

func DiscoverSSHAgentEd25519Keys() ([]markl.Id, error) {
	discovered, err := DiscoverSSHAgentEd25519KeysVerbose()
	if err != nil {
		return nil, err
	}

	ids := make([]markl.Id, len(discovered))
	for i, dk := range discovered {
		ids[i] = dk.Id
	}

	return ids, nil
}

func DiscoverSSHAgentEd25519KeysVerbose() ([]DiscoveredKey, error) {
	return DiscoverAgentEd25519KeysVerbose("SSH_AUTH_SOCK")
}

// DiscoverAgentEd25519KeysVerbose discovers Ed25519 keys from the agent
// whose unix socket path is held in the named environment variable (e.g.
// PIGGY_AUTH_SOCK to target piggy-agent instead of the agent fronted by
// SSH_AUTH_SOCK).
func DiscoverAgentEd25519KeysVerbose(
	socketEnvVar string,
) ([]DiscoveredKey, error) {
	keys, err := listAgentKeys(socketEnvVar)
	if err != nil {
		return nil, err
	}

	var discovered []DiscoveredKey

	for _, key := range keys {
		if key.Type() != ssh.KeyAlgoED25519 {
			continue
		}

		parsed, err := parseSSHPublicKey(key)
		if err != nil {
			continue
		}

		pubKey, ok := parsed.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			continue
		}

		var id markl.Id
		if err := id.SetMarklId(markl.FormatIdEd25519SSH, []byte(pubKey)); err != nil {
			continue
		}

		discovered = append(discovered, DiscoveredKey{
			Id:      id,
			KeyType: key.Type(),
			Comment: key.Comment,
		})
	}

	return discovered, nil
}

func DiscoverSSHAgentECDHKeys() ([]markl.Id, error) {
	discovered, err := DiscoverSSHAgentECDHKeysVerbose()
	if err != nil {
		return nil, err
	}

	ids := make([]markl.Id, len(discovered))
	for i, dk := range discovered {
		ids[i] = dk.Id
	}

	return ids, nil
}

func DiscoverSSHAgentECDHKeysVerbose() ([]DiscoveredKey, error) {
	return DiscoverAgentECDHKeysVerbose("SSH_AUTH_SOCK")
}

// DiscoverAgentECDHKeysVerbose discovers ECDSA P-256 keys from the agent
// whose unix socket path is held in the named environment variable (e.g.
// PIGGY_AUTH_SOCK to target piggy-agent instead of the agent fronted by
// SSH_AUTH_SOCK).
func DiscoverAgentECDHKeysVerbose(
	socketEnvVar string,
) ([]DiscoveredKey, error) {
	keys, err := listAgentKeys(socketEnvVar)
	if err != nil {
		return nil, err
	}

	return discoverEcdsaP256KeysFromAgentKeys(keys)
}
