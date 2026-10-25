package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// emptyExtensionAgent answers every extension with an empty payload; the
// cases under test call nothing else on it.
type emptyExtensionAgent struct{ agent.ExtendedAgent }

func (emptyExtensionAgent) Extension(string, []byte) ([]byte, error) {
	return []byte{}, nil
}

func ecdsaAgentKey(t *testing.T) *agent.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &agent.Key{Format: pub.Type(), Blob: pub.Marshal()}
}

// piggy#338: an agent that answers with an empty payload is a FAIL point,
// not a panic indexing resp[0].
func TestEmptyExtensionReplyIsAFailNotAPanic(t *testing.T) {
	keys := []*agent.Key{ecdsaAgentKey(t)}
	cases := map[string]func(){
		"ecdh":   func() { testECDH(emptyExtensionAgent{}, keys, true, ecdhExtensionNames[0]) },
		"attest": func() { testAttest(emptyExtensionAgent{}, keys, true) },
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			before := failed
			run()
			if failed != before+1 {
				t.Fatalf("want exactly one FAIL point, got %d", failed-before)
			}
		})
	}
}
