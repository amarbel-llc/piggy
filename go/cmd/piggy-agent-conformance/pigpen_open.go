package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"os"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	piggyagent "code.linenisgreat.com/piggy/go/internal/delta/agent"
	"code.linenisgreat.com/piggy/go/internal/delta/pigpen"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// runPigpenOpen is the `pigpen-open <socket>` mode: the path a consumer
// like madder takes to unlock a store key. It seals a pigpen document to
// every P-256 key the agent lists, writes it out, reads it back and opens
// it with agent.AgentECDHOracle, so the ECDH really is done by whatever
// stands behind the agent. Then it checks that a document sealed to a key
// the agent does not hold fails as an agent error.
//
// The in-process tests in internal/delta/agent run the same calls against
// a Go stand-in; this runs them against a real agent.
func runPigpenOpen(socketPath string) int {
	recipients, err := agentP256Recipients(socketPath)
	if err != nil {
		fmt.Printf("FAIL: pigpen-open — %v\n", err)
		return 1
	}
	if len(recipients) == 0 {
		fmt.Println("FAIL: pigpen-open — the agent lists no P-256 key to seal to")
		return 1
	}

	oracle := piggyagent.AgentECDHOracle{SocketPath: socketPath}

	plaintext := []byte("piggy-test: a store key unwrapped through the agent")
	if err := sealMarshalParseOpen(plaintext, recipients, oracle); err != nil {
		fmt.Printf("FAIL: pigpen-open — %v\n", err)
		return 1
	}
	fmt.Printf("PASS: pigpen-open — sealed to %d agent key(s), opened through %s\n", len(recipients), socketPath)

	stranger, err := strangerRecipient()
	if err != nil {
		fmt.Printf("FAIL: pigpen-open (key not held) — %v\n", err)
		return 1
	}
	err = sealMarshalParseOpen(plaintext, []markl.Id{stranger}, oracle)
	switch {
	case err == nil:
		fmt.Println("FAIL: pigpen-open (key not held) — opened a document sealed to a key the agent does not hold")
		return 1
	case !piggyagent.IsErrAgent(err):
		fmt.Printf("FAIL: pigpen-open (key not held) — not reported as an agent error: %v\n", err)
		return 1
	}
	fmt.Printf("PASS: pigpen-open (key not held) — agent error: %v\n", err)

	return 0
}

func sealMarshalParseOpen(plaintext []byte, recipients []markl.Id, oracle pigpen.ECDHOracle) error {
	sealed, err := pigpen.Seal(plaintext, recipients, nil)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	wire, err := sealed.MarshalText()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	parsed, err := pigpen.ParseDocument(wire)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	got, err := parsed.Open(oracle, nil)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if !bytes.Equal(got, plaintext) {
		return fmt.Errorf("opened to %q, want %q", got, plaintext)
	}
	return nil
}

// agentP256Recipients returns a piggy-recipient-v1 id for every
// ecdsa-sha2-nistp256 key the agent lists.
func agentP256Recipients(socketPath string) ([]markl.Id, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to the agent: %w", err)
	}
	defer conn.Close()

	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("listing the agent's keys: %w", err)
	}

	var recipients []markl.Id
	for _, key := range keys {
		if key.Type() != ssh.KeyAlgoECDSA256 {
			continue
		}
		var blob struct {
			KeyType string
			Curve   string
			Point   []byte
		}
		if err := ssh.Unmarshal(key.Blob, &blob); err != nil {
			return nil, fmt.Errorf("parsing an agent key: %w", err)
		}
		id, err := p256Recipient(blob.Point)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, id)
	}
	return recipients, nil
}

func strangerRecipient() (markl.Id, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return markl.Id{}, err
	}
	return p256Recipient(key.PublicKey().Bytes())
}

func p256Recipient(uncompressed []byte) (id markl.Id, err error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), uncompressed)
	if x == nil {
		return id, fmt.Errorf("not an uncompressed P-256 point (%d bytes)", len(uncompressed))
	}
	if err = id.SetPurposeId(markl.PurposePiggyRecipientV1); err != nil {
		return id, err
	}
	err = id.SetMarklId(markl.FormatIdPivyEcdhP256Pub, elliptic.MarshalCompressed(elliptic.P256(), x, y))
	return id, err
}

func pigpenOpenUsage() {
	fmt.Fprintf(os.Stderr, "Usage: piggy-agent-conformance pigpen-open <socket-path>\n")
}
