package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/piggy/go/internal/delta/pigpen"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// AgentECDHOracle satisfies pigpen's oracle interface structurally; this
// assertion lives in the test so the package itself never imports pigpen.
var _ pigpen.ECDHOracle = AgentECDHOracle{}

func TestResolveAuthSockPrefersPiggyThenSSHThenPivy(t *testing.T) {
	for _, tc := range []struct {
		label                  string
		piggy, sshSock, pivy   string
		want                   string
		wantErr                bool
	}{
		{label: "all three set", piggy: "/p", sshSock: "/s", pivy: "/v", want: "/p"},
		{label: "ssh and pivy", sshSock: "/s", pivy: "/v", want: "/s"},
		{label: "pivy only", pivy: "/v", want: "/v"},
		{label: "piggy only", piggy: "/p", want: "/p"},
		{label: "none set", wantErr: true},
	} {
		t.Setenv("PIGGY_AUTH_SOCK", tc.piggy)
		t.Setenv("SSH_AUTH_SOCK", tc.sshSock)
		t.Setenv("PIVY_AUTH_SOCK", tc.pivy)

		got, err := ResolveAuthSock()
		switch {
		case tc.wantErr && err == nil:
			t.Errorf("%s: resolved %q, want an error", tc.label, got)
		case !tc.wantErr && err != nil:
			t.Errorf("%s: %v", tc.label, err)
		case got != tc.want:
			t.Errorf("%s: resolved %q, want %q", tc.label, got, tc.want)
		}
	}
}

// softwareECDHAgent is an in-process ssh-agent that answers the
// ecdh@joyent.com extension with a software P-256 key, the way a card
// behind piggy-agent would.
type softwareECDHAgent struct {
	sshagent.ExtendedAgent
	key     *ecdh.PrivateKey
	framing ecdhReplyFraming
	calls   atomic.Int32
}

type sshECDSAKey struct {
	KeyType string
	Curve   string
	Point   []byte
}

func (a *softwareECDHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != "ecdh@joyent.com" {
		return nil, sshagent.ErrExtensionUnsupported
	}
	a.calls.Add(1)

	// The request is one outer string wrapping
	// string(card key) string(partner key) uint32(flags).
	var outer struct{ Inner []byte }
	if err := ssh.Unmarshal(contents, &outer); err != nil {
		return nil, err
	}
	var request struct {
		CardKey    []byte
		PartnerKey []byte
		Flags      uint32
	}
	if err := ssh.Unmarshal(outer.Inner, &request); err != nil {
		return nil, err
	}

	var cardKey, partnerKey sshECDSAKey
	if err := ssh.Unmarshal(request.CardKey, &cardKey); err != nil {
		return nil, err
	}
	if !bytes.Equal(cardKey.Point, a.key.PublicKey().Bytes()) {
		return nil, errors.New("ecdh: key not found")
	}
	if err := ssh.Unmarshal(request.PartnerKey, &partnerKey); err != nil {
		return nil, err
	}
	partner, err := ecdh.P256().NewPublicKey(partnerKey.Point)
	if err != nil {
		return nil, err
	}
	secret, err := a.key.ECDH(partner)
	if err != nil {
		return nil, err
	}

	appendString := func(buf, value []byte) []byte {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(value)))
		return append(buf, value...)
	}

	switch a.framing {
	case framingPiggyAgent:
		// SSH_AGENT_EXTENSION_RESPONSE, the extension name, the secret:
		// what the Rust piggy-agent sends and what
		// go/cmd/piggy-agent-conformance's testECDH expects.
		return appendString(appendString([]byte{29}, []byte(extensionType)), secret), nil
	default:
		// SSH_AGENT_SUCCESS, then the secret.
		return appendString([]byte{6}, secret), nil
	}
}

type ecdhReplyFraming int

const (
	framingPiggyAgent ecdhReplyFraming = iota
	framingBareSuccess
)

func serveSoftwareECDHAgent(
	t *testing.T,
	key *ecdh.PrivateKey,
	framing ecdhReplyFraming,
) (socketPath string, served *softwareECDHAgent) {
	t.Helper()

	served = &softwareECDHAgent{
		ExtendedAgent: sshagent.NewKeyring().(sshagent.ExtendedAgent),
		key:           key,
		framing:       framing,
	}
	// A unix socket path is capped near 108 bytes and t.TempDir() under a
	// worktree's TMPDIR overruns it, so bind a relative path from inside
	// the temp dir instead.
	t.Chdir(t.TempDir())
	socketPath = "agent.sock"
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = sshagent.ServeAgent(served, conn)
			}()
		}
	}()
	return socketPath, served
}

func p256RecipientID(t *testing.T, key *ecdh.PrivateKey) markl.Id {
	t.Helper()
	x, y := elliptic.Unmarshal(elliptic.P256(), key.PublicKey().Bytes())
	var id markl.Id
	if err := id.SetPurposeId(markl.PurposePiggyRecipientV1); err != nil {
		t.Fatal(err)
	}
	if err := id.SetMarklId(
		markl.FormatIdPivyEcdhP256Pub,
		elliptic.MarshalCompressed(elliptic.P256(), x, y),
	); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAgentECDHOracleOpensASealedPigpenDocument(t *testing.T) {
	for label, framing := range map[string]ecdhReplyFraming{
		"piggy-agent reply framing":  framingPiggyAgent,
		"bare success reply framing": framingBareSuccess,
	} {
		t.Run(label, func(t *testing.T) { openThroughSoftwareAgent(t, framing) })
	}
}

func openThroughSoftwareAgent(t *testing.T, framing ecdhReplyFraming) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, served := serveSoftwareECDHAgent(t, key, framing)

	plaintext := []byte("a blob-store key, unwrapped through the agent")
	sealed, err := pigpen.Seal(plaintext, []markl.Id{p256RecipientID(t, key)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pigpen.ParseDocument(wire)
	if err != nil {
		t.Fatal(err)
	}

	got, err := doc.Open(AgentECDHOracle{SocketPath: socketPath}, nil)
	if err != nil {
		t.Fatalf("open through the agent: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext: got %q", got)
	}
	if served.calls.Load() == 0 {
		t.Fatal("the agent's ecdh extension was never called")
	}
}

func TestAgentECDHOracleFailsForAKeyTheAgentDoesNotHold(t *testing.T) {
	held, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, _ := serveSoftwareECDHAgent(t, held, framingPiggyAgent)

	sealed, err := pigpen.Seal([]byte("x"), []markl.Id{p256RecipientID(t, other)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sealed.Open(AgentECDHOracle{SocketPath: socketPath}, nil)
	if err == nil {
		t.Fatal("opened a document sealed to a key the agent does not hold")
	}
	if !IsErrAgent(err) {
		t.Fatalf("Open hid the agent's refusal behind %v", err)
	}
}

// When the agent cannot be reached, Open must say so. "No usable
// recipient" would send the user looking at the recipient list.
func TestOpenSurfacesAnUnreachableAgentAsAnAgentError(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pigpen.Seal([]byte("x"), []markl.Id{p256RecipientID(t, key)}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sealed.Open(AgentECDHOracle{SocketPath: "/nonexistent/agent.sock"}, nil)
	if err == nil {
		t.Fatal("opened a document with no agent to ask")
	}
	if !IsErrAgent(err) {
		t.Fatalf("Open reported an unreachable agent as %v", err)
	}
}

func TestAgentECDHOracleRejectsANonP256Recipient(t *testing.T) {
	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdAgeX25519Pub, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := (AgentECDHOracle{SocketPath: "/nonexistent"}).ECDH(id, make([]byte, 33)); err == nil {
		t.Fatal("ECDH accepted an x25519 recipient")
	}
}
