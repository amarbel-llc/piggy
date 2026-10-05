package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"

	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/interfaces"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/pivy"
)

func clearAuthSockEnv(t *testing.T) {
	t.Helper()
	for _, name := range authSockEnvVars {
		t.Setenv(name, "")
	}
}

func encryptThrough(t *testing.T, wrapper interfaces.IOWrapper, plaintext []byte) []byte {
	t.Helper()
	var ciphertext bytes.Buffer
	writer, err := wrapper.WrapWriter(&ciphertext)
	if err != nil {
		t.Fatalf("WrapWriter: %v", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext.Bytes(), plaintext) {
		t.Fatal("the ciphertext contains the plaintext")
	}
	return ciphertext.Bytes()
}

// Building the wrapper and encrypting are software-only: neither needs an
// agent or a socket variable. (Building used to fail without
// PIVY_AUTH_SOCK.)
func TestPivyIOWrapperEncryptsWithNoAgentSocketSet(t *testing.T) {
	clearAuthSockEnv(t)
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	wrapper, err := PivyEcdhP256GetIOWrapper(p256RecipientID(t, key))
	if err != nil {
		t.Fatalf("building the wrapper with no socket variable set: %v", err)
	}
	encryptThrough(t, wrapper, []byte("written without an agent"))
}

// The round trip madder's store path makes, against an agent that frames
// its reply the way piggy-agent does and the way the C pivy-agent did.
func TestPivyIOWrapperRoundTripsThroughTheAgent(t *testing.T) {
	for label, framing := range map[string]ecdhReplyFraming{
		"piggy-agent reply framing":  framingPiggyAgent,
		"bare success reply framing": framingBareSuccess,
	} {
		t.Run(label, func(t *testing.T) {
			clearAuthSockEnv(t)
			key, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			socketPath, served := serveSoftwareECDHAgent(t, key, framing)

			wrapper, err := PivyEcdhP256GetIOWrapper(p256RecipientID(t, key))
			if err != nil {
				t.Fatal(err)
			}
			plaintext := []byte("a blob in a PIV-recipient store")
			ciphertext := encryptThrough(t, wrapper, plaintext)
			if served.calls.Load() != 0 {
				t.Fatal("encrypting called the agent")
			}

			// The socket is looked up at decrypt time, PIGGY_AUTH_SOCK first.
			t.Setenv("PIGGY_AUTH_SOCK", socketPath)
			t.Setenv("SSH_AUTH_SOCK", "/nonexistent/ssh-agent.sock")

			reader, err := wrapper.WrapReader(bytes.NewReader(ciphertext))
			if err != nil {
				t.Fatalf("WrapReader: %v", err)
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("reading the decrypted blob: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext: got %q", got)
			}
			if served.calls.Load() == 0 {
				t.Fatal("decrypting never called the agent")
			}
		})
	}
}

// An agent that cannot be reached is an agent error, which a caller must
// be able to tell apart from "this blob is not for this recipient".
func TestPivyIOWrapperReportsAgentFailuresAsAgentErrors(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := PivyEcdhP256GetIOWrapper(p256RecipientID(t, key))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encryptThrough(t, wrapper, []byte("a blob the agent cannot be asked about"))

	for label, setEnv := range map[string]func(){
		"no socket variable set": func() {},
		"a socket nobody listens on": func() {
			t.Setenv("PIGGY_AUTH_SOCK", "/nonexistent/agent.sock")
		},
	} {
		clearAuthSockEnv(t)
		setEnv()

		reader, err := wrapper.WrapReader(bytes.NewReader(ciphertext))
		if err == nil {
			_, err = io.ReadAll(reader)
		}
		if err == nil {
			t.Errorf("%s: decrypted, want an agent error", label)
			continue
		}
		if !pivy.IsErrAgent(err) {
			t.Errorf("%s: %v is not a pivy agent error", label, err)
		}
	}
}

// A key the agent does not hold: the agent answers with a failure, which
// is also an agent error, not a silent wrong-recipient skip.
func TestPivyIOWrapperReportsAnUnknownKeyAsAnAgentError(t *testing.T) {
	clearAuthSockEnv(t)
	held, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, _ := serveSoftwareECDHAgent(t, held, framingPiggyAgent)

	wrapper, err := PivyEcdhP256GetIOWrapper(p256RecipientID(t, other))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := encryptThrough(t, wrapper, []byte("a blob for a key the agent does not hold"))
	t.Setenv("PIGGY_AUTH_SOCK", socketPath)

	reader, err := wrapper.WrapReader(bytes.NewReader(ciphertext))
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if err == nil {
		t.Fatal("decrypted with a key the agent does not hold")
	}
	if !pivy.IsErrAgent(err) {
		t.Fatalf("%v is not a pivy agent error", err)
	}
}
