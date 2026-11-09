package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startFixture serves piggy-test-sshd on an ephemeral loopback port and
// returns a client connected to it.
func startFixture(t *testing.T) *ssh.Client {
	t.Helper()
	hostSigner, err := generateECDSAHostKey()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go serve(listener, hostSigner)

	client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.FixedHostKey(hostSigner.PublicKey()),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// startEcho listens on an ephemeral loopback port and echoes every
// connection back to itself.
func startEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close() //nolint:errcheck
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// A direct-tcpip channel (what `ssh -L` and `ssh -W` open) reaches the
// requested host:port and carries bytes both ways (piggy#139).
func TestDirectTCPIPRoundTrip(t *testing.T) {
	client := startFixture(t)
	echo := startEcho(t)

	conn, err := client.Dial("tcp", echo)
	if err != nil {
		t.Fatalf("direct-tcpip to %s: %v", echo, err)
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	for _, msg := range []string{"piggy-139 first\n", "and a second write\n"} {
		if _, err := io.WriteString(conn, msg); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, []byte(msg)) {
			t.Fatalf("echo through direct-tcpip: got %q, want %q", got, msg)
		}
	}
}

// A destination that refuses the connection is rejected as
// ConnectionFailed, naming the destination, rather than hanging.
func TestDirectTCPIPRejectsAnUnreachableDestination(t *testing.T) {
	client := startFixture(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()

	conn, err := client.Dial("tcp", closed)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("direct-tcpip to closed %s succeeded", closed)
	}
	var open *ssh.OpenChannelError
	if !errors.As(err, &open) || open.Reason != ssh.ConnectionFailed {
		t.Fatalf("want a ConnectionFailed rejection, got %v", err)
	}
	if !strings.Contains(open.Message, closed) {
		t.Fatalf("rejection %q does not name %s", open.Message, closed)
	}
}

func TestParseDirectTCPIP(t *testing.T) {
	payload := ssh.Marshal(struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}{"127.0.0.1", 2222, "10.0.0.1", 55555})
	host, port, ok := parseDirectTCPIP(payload)
	if !ok || host != "127.0.0.1" || port != 2222 {
		t.Fatalf("got (%q, %d, %v)", host, port, ok)
	}

	// Truncated anywhere before the port's last byte (a 4-byte length,
	// the host, a 4-byte port): refused, no panic.
	for n := 0; n < 4+len("127.0.0.1")+4; n++ {
		if _, _, ok := parseDirectTCPIP(payload[:n]); ok {
			t.Fatalf("truncated payload of %d bytes parsed", n)
		}
	}
}
