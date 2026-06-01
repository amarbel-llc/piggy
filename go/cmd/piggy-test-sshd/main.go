// Package main is a test-only SSH server for piggy's hardware-free
// SSH-over-fibby bats lane (piggy#135 Phase A). It mirrors madder's
// test-subprocess handshake (RFC 0001): the bats helper spawns it as a
// coproc with a magic cookie, reads one handshake line giving the
// ephemeral port + known_hosts path, and closes stdin to shut it down.
//
// It accepts any password/public key (it's a fixture, not a real
// server) and handles `session` channels' `exec` requests by running
// the command through `sh -c` and wiring stdio + the exit status back
// to the client. Agent forwarding and TCP forwarding land in Phase B.
//
// Refuses to start without PIGGY_PLUGIN_COOKIE so an accidental direct
// invocation on a shared machine fails loudly rather than binding a
// listener.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

const (
	programName     = "piggy-test-sshd"
	protocolVersion = "1"
	subprotocol     = "ssh"
)

func main() {
	cookie := os.Getenv("PIGGY_PLUGIN_COOKIE")
	if cookie == "" {
		fmt.Fprintf(os.Stderr, "[%s] PIGGY_PLUGIN_COOKIE unset; refusing to start\n", programName)
		os.Exit(1)
	}

	hostSigner, err := generateECDSAHostKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] host key: %v\n", programName, err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] listen: %v\n", programName, err)
		os.Exit(1)
	}

	// OpenSSH known_hosts doesn't support port wildcards on
	// `[host]:port` patterns, so write the file once the listener has
	// bound and we know the ephemeral port the client must connect to.
	addr := listener.Addr().(*net.TCPAddr)
	knownHostsPath, err := writeKnownHosts(hostSigner.PublicKey(), addr.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] known_hosts: %v\n", programName, err)
		_ = listener.Close()
		os.Exit(1)
	}

	// Handshake line (RFC 0001): cookie|version|transport|addr|known_hosts=PATH|subproto
	fmt.Printf(
		"%s|%s|tcp|%s|known_hosts=%s|%s\n",
		cookie,
		protocolVersion,
		listener.Addr().String(),
		knownHostsPath,
		subprotocol,
	)
	_ = os.Stdout.Sync()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// RFC 0001 Lifecycle: a closed stdin (EOF) is the sole normative
		// shutdown signal. Drain anything the parent sends; EOF => stop.
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()

	served := make(chan struct{})
	go func() {
		serve(listener, hostSigner)
		close(served)
	}()

	<-ctx.Done()
	_ = listener.Close()
	<-served
	_ = os.Remove(knownHostsPath)
}

func generateECDSAHostKey() (ssh.Signer, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("ssh signer: %w", err)
	}
	return signer, nil
}

// writeKnownHosts writes the host public key into a temp file in
// OpenSSH known_hosts format scoped to [127.0.0.1]:port — the exact
// host:port pattern the client will connect to.
func writeKnownHosts(publicKey ssh.PublicKey, port int) (name string, err error) {
	f, err := os.CreateTemp("", "piggy-test-sshd-known_hosts-*")
	if err != nil {
		return "", err
	}
	line := fmt.Sprintf(
		"[127.0.0.1]:%d %s %s\n",
		port,
		publicKey.Type(),
		base64.StdEncoding.EncodeToString(publicKey.Marshal()),
	)
	if _, err = f.WriteString(line); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func serve(listener net.Listener, hostSigner ssh.Signer) {
	// Any auth wins — this is a fixture. The SSH-over-fibby lane drives
	// real PIV-backed auth at the *agent* layer (Phase B forwards the
	// client's agent through), not at this server's auth gate.
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleConnection(conn, config)
	}
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close() //nolint:errcheck // teardown; close errors not actionable

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] ssh handshake failed: %v\n", programName, err)
		return
	}
	defer sshConn.Close() //nolint:errcheck

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go serveSession(channel, requests)
	}
}

// serveSession handles one session channel. Phase A supports `exec`
// (run a command, return its output + exit status). Other request types
// are declined so a client doesn't hang waiting for a reply.
func serveSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "exec":
			command := parseStringPayload(req.Payload)
			_ = req.Reply(true, nil)
			runExec(channel, command)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	_ = channel.Close()
}

// parseStringPayload decodes an SSH "string" wire field (a uint32
// big-endian length prefix followed by that many bytes) — the shape of
// the `exec` request's command argument (RFC 4254 §6.5).
func parseStringPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(payload[:4])
	end := 4 + int(n)
	if n > uint32(len(payload)-4) {
		end = len(payload)
	}
	return string(payload[4:end])
}

// runExec runs the command through `sh -c`, wiring the channel as the
// process's stdio, then sends the exit status back per RFC 4254 §6.10.
func runExec(channel ssh.Channel, command string) {
	defer channel.Close() //nolint:errcheck

	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "[%s] exec %q: %v\n", programName, command, err)
			exitCode = 127
		}
	}
	sendExitStatus(channel, exitCode)
}

func sendExitStatus(channel ssh.Channel, code int) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], uint32(code))
	_, _ = channel.SendRequest("exit-status", false, payload[:])
}
