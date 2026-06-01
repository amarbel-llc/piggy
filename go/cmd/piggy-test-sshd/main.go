// Package main is a test-only SSH server for piggy's hardware-free
// SSH-over-fibby bats lane (piggy#135 Phase A). It mirrors madder's
// test-subprocess handshake (RFC 0001): the bats helper spawns it as a
// coproc with a magic cookie, reads one handshake line giving the
// ephemeral port + known_hosts path, and closes stdin to shut it down.
//
// It accepts any password/public key (it's a fixture, not a real
// server) and handles `session` channels' `exec` requests by running
// the command through `sh -c` and wiring stdio + the exit status back
// to the client. Phase B adds SSH agent forwarding (the agent-forward
// request arms a remote unix socket whose connections are proxied back
// to the client's agent, with SSH_AUTH_SOCK injected into the exec env)
// and `direct-tcpip` TCP forwarding. See agentForwardRequest /
// agentForwardChannel for the OpenSSH extension names.
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
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	programName     = "piggy-test-sshd"
	protocolVersion = "1"
	subprotocol     = "ssh"
)

// OpenSSH agent-forwarding extension names. Assembled by concatenation
// so the "openssh.com" suffix survives email-address obfuscation in
// editing tooling — a bare "name<at>openssh.com" string literal gets
// rewritten, which would silently break the protocol string match.
//
//	agentForwardRequest = the session request that arms forwarding
//	agentForwardChannel = the reverse channel opened toward the client
const (
	openSSHExt          = "@" + "openssh.com"
	agentForwardRequest = "auth-agent-req" + openSSHExt
	agentForwardChannel = "auth-agent" + openSSHExt
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
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go serveSession(sshConn, channel, requests)
		case "direct-tcpip":
			go handleDirectTCPIP(newChannel)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// serveSession handles one session channel: the agent-forward request
// (arm agent forwarding) followed by `exec` (run a command, return its
// output + exit status). The agent-forward request always precedes exec
// on the wire, so by the time exec runs we know the forwarded
// SSH_AUTH_SOCK path. Other request types are declined so the client
// doesn't hang waiting for a reply.
func serveSession(sshConn ssh.Conn, channel ssh.Channel, requests <-chan *ssh.Request) {
	var agentSock string
	var cleanup func()
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	for req := range requests {
		switch req.Type {
		case agentForwardRequest:
			sock, cl, err := setupAgentForward(sshConn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] agent-forward setup: %v\n", programName, err)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			agentSock, cleanup = sock, cl
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			command := parseStringPayload(req.Payload)
			_ = req.Reply(true, nil)
			runExec(channel, command, agentSock)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	_ = channel.Close()
}

// parseStringPayload decodes the leading SSH "string" wire field of a
// request payload — the shape of the `exec` request's command argument
// (RFC 4254 §6.5).
func parseStringPayload(payload []byte) string {
	s, _, ok := parseSSHString(payload)
	if !ok {
		return ""
	}
	return s
}

// parseSSHString decodes one SSH "string" field (a uint32 big-endian
// length prefix followed by that many bytes) and returns it plus the
// remaining bytes. ok is false on a truncated buffer.
func parseSSHString(data []byte) (value string, rest []byte, ok bool) {
	if len(data) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(data[:4])
	if uint32(len(data)-4) < n {
		return "", nil, false
	}
	return string(data[4 : 4+n]), data[4+n:], true
}

// runExec runs the command through `sh -c`, wiring the channel as the
// process's stdio, then sends the exit status back per RFC 4254 §6.10.
// When agentSock is non-empty (agent forwarding was armed) it is exported
// as SSH_AUTH_SOCK so the command can reach the forwarded agent.
func runExec(channel ssh.Channel, command, agentSock string) {
	defer channel.Close() //nolint:errcheck

	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	if agentSock != "" {
		cmd.Env = envWithAuthSock(agentSock)
	}

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

// envWithAuthSock returns the process environment with SSH_AUTH_SOCK set
// to sock, REPLACING any inherited value rather than appending — glibc
// getenv returns the first match, so a stale inherited SSH_AUTH_SOCK
// (e.g. the operator's agent) would otherwise shadow the forwarded one
// and the remote command would talk to the wrong agent.
func envWithAuthSock(sock string) []string {
	base := os.Environ()
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "SSH_AUTH_SOCK="+sock)
}

// setupAgentForward arms SSH agent forwarding: it binds a unix socket on
// the remote (server) side and, for each connection to it, opens an
// reverse agent-forward channel back to the client — whose ssh -A agent
// serves it. The returned path is exported to the exec'd command as
// SSH_AUTH_SOCK; cleanup stops the listener and removes the socket dir.
func setupAgentForward(sshConn ssh.Conn) (sockPath string, cleanup func(), err error) {
	// Short /tmp path: the socket's absolute path must fit AF_UNIX
	// sun_path (108 bytes on Linux, 104 on darwin). The devshell $TMPDIR
	// can nest deeply under the worktree and overrun it, so bind under
	// /tmp with short names — the same dodge the bats helpers use.
	dir, err := os.MkdirTemp("/tmp", "pts-agent-")
	if err != nil {
		return "", nil, err
	}
	sockPath = filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	go func() {
		for {
			local, acceptErr := listener.Accept()
			if acceptErr != nil {
				return // listener closed by cleanup
			}
			go proxyAgentConn(sshConn, local)
		}
	}()
	cleanup = func() {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
	}
	return sockPath, cleanup, nil
}

// proxyAgentConn bridges one connection to the forwarded-agent socket to
// a reverse agent-forward channel toward the client's agent.
func proxyAgentConn(sshConn ssh.Conn, local net.Conn) {
	defer local.Close() //nolint:errcheck
	channel, reqs, err := sshConn.OpenChannel(agentForwardChannel, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s] open agent channel: %v\n", programName, err)
		return
	}
	defer channel.Close() //nolint:errcheck
	go ssh.DiscardRequests(reqs)
	proxy(channel, local)
}

// handleDirectTCPIP serves a `direct-tcpip` channel: dial the requested
// host:port and splice it to the channel. Used for client-driven TCP
// port forwarding (RFC 4254 §7.2).
func handleDirectTCPIP(newChannel ssh.NewChannel) {
	host, port, ok := parseDirectTCPIP(newChannel.ExtraData())
	if !ok {
		_ = newChannel.Reject(ssh.ConnectionFailed, "malformed direct-tcpip payload")
		return
	}
	dest := net.JoinHostPort(host, strconv.Itoa(int(port)))
	remote, err := net.Dial("tcp", dest)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("dial %s: %v", dest, err))
		return
	}
	defer remote.Close() //nolint:errcheck
	channel, reqs, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close() //nolint:errcheck
	go ssh.DiscardRequests(reqs)
	proxy(channel, remote)
}

// parseDirectTCPIP extracts the destination host+port from a
// direct-tcpip channel's extra data (string host, uint32 port, string
// origHost, uint32 origPort). Only the destination is needed.
func parseDirectTCPIP(data []byte) (host string, port uint32, ok bool) {
	host, rest, ok := parseSSHString(data)
	if !ok || len(rest) < 4 {
		return "", 0, false
	}
	return host, binary.BigEndian.Uint32(rest[:4]), true
}

// proxy splices an SSH channel and a net.Conn bidirectionally, returning
// once either direction closes.
func proxy(channel ssh.Channel, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(channel, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, channel); done <- struct{}{} }()
	<-done
}
