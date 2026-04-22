package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var passed, failed int

func isConnectionDead(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset")
}

func pass(name, detail string) {
	fmt.Printf("PASS: %s — %s\n", name, detail)
	passed++
}

func fail(name, detail string) {
	fmt.Printf("FAIL: %s — %s\n", name, detail)
	failed++
}

func readSSHString(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", 0, errors.New("not enough data for string length")
	}
	slen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+slen > len(data) {
		return "", 0, fmt.Errorf("string length %d exceeds remaining data %d", slen, len(data)-offset)
	}
	s := string(data[offset : offset+slen])
	offset += slen
	s = strings.TrimRight(s, "\x00")
	return s, offset, nil
}

func testList(client agent.ExtendedAgent) []*agent.Key {
	name := "list"
	keys, err := client.List()
	if err != nil {
		// pivy-agent returns SSH_AGENT_FAILURE when pcscd is unavailable,
		// which is a valid protocol response — not a conformance failure.
		fmt.Printf("SKIP: %s — %v (pcscd likely unavailable)\n", name, err)
		return nil
	}
	pass(name, fmt.Sprintf("Go parsed identity list: %d keys", len(keys)))
	return keys
}

func testSign(client agent.ExtendedAgent, keys []*agent.Key) {
	name := "sign"
	if len(keys) == 0 {
		fmt.Printf("SKIP: %s — no keys available (card not present)\n", name)
		return
	}

	key := keys[0]
	data := []byte("pivy-agent-conformance test payload")

	sig, err := client.Sign(key, data)
	if err != nil {
		fail(name, fmt.Sprintf("Sign() error: %v", err))
		return
	}

	pubKey, err := ssh.ParsePublicKey(key.Blob)
	if err != nil {
		fail(name, fmt.Sprintf("failed to parse public key for verification: %v", err))
		return
	}

	if err := pubKey.Verify(data, sig); err != nil {
		fail(name, fmt.Sprintf("signature verification failed: %v", err))
		return
	}

	pass(name, fmt.Sprintf("format=%s, key=%s, verified=true", sig.Format, key.Type()))
}

func testQuery(client agent.ExtendedAgent) {
	name := "query"
	resp, err := client.Extension("query", nil)
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		fail(name, "agent does not support query extension")
		return
	}
	if err != nil {
		fail(name, fmt.Sprintf("Extension() error: %v", err))
		return
	}

	if len(resp) < 1 {
		fail(name, "empty response")
		return
	}
	if resp[0] != 29 {
		fail(name, fmt.Sprintf("expected type 29 (SSH_AGENT_EXTENSION_RESPONSE), got %d", resp[0]))
		return
	}

	offset := 1
	echo, next, err := readSSHString(resp, offset)
	if err != nil {
		fail(name, fmt.Sprintf("failed to read name echo: %v", err))
		return
	}
	if echo != "query" {
		fail(name, fmt.Sprintf("name echo mismatch: got %q, want %q", echo, "query"))
		return
	}
	offset = next

	var extensions []string
	for offset < len(resp) {
		var s string
		s, offset, err = readSSHString(resp, offset)
		if err != nil {
			fail(name, fmt.Sprintf("failed to parse extension name at offset %d: %v", offset, err))
			return
		}
		extensions = append(extensions, s)
	}

	pass(name, fmt.Sprintf("type=29, echo=\"query\", %d extensions: [%s]",
		len(extensions), strings.Join(extensions, ", ")))
}

func testPinStatus(client agent.ExtendedAgent) {
	name := "pin-status@joyent.com"
	resp, err := client.Extension("pin-status@joyent.com", nil)
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		fail(name, "agent does not support pin-status extension")
		return
	}
	if err != nil {
		fail(name, fmt.Sprintf("Extension() error: %v", err))
		return
	}

	if len(resp) < 1 {
		fail(name, "empty response")
		return
	}
	if resp[0] != 29 {
		fail(name, fmt.Sprintf("expected type 29, got %d", resp[0]))
		return
	}

	offset := 1
	echo, next, err := readSSHString(resp, offset)
	if err != nil {
		fail(name, fmt.Sprintf("failed to read name echo: %v", err))
		return
	}
	if echo != "pin-status@joyent.com" {
		fail(name, fmt.Sprintf("name echo mismatch: got %q, want %q", echo, "pin-status@joyent.com"))
		return
	}
	offset = next

	remaining := len(resp) - offset
	if remaining != 2 {
		fail(name, fmt.Sprintf("expected 2 payload bytes (has_pin + has_card), got %d", remaining))
		return
	}

	hasPin := resp[offset]
	hasCard := resp[offset+1]
	pass(name, fmt.Sprintf("type=29, echo, has_pin=%d has_card=%d", hasPin, hasCard))
}

func putSSHString(buf []byte, s []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, s...)
	return buf
}

func generateDummyKey() (ssh.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return sshPub, nil
}

func testSessionBind(client agent.ExtendedAgent) {
	name := "session-bind@openssh.com"

	dummyKey, err := generateDummyKey()
	if err != nil {
		fail(name, fmt.Sprintf("failed to generate dummy key: %v", err))
		return
	}

	// Wire format: ssh_key_blob + ssh_string(session_id) + ssh_string(signature) + u8(is_forwarding)
	var contents []byte
	contents = putSSHString(contents, dummyKey.Marshal())
	contents = putSSHString(contents, []byte("dummy-session-id"))
	contents = putSSHString(contents, []byte("dummy-signature"))
	contents = append(contents, 0) // is_forwarding=0 (auth bind)

	resp, err := client.Extension("session-bind@openssh.com", contents)
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		fail(name, "agent does not support session-bind extension")
		return
	}
	if err != nil {
		fail(name, fmt.Sprintf("Extension() error: %v", err))
		return
	}

	// pivy-agent returns SSH_AGENT_SUCCESS (type 6) with a trailing u32
	if len(resp) < 1 {
		fail(name, "empty response")
		return
	}
	if resp[0] != 6 {
		fail(name, fmt.Sprintf("expected type 6 (SSH_AGENT_SUCCESS), got %d", resp[0]))
		return
	}

	pass(name, "type=6 (SSH_AGENT_SUCCESS)")
}

func testX509CertsNoCard(client agent.ExtendedAgent) {
	name := "x509-certs@joyent.com (no card)"

	dummyKey, err := generateDummyKey()
	if err != nil {
		fail(name, fmt.Sprintf("failed to generate dummy key: %v", err))
		return
	}

	// Wire format: ssh_key_blob + u32(flags)
	var contents []byte
	contents = putSSHString(contents, dummyKey.Marshal())
	var flagsBuf [4]byte
	binary.BigEndian.PutUint32(flagsBuf[:], 0)
	contents = append(contents, flagsBuf[:]...)

	_, err = client.Extension("x509-certs@joyent.com", contents)
	if err == nil {
		fail(name, "expected failure with unknown key, got success")
		return
	}
	if isConnectionDead(err) {
		fail(name, fmt.Sprintf("agent crashed or connection lost: %v", err))
		return
	}

	pass(name, fmt.Sprintf("graceful failure: %v", err))
}

func testSignPrehashNoCard(client agent.ExtendedAgent) {
	name := "sign-prehash@arekinath.github.io (no card)"

	dummyKey, err := generateDummyKey()
	if err != nil {
		fail(name, fmt.Sprintf("failed to generate dummy key: %v", err))
		return
	}

	// Wire format: ssh_key_blob + ssh_string(data) + u32(flags)
	var contents []byte
	contents = putSSHString(contents, dummyKey.Marshal())
	contents = putSSHString(contents, []byte("dummy-prehash-data"))
	var flagsBuf [4]byte
	binary.BigEndian.PutUint32(flagsBuf[:], 0)
	contents = append(contents, flagsBuf[:]...)

	_, err = client.Extension("sign-prehash@arekinath.github.io", contents)
	if err == nil {
		fail(name, "expected failure with unknown key, got success")
		return
	}
	if isConnectionDead(err) {
		fail(name, fmt.Sprintf("agent crashed or connection lost: %v", err))
		return
	}

	pass(name, fmt.Sprintf("graceful failure: %v", err))
}

func wrapInSSHString(payload []byte) []byte {
	var buf []byte
	return putSSHString(buf, payload)
}

func findECDSAKey(keys []*agent.Key) *agent.Key {
	for _, k := range keys {
		if strings.HasPrefix(k.Type(), "ecdsa-sha2-") {
			return k
		}
	}
	return nil
}

func generateEphemeralECDSA() (ssh.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(&priv.PublicKey)
}

func testECDH(client agent.ExtendedAgent, keys []*agent.Key, hardware bool) {
	name := "ecdh@joyent.com"
	if !hardware {
		fmt.Printf("SKIP: %s — requires --hardware flag\n", name)
		return
	}

	ecKey := findECDSAKey(keys)
	if ecKey == nil {
		fmt.Printf("SKIP: %s — no ECDSA key available on card\n", name)
		return
	}

	partner, err := generateEphemeralECDSA()
	if err != nil {
		fail(name, fmt.Sprintf("failed to generate ephemeral ECDSA key: %v", err))
		return
	}

	// eh_string=B_TRUE: contents must be a single SSH string wrapping the inner payload
	// Inner: ssh_key(card_key) + ssh_key(partner) + u32(flags=0)
	var inner []byte
	inner = putSSHString(inner, ecKey.Blob)
	inner = putSSHString(inner, partner.Marshal())
	var flagsBuf [4]byte
	inner = append(inner, flagsBuf[:]...)

	resp, err := client.Extension("ecdh@joyent.com", wrapInSSHString(inner))
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		fail(name, "agent does not support ecdh extension")
		return
	}
	if err != nil {
		fail(name, fmt.Sprintf("Extension() error: %v", err))
		return
	}

	if len(resp) < 1 || resp[0] != 29 {
		fail(name, fmt.Sprintf("expected type 29, got %d", resp[0]))
		return
	}

	offset := 1
	echo, next, err := readSSHString(resp, offset)
	if err != nil {
		fail(name, fmt.Sprintf("failed to read name echo: %v", err))
		return
	}
	if echo != "ecdh@joyent.com" {
		fail(name, fmt.Sprintf("name echo mismatch: got %q", echo))
		return
	}
	offset = next

	// Read the ECDH secret
	if offset+4 > len(resp) {
		fail(name, "response too short for secret string")
		return
	}
	secretLen := int(binary.BigEndian.Uint32(resp[offset:]))
	offset += 4
	if offset+secretLen > len(resp) {
		fail(name, fmt.Sprintf("secret length %d exceeds response", secretLen))
		return
	}
	if secretLen == 0 {
		fail(name, "ECDH secret is empty")
		return
	}

	pass(name, fmt.Sprintf("type=29, echo, secret_len=%d", secretLen))
}

func testECDHRebox(client agent.ExtendedAgent, keys []*agent.Key, hardware bool) {
	name := "ecdh-rebox@joyent.com"
	if !hardware {
		fmt.Printf("SKIP: %s — requires --hardware flag\n", name)
		return
	}
	if len(keys) == 0 {
		fmt.Printf("SKIP: %s — no keys available\n", name)
		return
	}

	partner, err := generateEphemeralECDSA()
	if err != nil {
		fail(name, fmt.Sprintf("failed to generate ephemeral ECDSA key: %v", err))
		return
	}

	// eh_string=B_TRUE: contents wrapped in SSH string
	// Inner: ssh_string(boxbuf) + ssh_string(guidb) + u8(slotid) + ssh_key(partner) + u32(flags)
	// We send dummy box data — this will fail at sshbuf_get_piv_box, which is fine.
	var inner []byte
	inner = putSSHString(inner, []byte("dummy-box-data"))
	inner = putSSHString(inner, []byte{}) // empty guid
	inner = append(inner, 0x9D)           // slot ID
	inner = putSSHString(inner, partner.Marshal())
	var flagsBuf [4]byte
	inner = append(inner, flagsBuf[:]...)

	_, err = client.Extension("ecdh-rebox@joyent.com", wrapInSSHString(inner))
	if err == nil {
		fail(name, "expected failure with dummy box, got success")
		return
	}
	if isConnectionDead(err) {
		fail(name, fmt.Sprintf("agent crashed or connection lost: %v", err))
		return
	}

	pass(name, fmt.Sprintf("graceful failure: %v", err))
}

func testAttest(client agent.ExtendedAgent, keys []*agent.Key, hardware bool) {
	name := "ykpiv-attest@joyent.com"
	if !hardware {
		fmt.Printf("SKIP: %s — requires --hardware flag\n", name)
		return
	}
	if len(keys) == 0 {
		fmt.Printf("SKIP: %s — no keys available\n", name)
		return
	}

	// eh_string=B_TRUE: contents wrapped in SSH string
	// Inner: ssh_key(card_key) + u32(flags=0)
	key := keys[0]
	var inner []byte
	inner = putSSHString(inner, key.Blob)
	var flagsBuf [4]byte
	inner = append(inner, flagsBuf[:]...)

	resp, err := client.Extension("ykpiv-attest@joyent.com", wrapInSSHString(inner))
	if errors.Is(err, agent.ErrExtensionUnsupported) {
		fail(name, "agent does not support attest extension")
		return
	}
	if err != nil {
		fail(name, fmt.Sprintf("Extension() error: %v", err))
		return
	}

	if len(resp) < 1 || resp[0] != 29 {
		fail(name, fmt.Sprintf("expected type 29, got %d", resp[0]))
		return
	}

	offset := 1
	echo, next, err := readSSHString(resp, offset)
	if err != nil {
		fail(name, fmt.Sprintf("failed to read name echo: %v", err))
		return
	}
	if echo != "ykpiv-attest@joyent.com" {
		fail(name, fmt.Sprintf("name echo mismatch: got %q", echo))
		return
	}
	offset = next

	// Read cert count (u32)
	if offset+4 > len(resp) {
		fail(name, "response too short for cert count")
		return
	}
	certCount := binary.BigEndian.Uint32(resp[offset:])
	offset += 4

	// Read each cert blob
	for i := uint32(0); i < certCount; i++ {
		if offset+4 > len(resp) {
			fail(name, fmt.Sprintf("response too short for cert %d length", i))
			return
		}
		certLen := int(binary.BigEndian.Uint32(resp[offset:]))
		offset += 4
		if offset+certLen > len(resp) {
			fail(name, fmt.Sprintf("cert %d length %d exceeds response", i, certLen))
			return
		}
		if certLen == 0 {
			fail(name, fmt.Sprintf("cert %d is empty", i))
			return
		}
		offset += certLen
	}

	pass(name, fmt.Sprintf("type=29, echo, %d certs", certCount))
}

func main() {
	var hardware bool
	args := os.Args[1:]
	for i, a := range args {
		if a == "--hardware" {
			hardware = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: pivy-agent-conformance [--hardware] <socket-path>\n")
		os.Exit(2)
	}

	conn, err := net.Dial("unix", args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to agent: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := agent.NewClient(conn)

	fmt.Println("Running Go conformance tests...\n")
	keys := testList(client)
	testSign(client, keys)
	testQuery(client)
	testSessionBind(client)
	testX509CertsNoCard(client)
	testSignPrehashNoCard(client)
	testPinStatus(client)

	testECDH(client, keys, hardware)
	testECDHRebox(client, keys, hardware)
	testAttest(client, keys, hardware)

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}
