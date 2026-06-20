package agent

import (
	"math/big"
	"testing"

	markl "github.com/amarbel-llc/piggy/go/markl/pkgs/markl"

	"golang.org/x/crypto/ssh"
)

// TestParseSSHEcdsaSignatureBlob pins the SSH-wire (two mpints) ->
// fixed 64-byte r‖s conversion: each component is left-zero-padded into
// its 32-byte half, big-endian.
func TestParseSSHEcdsaSignatureBlob(t *testing.T) {
	r := big.NewInt(0x0102)
	s := big.NewInt(0xABCD)

	blob := ssh.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})

	fixed, err := parseSSHEcdsaSignatureBlob(blob)
	if err != nil {
		t.Fatalf("parseSSHEcdsaSignatureBlob: %v", err)
	}
	if len(fixed) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(fixed))
	}

	gotR := new(big.Int).SetBytes(fixed[:32])
	gotS := new(big.Int).SetBytes(fixed[32:64])

	if gotR.Cmp(r) != 0 {
		t.Errorf("r mismatch: got %x, want %x", gotR, r)
	}
	if gotS.Cmp(s) != 0 {
		t.Errorf("s mismatch: got %x, want %x", gotS, s)
	}
}

// TestPivyEcdhSwappedAtInit verifies this package's init() swapped the
// real pivy GetIOWrapper over the core's erroring pivy_ecdh_p256 stub:
// the format no longer returns the ErrPivyEcdhP256NotConnected sentinel.
// (It still errors — on an invalid dummy point / absent agent — just not
// with the not-connected sentinel, which is the proof the swap happened.)
func TestPivyEcdhSwappedAtInit(t *testing.T) {
	format, err := markl.GetFormatOrError(markl.FormatIdPivyEcdhP256Pub)
	if err != nil {
		t.Fatalf("GetFormatOrError(pivy_ecdh_p256_pub): %v", err)
	}

	fs, ok := format.(markl.FormatSec)
	if !ok {
		t.Fatalf("pivy_ecdh_p256_pub format is %T, want markl.FormatSec", format)
	}

	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdPivyEcdhP256Pub, make([]byte, 33)); err != nil {
		t.Fatalf("SetMarklId: %v", err)
	}

	_, err = fs.GetIOWrapper(id)
	if err == nil {
		// A bare 33-zero-byte point is not a valid P-256 point and there
		// is no agent in the test env, so a real GetIOWrapper must error.
		t.Fatal("expected GetIOWrapper to error on a dummy point")
	}
	if markl.IsErrPivyEcdhP256NotConnected(err) {
		t.Errorf("pivy_ecdh_p256 still on the stub (swap did not fire): %v", err)
	}
}

// TestSSHSigningFormatsStubbedUntilRegistered verifies the consumer-driven
// SSH signing swaps did NOT auto-fire at init (unlike pivy): until
// RegisterEcdsaP256SSHFormat / RegisterSSHEd25519Format are called with a
// connected signer, ecdsa_p256_ssh and ed25519_ssh stay erroring stubs.
// These tests never call Register (no real agent), so the stubs persist.
func TestSSHSigningFormatsStubbedUntilRegistered(t *testing.T) {
	cases := []struct {
		formatId string
		isStub   func(error) bool
	}{
		{markl.FormatIdEcdsaP256SSH, markl.IsErrEcdsaP256SSHAgentNotConnected},
		{markl.FormatIdEd25519SSH, markl.IsErrEd25519SSHAgentNotConnected},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.formatId, func(t *testing.T) {
			format, err := markl.GetFormatOrError(tc.formatId)
			if err != nil {
				t.Fatalf("GetFormatOrError(%q): %v", tc.formatId, err)
			}
			fs, ok := format.(markl.FormatSec)
			if !ok {
				t.Fatalf("%q format is %T, want markl.FormatSec", tc.formatId, format)
			}

			_, err = fs.Sign(nil, nil, nil)
			if !tc.isStub(err) {
				t.Errorf("%q Sign did not return the not-connected sentinel: %v",
					tc.formatId, err)
			}
		})
	}
}
