package age

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

// ageKeypairIDs mints an age identity and returns it as the two markl ids
// a consumer holds: the secret (age_x25519_sec) and the matching public
// recipient (age_x25519_pub).
func ageKeypairIDs(t *testing.T) (secretID, publicID markl.Id) {
	t.Helper()

	secret, err := ageSecFormat(t).Generate(nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := secretID.SetMarklId(markl.FormatIdAgeX25519Sec, secret); err != nil {
		t.Fatal(err)
	}

	key, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := publicID.SetPurposeId(markl.PurposePiggyRecipientV1); err != nil {
		t.Fatal(err)
	}
	if err := publicID.SetMarklId(markl.FormatIdAgeX25519Pub, key.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	return secretID, publicID
}

// What a store does: encrypt to the public recipient through
// markl.Id.GetIOWrapper, decrypt with the identity.
func TestAgeX25519PubEncryptsForTheMatchingIdentity(t *testing.T) {
	secretID, publicID := ageKeypairIDs(t)
	plaintext := []byte("a blob encrypted to a store's public key")

	publicWrapper, err := publicID.GetIOWrapper()
	if err != nil {
		t.Fatalf("GetIOWrapper on an age_x25519_pub id: %v", err)
	}

	var ciphertext bytes.Buffer
	writer, err := publicWrapper.WrapWriter(&ciphertext)
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

	secretWrapper, err := secretID.GetIOWrapper()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := secretWrapper.WrapReader(bytes.NewReader(ciphertext.Bytes()))
	if err != nil {
		t.Fatalf("WrapReader with the identity: %v", err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext: got %q", got)
	}
}

// A public key cannot decrypt. The wrapper says so; it does not go looking
// for an identity.
func TestAgeX25519PubRefusesToDecrypt(t *testing.T) {
	_, publicID := ageKeypairIDs(t)
	wrapper, err := publicID.GetIOWrapper()
	if err != nil {
		t.Fatal(err)
	}

	_, err = wrapper.WrapReader(strings.NewReader("anything"))
	if err == nil {
		t.Fatal("WrapReader on a public recipient succeeded")
	}
	if !IsErrNoIdentity(err) {
		t.Errorf("%v is not ErrNoIdentity", err)
	}
}

// A different identity must not open it.
func TestAgeX25519PubIsNotReadableByAnotherIdentity(t *testing.T) {
	_, publicID := ageKeypairIDs(t)
	otherSecretID, _ := ageKeypairIDs(t)

	wrapper, err := publicID.GetIOWrapper()
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	writer, err := wrapper.WrapWriter(&ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("not for the other identity")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	otherWrapper, err := otherSecretID.GetIOWrapper()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := otherWrapper.WrapReader(bytes.NewReader(ciphertext.Bytes()))
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	if err == nil {
		t.Fatal("another identity decrypted the blob")
	}
}

// A low-order X25519 "public key" yields the same shared secret for every
// sender, so anything encrypted to it is readable by anyone. None may be
// usable as a recipient. These are the small-order points of Curve25519,
// the non-canonical encodings among them (libsodium's blocklist).
func TestAgeX25519PubRefusesALowOrderKey(t *testing.T) {
	for label, point := range map[string]string{
		"zero":            "0000000000000000000000000000000000000000000000000000000000000000",
		"one":             "0100000000000000000000000000000000000000000000000000000000000000",
		"order 8":         "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"order 8, twin":   "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
		"p - 1":           "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"p (zero)":        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"p + 1 (one)":     "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"zero, high bit":  "0000000000000000000000000000000000000000000000000000000000000080",
		"p - 1, high bit": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		key, err := hex.DecodeString(point)
		if err != nil {
			t.Fatal(err)
		}
		var id markl.Id
		if err := id.SetMarklId(markl.FormatIdAgeX25519Pub, key); err != nil {
			t.Fatal(err)
		}

		wrapper, err := id.GetIOWrapper()
		if err == nil {
			_, err = wrapper.WrapWriter(io.Discard)
		}
		if err == nil {
			t.Errorf("%s: encrypting to a low-order key was allowed", label)
		}
	}
}
