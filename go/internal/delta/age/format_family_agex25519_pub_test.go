package age

import (
	"bytes"
	"crypto/ecdh"
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

// An all-zero X25519 "public key" is a low-order point: anything encrypted
// to it is readable by anyone. It must not be usable as a recipient.
func TestAgeX25519PubRefusesALowOrderKey(t *testing.T) {
	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdAgeX25519Pub, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	wrapper, err := id.GetIOWrapper()
	if err == nil {
		_, err = wrapper.WrapWriter(io.Discard)
	}
	if err == nil {
		t.Fatal("encrypting to the all-zero key was allowed")
	}
}
