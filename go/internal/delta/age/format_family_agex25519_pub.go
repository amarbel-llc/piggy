package age

import (
	"crypto/ecdh"
	stderrors "errors"
	"io"
	"sync"

	filippoage "filippo.io/age"

	domain_interfaces "code.linenisgreat.com/piggy/go/internal/0/domain_interfaces"
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/bech32"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/errors"
	"code.linenisgreat.com/purse-first/libs/dewey/pkgs/interfaces"
)

// ErrNoIdentity is what decrypting through an age_x25519_pub IO wrapper
// returns: a public recipient can encrypt and nothing else. Decryption is
// the job of the matching age_x25519_sec identity.
var ErrNoIdentity = stderrors.New(
	"age_x25519_pub is a public recipient: it can encrypt but holds no identity to decrypt with",
)

// IsErrNoIdentity reports whether err is, or wraps, ErrNoIdentity.
func IsErrNoIdentity(err error) bool {
	return stderrors.Is(err, ErrNoIdentity)
}

// ageRecipientHRP is the bech32 prefix of an age X25519 recipient
// ("age1…"). The 32 bytes it carries are exactly an age_x25519_pub
// markl id's payload (piggy RFC 0004).
const ageRecipientHRP = "age"

// x25519PubIOWrapper encrypts to one age X25519 recipient and refuses to
// decrypt. It writes a standard age v1 file, the same format the
// age_x25519_sec identity wrapper reads.
type x25519PubIOWrapper struct {
	recipient *filippoage.X25519Recipient
}

var _ interfaces.IOWrapper = x25519PubIOWrapper{}

func (wrapper x25519PubIOWrapper) WrapWriter(w io.Writer) (io.WriteCloser, error) {
	out, err := filippoage.Encrypt(w, wrapper.recipient)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	return out, nil
}

func (x25519PubIOWrapper) WrapReader(io.Reader) (io.ReadCloser, error) {
	return nil, errors.Wrap(ErrNoIdentity)
}

// AgeX25519PubGetIOWrapper builds an encrypt-only IO wrapper for the age
// X25519 recipient carried by public (an age_x25519_pub markl id). It is
// how a consumer encrypts to a key whose secret half it does not hold at
// write time.
//
// It is built directly on filippo.io/age: dewey's age package has no
// recipient-only wrapper, only identities.
func AgeX25519PubGetIOWrapper(
	public domain_interfaces.MarklId,
) (ioWrapper interfaces.IOWrapper, err error) {
	key := public.GetBytes()

	// A low-order point (all zero, say) makes every exchange yield the
	// same all-zero secret, so anyone could read what is encrypted to it
	// (RFC 7748 §6.1). crypto/ecdh refuses that exchange; probe with a
	// fixed scalar so the refusal happens here, not at the first write.
	if err = rejectLowOrderX25519(key); err != nil {
		err = errors.Wrap(err)
		return ioWrapper, err
	}

	encoded, err := bech32.Encode(ageRecipientHRP, key)
	if err != nil {
		err = errors.Wrap(err)
		return ioWrapper, err
	}

	recipient, err := filippoage.ParseX25519Recipient(encoded)
	if err != nil {
		err = errors.Wrapf(err, "age recipient from an age_x25519_pub id")
		return ioWrapper, err
	}

	ioWrapper = x25519PubIOWrapper{recipient: recipient}

	return ioWrapper, err
}

func rejectLowOrderX25519(publicKey []byte) error {
	curve := ecdh.X25519()

	peer, err := curve.NewPublicKey(publicKey)
	if err != nil {
		return errors.Wrapf(err, "age_x25519_pub key")
	}

	// Any valid scalar exposes a low-order peer: the result is all zero
	// whatever the scalar is.
	probe, err := curve.NewPrivateKey(make([]byte, 32))
	if err != nil {
		return errors.Wrap(err)
	}

	if _, err = probe.ECDH(peer); err != nil {
		return errors.Errorf("age_x25519_pub key is a low-order point and cannot be encrypted to")
	}

	return nil
}

var ageX25519PubFormatOnce sync.Once

// RegisterAgeX25519PubFormat swaps an encrypt-capable registration over
// the core's plain age_x25519_pub format (idempotent via sync.Once). The
// core registers it as a bare markl.Format, which markl.Id.GetIOWrapper
// cannot use; importing this package makes an age public recipient
// encryptable the same way every other key type is. Fired at init().
func RegisterAgeX25519PubFormat() {
	ageX25519PubFormatOnce.Do(func() {
		errors.PanicIfError(markl.SwapFormat(
			markl.FormatIdAgeX25519Pub,
			markl.FormatSec{
				Id:           markl.FormatIdAgeX25519Pub,
				Size:         32,
				GetIOWrapper: AgeX25519PubGetIOWrapper,
			},
		))
	})
}

func init() {
	RegisterAgeX25519PubFormat()
}
