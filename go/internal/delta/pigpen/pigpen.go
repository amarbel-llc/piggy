package pigpen

//go:generate dagnabit export

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/amarbel-llc/piggy/go/internal/alfa/blech32"
	"github.com/amarbel-llc/piggy/go/internal/bravo/markl"

	// Blank-import the native registrations so pivy_ecdh_p256_pub and
	// age_x25519_pub are present before we build/parse recipient IDs.
	_ "github.com/amarbel-llc/piggy/go/internal/charlie/markl_registrations"
)

const (
	typeTag = "pigpen-v1"

	formatPivyP256  = "pivy_ecdh_p256_pub"
	formatAgeX25519 = "age_x25519_pub"

	hrpWrapP256      = "pigpen_wrap_p256"
	hrpWrapX25519    = "pigpen_wrap_x25519"
	hrpHeaderMAC     = "pigpen_header_mac"
	purposeWrap      = "pigpen-wrap-v1"
	purposeRecipient = "piggy-recipient-v1"
)

// markIdentity aliases the markl Id so crypto.go can name the oracle's
// "self" key without importing markl.
type markIdentity = markl.Id

// ECDHOracle performs the card-bound scalar multiplication for a P-256
// recipient (RFC 0008 §4.3, §7). A WASM host wires this to piggy-agent's
// ecdh@joyent.com extension; the slot-9D scalar never leaves the card.
type ECDHOracle interface {
	// ECDH returns the 32-byte X-coordinate of (self_private · partnerEpk),
	// where self names the card key by its recipient markl ID and
	// partnerEpk is the compressed (33-byte) ephemeral public key.
	ECDH(self markl.Id, partnerEpk []byte) ([]byte, error)
}

// X25519Identity is a software age identity for the pure-software open
// path (RFC 0008 §4.4): both halves of an X25519 keypair.
type X25519Identity struct {
	Public []byte // 32-byte recipient key
	Secret []byte // 32-byte scalar
}

// Recipient is one recipient line of a pigpen document.
type Recipient struct {
	ID      markl.Id // recipient markl ID (pivy_ecdh_p256_pub | age_x25519_pub)
	Comment string   // recipient-set mode only
	Wrap    []byte   // sealed mode: Epk‖AEAD(file key); nil otherwise
}

func (r Recipient) format() string { return r.ID.GetMarklFormat().GetMarklFormatId() }

// Document is the in-memory model of a pigpen-v1 document.
type Document struct {
	Description string
	Recipients  []Recipient
	Payload     []byte // inline ciphertext (sealed mode); nil otherwise
	MAC         []byte // 32-byte header MAC (sealed mode); nil otherwise
}

// Sealed reports whether the document carries a payload + MAC (vs. being
// a bare recipient set / piggy-ids replacement).
func (d *Document) Sealed() bool { return d.MAC != nil }

// NewRecipientSet builds a payload-less pigpen document — the drop-in for
// a piggy-ids file (RFC 0008 §2.2).
func NewRecipientSet(recipients []Recipient) *Document {
	return &Document{Recipients: recipients}
}

// Seal encrypts plaintext to the given recipients, producing a sealed
// pigpen document. All wraps are computed in pure software (the P-256
// encrypt side needs no card). rng may be nil to use the package CSPRNG.
func Seal(plaintext []byte, recipients []markl.Id, rng io.Reader) (*Document, error) {
	if rng == nil {
		rng = defaultRand
	}
	if len(recipients) == 0 {
		return nil, errors.New("pigpen: at least one recipient is required")
	}
	fileKey, err := randomFileKey(rng)
	if err != nil {
		return nil, err
	}
	defer zero(fileKey)

	d := &Document{}
	for _, id := range recipients {
		r := Recipient{ID: id}
		switch f := id.GetMarklFormat().GetMarklFormatId(); f {
		case formatPivyP256:
			if r.Wrap, err = wrapP256(fileKey, id.GetBytes(), rng); err != nil {
				return nil, err
			}
		case formatAgeX25519:
			if r.Wrap, err = wrapX25519(fileKey, id.GetBytes(), rng); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("pigpen: unsupported recipient format %q", f)
		}
		d.Recipients = append(d.Recipients, r)
	}

	if d.Payload, err = sealPayload(fileKey, plaintext, rng); err != nil {
		return nil, err
	}

	canon, err := d.canonicalHeader()
	if err != nil {
		return nil, err
	}
	d.MAC = headerMAC(fileKey, canon)
	return d, nil
}

// Open recovers the plaintext. It tries each recipient against the
// supplied software X25519 identities and, for P-256 recipients, the
// oracle (which may be nil to skip card-bound recipients).
func (d *Document) Open(oracle ECDHOracle, x25519 []X25519Identity) ([]byte, error) {
	if !d.Sealed() {
		return nil, errors.New("pigpen: document is a recipient set, not sealed")
	}
	for _, r := range d.Recipients {
		if r.Wrap == nil {
			continue
		}
		var fileKey []byte
		var err error
		switch r.format() {
		case formatAgeX25519:
			id := findX25519(x25519, r.ID.GetBytes())
			if id == nil {
				continue
			}
			fileKey, err = unwrapX25519(r.Wrap, r.ID.GetBytes(), id.Secret)
		case formatPivyP256:
			if oracle == nil {
				continue
			}
			fileKey, err = unwrapP256(r.Wrap, r.ID.GetBytes(), oracle, r.ID)
		default:
			continue
		}
		if err != nil {
			continue // not our key (or tampered); try the next recipient
		}
		defer zero(fileKey)

		canon, err := d.canonicalHeader()
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(headerMAC(fileKey, canon), d.MAC) {
			return nil, errors.New("pigpen: header MAC mismatch")
		}
		return openPayload(fileKey, d.Payload)
	}
	return nil, errors.New("pigpen: no usable recipient (no matching identity/oracle)")
}

// --- markl-ID encoding for the pigpen blobs ------------------------------

func encodeWrap(format string, blob []byte) (string, error) {
	var hrp string
	switch format {
	case formatPivyP256:
		hrp = hrpWrapP256
	case formatAgeX25519:
		hrp = hrpWrapX25519
	default:
		return "", fmt.Errorf("pigpen: no wrap HRP for %q", format)
	}
	s, err := blech32.Encode(hrp, blob)
	if err != nil {
		return "", err
	}
	return purposeWrap + "@" + string(s), nil
}

func decodeWrap(s string) ([]byte, error) {
	body := s
	if i := strings.IndexByte(s, '@'); i >= 0 {
		body = s[i+1:]
	}
	hrp, data, err := blech32.DecodeString(body)
	if err != nil {
		return nil, err
	}
	if hrp != hrpWrapP256 && hrp != hrpWrapX25519 {
		return nil, fmt.Errorf("pigpen: unexpected wrap HRP %q", hrp)
	}
	return data, nil
}

func encodeMAC(mac []byte) (string, error) {
	s, err := blech32.Encode(hrpHeaderMAC, mac)
	if err != nil {
		return "", err
	}
	return string(s), nil
}

func decodeMAC(s string) ([]byte, error) {
	hrp, data, err := blech32.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if hrp != hrpHeaderMAC {
		return nil, fmt.Errorf("pigpen: unexpected MAC HRP %q", hrp)
	}
	return data, nil
}

func findX25519(ids []X25519Identity, pub []byte) *X25519Identity {
	for i := range ids {
		if bytes.Equal(ids[i].Public, pub) {
			return &ids[i]
		}
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
