package pigpen

//go:generate dagnabit export

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"

	// Blank-import the native registrations so the recipient formats and
	// the pigpen wrap / header-MAC formats and purposes are present before
	// we build or parse any id.
	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

const (
	typeTag = "pigpen-v1"

	formatPivyP256   = markl.FormatIdPivyEcdhP256Pub
	formatAgeX25519  = markl.FormatIdAgeX25519Pub
	purposeRecipient = markl.PurposePiggyRecipientV1
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
//
// The wrap lock is `pigpen-wrap-v1@<wrap-format>-<blech32>` and the header
// MAC lock is the bare `pigpen_header_mac-<blech32>` (RFC 0008 §2.4, §2.6).
// Both go through the markl codec, so the registry enforces the blob size
// and the (purpose, format) pairing.

// wrapFormatFor names the wrap format that locks a recipient of the given
// format. A recipient format with no wrap format is not an encryption
// recipient and carries no wrap lock (RFC 0008 §2.3).
func wrapFormatFor(recipientFormat string) (string, error) {
	switch recipientFormat {
	case formatPivyP256:
		return markl.FormatIdPigpenWrapP256, nil
	case formatAgeX25519:
		return markl.FormatIdPigpenWrapX25519, nil
	default:
		return "", fmt.Errorf(
			"pigpen: %q is not an encryption recipient format and carries no wrap lock",
			recipientFormat,
		)
	}
}

func encodeWrap(recipientFormat string, blob []byte) (string, error) {
	wrapFormat, err := wrapFormatFor(recipientFormat)
	if err != nil {
		return "", err
	}
	var id markl.Id
	if err := id.SetPurposeId(markl.PurposePigpenWrapV1); err != nil {
		return "", err
	}
	if err := id.SetMarklId(wrapFormat, blob); err != nil {
		return "", fmt.Errorf("pigpen: bad %s wrap for a %s recipient: %w", wrapFormat, recipientFormat, err)
	}
	return id.StringWithFormat(), nil
}

func decodeWrap(recipientFormat, s string) ([]byte, error) {
	wrapFormat, err := wrapFormatFor(recipientFormat)
	if err != nil {
		return nil, err
	}
	var id markl.Id
	if err := id.Set(s); err != nil {
		return nil, fmt.Errorf("pigpen: bad wrap lock %q: %w", s, err)
	}
	if got := id.GetPurposeId(); got != markl.PurposePigpenWrapV1 {
		return nil, fmt.Errorf(
			"pigpen: wrap lock has purpose %q, want %q", got, markl.PurposePigpenWrapV1,
		)
	}
	if got := id.GetMarklFormat().GetMarklFormatId(); got != wrapFormat {
		return nil, fmt.Errorf(
			"pigpen: a %s recipient is locked with a %s wrap, want %s",
			recipientFormat, got, wrapFormat,
		)
	}
	return bytes.Clone(id.GetBytes()), nil
}

func encodeMAC(mac []byte) (string, error) {
	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdPigpenHeaderMac, mac); err != nil {
		return "", fmt.Errorf("pigpen: bad header MAC: %w", err)
	}
	return id.StringWithFormat(), nil
}

func decodeMAC(s string) ([]byte, error) {
	var id markl.Id
	if err := id.Set(s); err != nil {
		return nil, fmt.Errorf("pigpen: bad header MAC lock %q: %w", s, err)
	}
	if got := id.GetPurposeId(); got != "" {
		return nil, fmt.Errorf("pigpen: header MAC lock carries purpose %q, want none", got)
	}
	if got := id.GetMarklFormat().GetMarklFormatId(); got != markl.FormatIdPigpenHeaderMac {
		return nil, fmt.Errorf(
			"pigpen: header MAC lock has format %q, want %q", got, markl.FormatIdPigpenHeaderMac,
		)
	}
	return bytes.Clone(id.GetBytes()), nil
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
