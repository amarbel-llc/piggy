package pigpen

//go:generate dagnabit export

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"strings"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"

	// Blank-import the native registrations so the recipient formats and
	// the pigpen wrap / header-MAC formats and purposes are present before
	// we build or parse any id.
	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)

const (
	typeTag        = "pigpen-v1"
	pointerTypeTag = "pigpen-pointer-v1"

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
//
// A caller-supplied rng does NOT make the output reproducible: the file
// key and payload nonce are read from it, but crypto/ecdh generates the
// per-recipient ephemeral keys from the system CSPRNG regardless
// (measured on go 1.26). Supply an rng only as an entropy source.
func Seal(plaintext []byte, recipients []markl.Id, rng io.Reader) (*Document, error) {
	if rng == nil {
		rng = defaultRand
	}
	in, err := drawSealInputs(recipients, rng)
	defer in.zero() // also scrubs what a failed draw got as far as reading
	if err != nil {
		return nil, err
	}
	return sealWith(plaintext, recipients, in)
}

// sealInputs are every secret a seal consumes (RFC 0008 §4.1, §4.3–§4.5).
// Seal draws them from a CSPRNG; the normative vectors (RFC 0009 §8) fix
// them, so the production path and the vector path share all the crypto.
type sealInputs struct {
	fileKey      []byte   // fileKeyLen bytes
	payloadNonce []byte   // payloadNonceLen bytes
	ephemeral    [][]byte // one ephemeral private scalar per recipient, in order
}

func (in sealInputs) zero() {
	zero(in.fileKey)
	for _, secret := range in.ephemeral {
		zero(secret)
	}
}

func drawSealInputs(recipients []markl.Id, rng io.Reader) (in sealInputs, err error) {
	if in.fileKey, err = randomBytes(rng, fileKeyLen); err != nil {
		return in, err
	}
	for _, id := range recipients {
		if !isEncryptionRecipient(id) {
			return in, notAnEncryptionRecipient(id)
		}
		var curve ecdh.Curve
		switch id.GetMarklFormat().GetMarklFormatId() {
		case formatPivyP256:
			curve = ecdh.P256()
		default:
			curve = ecdh.X25519()
		}
		esk, err := curve.GenerateKey(rng)
		if err != nil {
			return in, err
		}
		in.ephemeral = append(in.ephemeral, esk.Bytes())
	}
	if in.payloadNonce, err = randomBytes(rng, payloadNonceLen); err != nil {
		return in, err
	}
	return in, nil
}

func notAnEncryptionRecipient(id markl.Id) error {
	return fmt.Errorf(
		"pigpen: %q is not an encryption recipient (want a %s or %s key, bare or under %s)",
		id.StringWithFormat(), formatPivyP256, formatAgeX25519, purposeRecipient,
	)
}

// sealWith is Seal with every secret supplied by the caller.
func sealWith(plaintext []byte, recipients []markl.Id, in sealInputs) (*Document, error) {
	if len(recipients) == 0 {
		return nil, errors.New("pigpen: at least one recipient is required")
	}
	if len(in.ephemeral) != len(recipients) {
		return nil, fmt.Errorf(
			"pigpen: %d ephemeral secrets for %d recipients", len(in.ephemeral), len(recipients),
		)
	}
	if len(in.fileKey) != fileKeyLen {
		return nil, fmt.Errorf("pigpen: file key is %d bytes, want %d", len(in.fileKey), fileKeyLen)
	}

	d := &Document{}
	var err error
	for i, id := range recipients {
		// A null id has no format, and an id under a foreign purpose is
		// not a key to wrap to; a bare id is promoted (RFC 0008 §2.3).
		if !isEncryptionRecipient(id) {
			return nil, notAnEncryptionRecipient(id)
		}
		if id, err = canonicalRecipient(id); err != nil {
			return nil, err
		}
		r := Recipient{ID: id}
		switch f := id.GetMarklFormat().GetMarklFormatId(); f {
		case formatPivyP256:
			if r.Wrap, err = wrapP256(in.fileKey, id.GetBytes(), in.ephemeral[i]); err != nil {
				return nil, err
			}
		case formatAgeX25519:
			if r.Wrap, err = wrapX25519(in.fileKey, id.GetBytes(), in.ephemeral[i]); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("pigpen: unsupported recipient format %q", f)
		}
		d.Recipients = append(d.Recipients, r)
	}

	if d.Payload, err = sealPayload(in.fileKey, plaintext, in.payloadNonce); err != nil {
		return nil, err
	}

	canon, err := d.canonicalHeader()
	if err != nil {
		return nil, err
	}
	d.MAC = headerMAC(in.fileKey, canon)
	return d, nil
}

// Open recovers the plaintext. It tries each recipient against the
// supplied software X25519 identities and, for P-256 recipients, the
// oracle (which may be nil to skip card-bound recipients).
func (d *Document) Open(oracle ECDHOracle, x25519 []X25519Identity) ([]byte, error) {
	if !d.Sealed() {
		return nil, errors.New("pigpen: document is a recipient set, not sealed")
	}
	var oracleFailures []error
	tried := make(map[string]bool, len(d.Recipients))
	for _, r := range d.Recipients {
		if r.Wrap == nil {
			continue
		}
		// One attempt per distinct key: a well-formed document names each
		// recipient once, and a crafted one repeating a key must not buy
		// one card operation (a touch, a PIN) per repeat.
		key := string(r.ID.GetBytes())
		if tried[key] {
			continue
		}
		tried[key] = true
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
			// An oracle that could not answer is not "not our key": keep
			// it, so a caller is not told a reachable-agent problem is a
			// wrong-recipient one.
			var oracleFailure oracleError
			if errors.As(err, &oracleFailure) {
				oracleFailures = append(oracleFailures, oracleFailure.cause)
			}
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
	if len(oracleFailures) > 0 {
		return nil, fmt.Errorf(
			"pigpen: no recipient could be opened; the ECDH oracle failed: %w",
			errors.Join(oracleFailures...),
		)
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
	// markl.Id treats empty data as the null id and renders it as "";
	// an empty wrap must fail here, not serialize as a missing lock.
	if len(blob) == 0 {
		return "", fmt.Errorf("pigpen: empty wrap for a %s recipient", recipientFormat)
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
	if len(mac) == 0 {
		return "", errors.New("pigpen: empty header MAC")
	}
	var id markl.Id
	if err := id.SetMarklId(markl.FormatIdPigpenHeaderMac, mac); err != nil {
		return "", fmt.Errorf("pigpen: bad header MAC: %w", err)
	}
	return id.StringWithFormat(), nil
}

func decodeMAC(s string) ([]byte, error) {
	// The lock is a bare id. Refuse any purpose slot outright: a quoted
	// empty one (`""@…`) would otherwise decode to "no purpose".
	if strings.Contains(s, "@") {
		return nil, fmt.Errorf("pigpen: header MAC lock %q carries a purpose, want none", s)
	}
	var id markl.Id
	if err := id.Set(s); err != nil {
		return nil, fmt.Errorf("pigpen: bad header MAC lock %q: %w", s, err)
	}
	// markl.Id.Set treats "" as the null id, which has no format.
	if id.IsEmpty() {
		return nil, errors.New("pigpen: empty header MAC lock")
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
