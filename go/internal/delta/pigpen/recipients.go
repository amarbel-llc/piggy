package pigpen

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

// isEncryptionRecipient reports whether id names a key a file key can be
// wrapped to: a pivy_ecdh_p256_pub or age_x25519_pub key, bare or under
// piggy-recipient-v1 (RFC 0008 §2.3). SSH-auth entries and ids under any
// other purpose are not encryption recipients.
func isEncryptionRecipient(id markl.Id) bool {
	format := id.GetMarklFormat()
	if format == nil {
		return false
	}
	switch format.GetMarklFormatId() {
	case formatPivyP256, formatAgeX25519:
	default:
		return false
	}
	switch id.GetPurposeId() {
	case "", purposeRecipient:
		return true
	default:
		return false
	}
}

// canonicalRecipient returns id under the piggy-recipient-v1 purpose, the
// form writers emit (RFC 0003 "Canonical Form").
func canonicalRecipient(id markl.Id) (markl.Id, error) {
	var out markl.Id
	if err := out.SetPurposeId(purposeRecipient); err != nil {
		return out, err
	}
	if err := out.SetMarklId(id.GetMarklFormat().GetMarklFormatId(), id.GetBytes()); err != nil {
		return out, err
	}
	return out, nil
}

// EncryptionRecipients returns the document's encryption recipients in
// document order, each under the piggy-recipient-v1 purpose. SSH-auth and
// unknown-purpose lines are skipped (RFC 0008 §2.3).
func (d *Document) EncryptionRecipients() []markl.Id {
	var out []markl.Id
	for _, r := range d.Recipients {
		if !isEncryptionRecipient(r.ID) {
			continue
		}
		id, err := canonicalRecipient(r.ID)
		if err != nil {
			// Unreachable: the id already parsed in this format and the
			// purpose accepts it.
			panic(err)
		}
		out = append(out, id)
	}
	return out
}

// ParseRecipients reads a piggy-ids file in either form and returns its
// encryption recipients: a pigpen document (leading "---\n", RFC 0009
// §3.2) or RFC 0003 lines. A pointer document is an error here; resolve
// it first (RFC 0010).
func ParseRecipients(raw []byte) ([]markl.Id, error) {
	if !bytes.HasPrefix(raw, []byte(boundary)) {
		return parseRFC0003Recipients(raw)
	}
	if isPointerDocument(raw) {
		return nil, errors.New(
			"pigpen: this is a pointer document; resolve it into a recipient set first (RFC 0010)",
		)
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return nil, err
	}
	return doc.EncryptionRecipients(), nil
}

// isPointerDocument reports whether a hyphence document's type line names
// the pointer face (RFC 0008 §2.2).
func isPointerDocument(raw []byte) bool {
	h, err := parseHyphence(raw)
	if err != nil {
		return false
	}
	for _, l := range h.meta {
		if l.prefix == '!' && l.body == pointerTypeTag {
			return true
		}
	}
	return false
}

// parseRFC0003Recipients reads the RFC 0003 line format (piggy-ids(5)
// GRAMMAR): blank lines, `#` comment lines, and one markl id per line with
// an optional whitespace-separated `#` comment. SSH-auth entries are
// skipped; any other non-recipient id is an error.
func parseRFC0003Recipients(raw []byte) ([]markl.Id, error) {
	var out []markl.Id
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idStr := strings.Fields(line)[0]
		var id markl.Id
		if err := id.Set(idStr); err != nil {
			return nil, fmt.Errorf("pigpen: piggy-ids line %d: bad markl id %q: %w", n+1, idStr, err)
		}
		switch {
		case isEncryptionRecipient(id):
			canonical, err := canonicalRecipient(id)
			if err != nil {
				return nil, err
			}
			out = append(out, canonical)
		case id.GetPurposeId() == markl.PurposePiggyPivAuthV1:
			// "who may log in", not "who can decrypt" (RFC 0003).
		default:
			return nil, fmt.Errorf(
				"pigpen: piggy-ids line %d: %q is neither an encryption recipient nor an ssh-auth entry",
				n+1, idStr,
			)
		}
	}
	return out, nil
}

// CanonicalRecipientSet returns the bytes a consumer hashes to detect a
// changed recipient set: each id in its piggy-recipient-v1@ text form,
// de-duplicated, sorted bytewise, one per line, each line ending in "\n".
// The empty set is zero bytes. Ids that are not encryption recipients are
// ignored. Comments and order never reach this form, which makes it RFC
// 0003 equality.
func CanonicalRecipientSet(ids []markl.Id) []byte {
	seen := make(map[string]struct{}, len(ids))
	var lines []string
	for _, id := range ids {
		if !isEncryptionRecipient(id) {
			continue
		}
		canonical, err := canonicalRecipient(id)
		if err != nil {
			panic(err) // unreachable, as in EncryptionRecipients
		}
		text := canonical.StringWithFormat()
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}
		lines = append(lines, text)
	}
	sort.Strings(lines)

	var out bytes.Buffer
	for _, line := range lines {
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// SameRecipientSet reports whether a and b name the same encryption
// recipients: exactly equality of their CanonicalRecipientSet bytes.
func SameRecipientSet(a, b []markl.Id) bool {
	return bytes.Equal(CanonicalRecipientSet(a), CanonicalRecipientSet(b))
}
