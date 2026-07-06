package pigpen

import (
	"errors"
	"fmt"
	"strings"

	"github.com/amarbel-llc/piggy/go/internal/bravo/markl"
)

// buildHyphence renders the Document into the framing-level view. When
// includeMAC is false the type line is the bare "pigpen-v1" (used for the
// MAC pre-image, RFC 0008 §4.6); otherwise it carries the MAC lock.
func (d *Document) buildHyphence(includeMAC bool) (*hyphenceDoc, error) {
	h := &hyphenceDoc{}
	// An empty description renders nothing (a "# " line would desync the
	// header MAC against the Rust impl, which also drops it).
	if d.Description != "" {
		if err := rejectControl("description", d.Description); err != nil {
			return nil, err
		}
		h.meta = append(h.meta, metaLine{'#', d.Description})
	}
	for _, r := range d.Recipients {
		body := r.ID.StringWithFormat()
		switch {
		case r.Wrap != nil:
			wrapStr, err := encodeWrap(r.format(), r.Wrap)
			if err != nil {
				return nil, err
			}
			body += " < " + wrapStr
		case r.Comment != "":
			if err := rejectControl("comment", r.Comment); err != nil {
				return nil, err
			}
			body += "  # " + r.Comment
		}
		h.meta = append(h.meta, metaLine{'-', body})
	}
	typeBody := typeTag
	if includeMAC && d.MAC != nil {
		macStr, err := encodeMAC(d.MAC)
		if err != nil {
			return nil, err
		}
		typeBody += "@" + macStr
	}
	h.meta = append(h.meta, metaLine{'!', typeBody})
	if includeMAC && d.Sealed() {
		h.body = d.Payload
	}
	return h, nil
}

// canonicalHeader is the MAC pre-image: the metadata section with the
// bare type line (RFC 0008 §4.6).
func (d *Document) canonicalHeader() ([]byte, error) {
	h, err := d.buildHyphence(false)
	if err != nil {
		return nil, err
	}
	return h.marshalMetadata(), nil
}

// MarshalText renders the full pigpen document as hyphence bytes.
func (d *Document) MarshalText() ([]byte, error) {
	h, err := d.buildHyphence(true)
	if err != nil {
		return nil, err
	}
	return h.marshal()
}

// ParseDocument decodes a pigpen document from hyphence bytes.
func ParseDocument(raw []byte) (*Document, error) {
	h, err := parseHyphence(raw)
	if err != nil {
		return nil, err
	}
	d := &Document{}
	sawType := false
	for _, l := range h.meta {
		switch l.prefix {
		case '#':
			// Skip empty "# " lines so an empty description stays "" (the
			// none sentinel, symmetric with Rust), keeping the canonical
			// header — and thus the MAC — identical across implementations.
			if l.body != "" {
				if d.Description != "" {
					d.Description += " "
				}
				d.Description += l.body
			}
		case '-':
			r, err := parseRecipientLine(l.body)
			if err != nil {
				return nil, err
			}
			d.Recipients = append(d.Recipients, r)
		case '@':
			return nil, errors.New("pigpen: '@'-referenced payload not supported in prototype (inline only)")
		case '!':
			if err := d.parseTypeLine(l.body); err != nil {
				return nil, err
			}
			sawType = true
		}
	}
	if !sawType {
		return nil, errors.New("pigpen: missing '! pigpen-v1' type line")
	}
	d.Payload = h.body
	if err := d.validate(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Document) parseTypeLine(body string) error {
	tag := body
	if i := strings.IndexByte(body, '@'); i >= 0 {
		tag = body[:i]
		mac, err := decodeMAC(body[i+1:])
		if err != nil {
			return err
		}
		d.MAC = mac
	}
	if tag != typeTag {
		return fmt.Errorf("pigpen: unexpected type %q (want %q)", tag, typeTag)
	}
	return nil
}

func parseRecipientLine(body string) (Recipient, error) {
	var r Recipient
	idStr := body
	// Split the comment on the exact "  # " delimiter (two spaces, hash,
	// space) and take the remainder verbatim, BEFORE looking for the " < "
	// wrap delimiter. A comment is free text that MAY contain " < " or a
	// leading '#'; checking it first (and not trimming its body) keeps those
	// characters intact instead of mistaking a comment for a key wrap or
	// eating a leading '#'. The id and blech32 wrap never contain "  # ".
	if i := strings.Index(body, "  # "); i >= 0 {
		idStr = strings.TrimSpace(body[:i])
		r.Comment = body[i+4:]
	} else if i := strings.Index(body, " < "); i >= 0 {
		idStr = strings.TrimSpace(body[:i])
		wrap, err := decodeWrap(strings.TrimSpace(body[i+3:]))
		if err != nil {
			return r, err
		}
		r.Wrap = wrap
	} else {
		idStr = strings.TrimSpace(body)
	}
	var id markl.Id
	if err := id.Set(idStr); err != nil {
		return r, fmt.Errorf("pigpen: bad recipient %q: %w", idStr, err)
	}
	r.ID = id
	return r, nil
}

// rejectControl refuses a description/comment carrying a line-breaking
// control character. Metadata is single-line (RFC 0001 framing), so an
// embedded newline would silently corrupt the document on re-parse; refuse
// it at serialization time.
func rejectControl(field, s string) error {
	if strings.ContainsAny(s, "\n\r") {
		return fmt.Errorf("pigpen: %s must not contain a newline (metadata is single-line)", field)
	}
	return nil
}

// validate enforces the structural rules of RFC 0008 §2.2: a document is
// either a pure recipient set (no wraps, no MAC, no body) or fully sealed
// (every encryption recipient wrapped, MAC present). Mixed states are
// rejected.
func (d *Document) validate() error {
	wrapped, unwrapped := 0, 0
	for _, r := range d.Recipients {
		if r.Wrap != nil {
			wrapped++
		} else {
			unwrapped++
		}
	}
	sealed := d.MAC != nil || len(d.Payload) > 0 || wrapped > 0
	if !sealed {
		return nil // pure recipient set
	}
	if unwrapped > 0 {
		return errors.New("pigpen: mixed sealed/unsealed recipients")
	}
	if d.MAC == nil {
		return errors.New("pigpen: sealed document missing header MAC")
	}
	if len(d.Payload) == 0 {
		return errors.New("pigpen: sealed document missing payload")
	}
	return nil
}
