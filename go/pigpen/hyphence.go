package pigpen

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Minimal hyphence framing (madder RFC 0001). Only the subset pigpen
// needs: a metadata section delimited by "---\n" boundaries, the
// prefixes pigpen uses (# - @ !), a required blank-line separator
// before an inline body, and the @-XOR-body rule.
//
// This is intentionally NOT a full RFC 0001 implementation (no % comment
// entanglement, no < standalone object refs, no lenient mode). It is the
// envelope sketch RFC 0008 "Compatibility" describes.

const boundary = "---\n"

var (
	errNoOpeningBoundary   = errors.New("pigpen: missing opening '---' boundary")
	errNoClosingBoundary   = errors.New("pigpen: missing closing '---' boundary")
	errMissingSeparator    = errors.New("pigpen: body present without blank-line separator")
	errAtRefWithInlineBody = errors.New("pigpen: '@' blob reference together with an inline body")
	errUnknownPrefix       = errors.New("pigpen: unknown metadata prefix")
)

// metaLine is one decoded metadata line: a single-byte prefix and its
// content (everything after "<prefix> ", trimmed of the trailing LF).
type metaLine struct {
	prefix byte
	body   string
}

// hyphenceDoc is the framing-level view: ordered metadata lines plus the
// raw body bytes (empty if none).
type hyphenceDoc struct {
	meta []metaLine
	body []byte
}

func (h *hyphenceDoc) hasInlineBody() bool { return len(h.body) > 0 }

func (h *hyphenceDoc) hasAtRef() bool {
	for _, l := range h.meta {
		if l.prefix == '@' {
			return true
		}
	}
	return false
}

// marshalMetadata renders just the metadata section (both boundaries
// included) in canonical RFC 0001 order: descriptions (#), tags/refs (-),
// blob (@), type (!). Within a prefix, input order is preserved.
func (h *hyphenceDoc) marshalMetadata() []byte {
	var b bytes.Buffer
	b.WriteString(boundary)
	for _, want := range []byte{'#', '-', '@', '!'} {
		for _, l := range h.meta {
			if l.prefix == want {
				fmt.Fprintf(&b, "%c %s\n", l.prefix, l.body)
			}
		}
	}
	b.WriteString(boundary)
	return b.Bytes()
}

// marshal renders the full document: metadata section, then (if there is
// an inline body) the blank-line separator and the body bytes.
func (h *hyphenceDoc) marshal() ([]byte, error) {
	if h.hasAtRef() && h.hasInlineBody() {
		return nil, errAtRefWithInlineBody
	}
	out := h.marshalMetadata()
	if h.hasInlineBody() {
		out = append(out, '\n')
		out = append(out, h.body...)
	}
	return out, nil
}

// parseHyphence decodes the framing of a pigpen document.
func parseHyphence(raw []byte) (*hyphenceDoc, error) {
	r := bufio.NewReader(bytes.NewReader(raw))

	first, err := r.ReadString('\n')
	if err != nil || first != boundary {
		return nil, errNoOpeningBoundary
	}

	doc := &hyphenceDoc{}
	closed := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, errNoClosingBoundary
		}
		if line == boundary {
			closed = true
			break
		}
		// "<prefix> <content>\n"
		content := strings.TrimSuffix(line, "\n")
		if len(content) < 2 || content[1] != ' ' {
			return nil, fmt.Errorf("pigpen: malformed metadata line: %q", line)
		}
		prefix := content[0]
		switch prefix {
		case '#', '-', '@', '!':
			body := content[2:]
			// Reject non-UTF-8 metadata bodies (symmetric with the Rust impl,
			// which also rejects rather than lossily decoding); valid pigpen
			// content — markl IDs, blech32, text — is always UTF-8.
			if !utf8.ValidString(body) {
				return nil, errors.New("pigpen: metadata line body is not valid UTF-8")
			}
			doc.meta = append(doc.meta, metaLine{prefix: prefix, body: body})
		default:
			return nil, fmt.Errorf("%w: %q", errUnknownPrefix, prefix)
		}
	}
	if !closed {
		return nil, errNoClosingBoundary
	}

	// Anything after the closing boundary is the body, preceded by the
	// required blank-line separator.
	rest, _ := readAll(r)
	if len(rest) > 0 {
		if rest[0] != '\n' {
			return nil, errMissingSeparator
		}
		doc.body = rest[1:]
	}
	if doc.hasAtRef() && doc.hasInlineBody() {
		return nil, errAtRefWithInlineBody
	}
	return doc, nil
}

func readAll(r *bufio.Reader) ([]byte, error) {
	var b bytes.Buffer
	_, err := b.ReadFrom(r)
	return b.Bytes(), err
}
