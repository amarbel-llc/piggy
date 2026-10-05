package pigpen

import (
	"errors"
	"fmt"
	"strings"
)

// Pointer is the pointer face of a pigpen document (RFC 0008 §2.2): it
// names a resolver by kind and an opaque locator instead of carrying
// recipients. Locator is never interpreted here; it is handed verbatim to
// whatever runs the resolver (RFC 0010).
type Pointer struct {
	Kind    string
	Locator string
}

// ParsePointer decodes a pigpen-pointer-v1 document. A document of any
// other type, a pointer missing its kind or locator, and a pointer
// carrying any other `-` line (a recipient, say) are all errors.
func ParsePointer(raw []byte) (*Pointer, error) {
	h, err := parseHyphence(raw)
	if err != nil {
		return nil, err
	}

	typeLines := 0
	for _, l := range h.meta {
		if l.prefix != '!' {
			continue
		}
		typeLines++
		if l.body != pointerTypeTag {
			return nil, fmt.Errorf("pigpen: not a %s document (type %q)", pointerTypeTag, l.body)
		}
	}
	switch {
	case typeLines == 0:
		return nil, fmt.Errorf("pigpen: not a %s document (no '!' type line)", pointerTypeTag)
	case typeLines > 1:
		return nil, errors.New("pigpen: more than one '!' type line")
	}
	if len(h.body) > 0 {
		return nil, errors.New("pigpen: a pointer document carries no body")
	}

	p := &Pointer{}
	sawKind, sawLocator := false, false
	for _, l := range h.meta {
		if l.prefix != '-' {
			continue
		}
		if value, ok := quotedTagValue(l.body, "kind"); ok && !sawKind {
			p.Kind, sawKind = value, true
		} else if value, ok := quotedTagValue(l.body, "locator"); ok && !sawLocator {
			p.Locator, sawLocator = value, true
		} else {
			// A recipient line, a repeated tag, or anything else: a
			// mixed-state document (RFC 0008 §2.2).
			return nil, fmt.Errorf("pigpen: unexpected '-' line in a %s document: %q", pointerTypeTag, l.body)
		}
	}
	switch {
	case !sawKind:
		return nil, errors.New("pigpen: pointer is missing its kind tag")
	case !sawLocator:
		return nil, errors.New("pigpen: pointer is missing its locator tag")
	}
	if err := ValidatePointerKind(p.Kind); err != nil {
		return nil, err
	}
	return p, nil
}

// ValidatePointerKind enforces RFC 0010 §2's one constraint on a kind: it
// names an executable looked up on PATH, so it must not be empty and must
// not contain a path separator or a NUL byte.
func ValidatePointerKind(kind string) error {
	if kind == "" {
		return errors.New("pigpen: pointer kind is empty")
	}
	if strings.ContainsAny(kind, "/\x00") {
		return fmt.Errorf("pigpen: pointer kind %q contains a path separator or NUL", kind)
	}
	return nil
}

// MarshalText renders the pointer as a pigpen-pointer-v1 document.
func (p *Pointer) MarshalText() ([]byte, error) {
	if err := ValidatePointerKind(p.Kind); err != nil {
		return nil, err
	}
	for field, value := range map[string]string{"kind": p.Kind, "locator": p.Locator} {
		if err := rejectControl(field, value); err != nil {
			return nil, err
		}
		if strings.Contains(value, `"`) {
			return nil, fmt.Errorf("pigpen: pointer %s must not contain a double quote", field)
		}
	}
	h := &hyphenceDoc{meta: []metaLine{
		{'-', `kind="` + p.Kind + `"`},
		{'-', `locator="` + p.Locator + `"`},
		{'!', pointerTypeTag},
	}}
	return h.marshal()
}

// quotedTagValue reads `key="value"`, returning value.
func quotedTagValue(body, key string) (string, bool) {
	rest, ok := strings.CutPrefix(body, key+`="`)
	if !ok {
		return "", false
	}
	return strings.CutSuffix(rest, `"`)
}
