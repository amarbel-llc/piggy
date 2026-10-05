package pigpen

import (
	"bytes"
	"testing"
)

// The worked example of RFC 0010 / RFC 0008 §9.
const rfc0010Pointer = "---\n- kind=\"papi-http\"\n- locator=\"https://example.com\"\n! pigpen-pointer-v1\n---\n"

func TestParsePointerReadsTheRFCExample(t *testing.T) {
	p, err := ParsePointer([]byte(rfc0010Pointer))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != "papi-http" || p.Locator != "https://example.com" {
		t.Fatalf("pointer = %+v", p)
	}
	out, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte(rfc0010Pointer)) {
		t.Fatalf("pointer changed on re-serialization:\n got %q\nwant %q", out, rfc0010Pointer)
	}
}

func TestParsePointerRejectsWhatIsNotAPointer(t *testing.T) {
	x, _, _, _ := recipientFixtures(t)
	for label, raw := range map[string]string{
		"a recipient set":            "---\n- " + x.StringWithFormat() + "\n! pigpen-v1\n---\n",
		"a pointer with a recipient": "---\n- kind=\"k\"\n- locator=\"l\"\n- " + x.StringWithFormat() + "\n! pigpen-pointer-v1\n---\n",
		"a missing locator":          "---\n- kind=\"k\"\n! pigpen-pointer-v1\n---\n",
		"a missing kind":             "---\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n",
		"a repeated kind":            "---\n- kind=\"k\"\n- kind=\"other\"\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n",
		"a kind with a slash":        "---\n- kind=\"../evil\"\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n",
		"an empty kind":              "---\n- kind=\"\"\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n",
		"an unquoted kind":           "---\n- kind=k\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n",
		"two type lines":             "---\n- kind=\"k\"\n- locator=\"l\"\n! pigpen-pointer-v1\n! pigpen-pointer-v1\n---\n",
		"a body":                     "---\n- kind=\"k\"\n- locator=\"l\"\n! pigpen-pointer-v1\n---\n\nbody\n",
		"no type line":               "---\n- kind=\"k\"\n- locator=\"l\"\n---\n",
		"not hyphence":               "kind=k\n",
	} {
		if _, err := ParsePointer([]byte(raw)); err == nil {
			t.Errorf("%s: accepted, want rejection", label)
		}
	}
}

func TestPointerMarshalRefusesWhatWouldNotRoundTrip(t *testing.T) {
	for label, p := range map[string]Pointer{
		"a newline in the locator": {Kind: "k", Locator: "a\nb"},
		"a quote in the locator":   {Kind: "k", Locator: `a"b`},
		"a slash in the kind":      {Kind: "a/b", Locator: "l"},
	} {
		if _, err := p.MarshalText(); err == nil {
			t.Errorf("%s: marshalled, want refusal", label)
		}
	}
}
