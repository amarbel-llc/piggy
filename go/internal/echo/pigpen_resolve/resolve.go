package pigpen_resolve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"code.linenisgreat.com/piggy/go/internal/bravo/markl"
	"code.linenisgreat.com/piggy/go/internal/delta/pigpen"
)

// resolverPrefix is RFC 0010 §2's discovery convention: a pointer of kind
// K is resolved by the executable `pigpen-resolver-K` found on PATH.
const resolverPrefix = "pigpen-resolver-"

// Resolve runs `pigpen-resolver-<kind> resolve <locator>` and parses its
// stdout as a recipient-set pigpen document (RFC 0010 §3).
//
// Failure is hard (§5): a missing resolver, a non-zero exit, and output
// that is not a recipient set are all errors, and each names the pointer's
// kind and locator. There is no cache and no stale fallback. The resolver
// runs under ctx; give it a deadline.
//
// The resolved bytes are trusted exactly as far as the resolver binary on
// PATH is (§6): this package verifies no signature and interprets no
// locator.
func Resolve(ctx context.Context, p *pigpen.Pointer) (*pigpen.Document, error) {
	if err := pigpen.ValidatePointerKind(p.Kind); err != nil {
		return nil, err
	}
	binary := resolverPrefix + p.Kind

	fail := func(cause string) error {
		return fmt.Errorf(
			"pigpen: failed to resolve pointer (kind=%q, locator=%q): %s", p.Kind, p.Locator, cause,
		)
	}

	path, err := exec.LookPath(binary)
	if err != nil {
		return nil, fail(fmt.Sprintf("no %s on PATH: %v", binary, err))
	}

	stdout, stderr, err := runResolver(ctx, path, p.Locator)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fail(fmt.Sprintf("%s did not finish: %v", binary, ctxErr))
		}
		detail := strings.TrimSpace(stderr)
		if detail == "" {
			detail = err.Error()
		}
		return nil, fail(fmt.Sprintf("%s: %s", binary, detail))
	}

	doc, err := pigpen.ParseDocument(stdout)
	if err != nil {
		return nil, fail(fmt.Sprintf("%s did not print a pigpen recipient set: %v", binary, err))
	}
	if doc.Sealed() {
		return nil, fail(fmt.Sprintf("%s printed a sealed document, want a recipient set", binary))
	}
	return doc, nil
}

// runResolver execs the resolver, retrying briefly on ETXTBSY: on Linux an
// exec fails that way while any process still holds the file open for
// writing, which a concurrent fork can cause for a just-installed binary
// (piggy#249).
func runResolver(ctx context.Context, path, locator string) (stdout []byte, stderr string, err error) {
	const maxAttempts = 5
	for attempt := 1; ; attempt++ {
		var out, errOut bytes.Buffer
		cmd := exec.CommandContext(ctx, path, "resolve", locator)
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err = cmd.Run()
		if errors.Is(err, syscall.ETXTBSY) && attempt < maxAttempts {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		return out.Bytes(), errOut.String(), err
	}
}

// LoadRecipients returns the encryption recipients a piggy-ids file
// names, whichever of its three forms it takes: RFC 0003 lines, a pigpen
// recipient-set (or sealed) document, or a pointer, which is resolved
// with Resolve.
func LoadRecipients(ctx context.Context, raw []byte) ([]markl.Id, error) {
	if !IsPointer(raw) {
		return pigpen.ParseRecipients(raw)
	}
	pointer, err := pigpen.ParsePointer(raw)
	if err != nil {
		return nil, err
	}
	doc, err := Resolve(ctx, pointer)
	if err != nil {
		return nil, err
	}
	return doc.EncryptionRecipients(), nil
}

// IsPointer reports whether raw is a hyphence document whose type line
// names the pointer face. It does not validate the pointer.
func IsPointer(raw []byte) bool {
	const boundary = "---\n"
	if !bytes.HasPrefix(raw, []byte(boundary)) {
		return false
	}
	// Look only inside the metadata section: a sealed document's body is
	// arbitrary bytes and must not be searched for a type line.
	metadata := raw[len(boundary)-1:] // keep the leading "\n"
	if end := bytes.Index(metadata, []byte("\n"+boundary)); end >= 0 {
		metadata = metadata[:end+1]
	}
	return bytes.Contains(metadata, []byte("\n! pigpen-pointer-v1\n"))
}
