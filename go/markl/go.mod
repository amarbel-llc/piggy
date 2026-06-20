module github.com/amarbel-llc/piggy/go/markl

go 1.26

// dewey is imported exactly as madder does it (a plain tagged require,
// no replace; the public amarbel-llc/purse-first repo tags the
// libs/dewey sub-path module). blech32 uses dewey/pkgs/{unicorn,errors};
// the tests use dewey/pkgs/test_ui (behind //go:build test, run via
// `just test-go-markl` = `go test -tags test`, hence the go-cmp indirect).
// The markl core (ported under #183) adds more dewey/pkgs. piggy sits
// above dewey in the dewey -> piggy -> madder layering, so the dep is by
// design.
require github.com/amarbel-llc/purse-first/libs/dewey v0.3.2

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
)
