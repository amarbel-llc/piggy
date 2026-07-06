module github.com/amarbel-llc/piggy/go

go 1.26

// dewey is imported exactly as madder does it (a plain tagged require,
// no replace; the public amarbel-llc/purse-first repo tags the
// libs/dewey sub-path module). blech32 uses dewey/pkgs/{unicorn,errors};
// the tests use dewey/pkgs/test_ui (behind //go:build test, run via
// `just test-go` = `go test -tags test`, hence the go-cmp indirect).
// The markl core (ported under #183) adds more dewey/pkgs. piggy sits
// above dewey in the dewey -> piggy -> madder layering, so the dep is by
// design. dewey is bridged via flake-input-go_mod (go/gomod.nix
// goFlakeInputs), so it MUST live in a require BLOCK: igloo's parseGoMod
// mishandles a standalone `require x v` line (the form `go mod tidy`
// emits when a comment is attached to a single require), yielding
// "expected a set but found a string" at buildGoApplication eval.
require (
	github.com/amarbel-llc/purse-first/libs/dewey v0.3.2
	golang.org/x/crypto v0.50.0
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f
)

require (
	filippo.io/age v1.3.1 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/term v0.42.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
)
