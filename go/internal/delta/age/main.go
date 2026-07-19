// Package age is the age x25519 encryption layer of piggy's markl module
// (piggy#183 / the #10 age port). It is a heavy sub-package parallel to
// go/markl/agent: importing it pulls dewey/age + dewey/bech32 (and their
// filippo.io/age closure), which the dep-light markl core deliberately
// excludes. Consumers that only need the registry/codec import
// go/markl/pkgs/markl; only consumers that encrypt/decrypt to an age
// recipient import this package.
//
// It swaps the real age-backed Generate + GetIOWrapper over the core's
// erroring age_x25519_sec stub via markl.SwapFormat. Like the pivy
// recipient (and unlike the SSH signing formats), the swap needs no
// connected signer, so it is fired at init() — giving importers the
// always-on age secret-key machinery madder's core init provided before
// the dep-light split. The age_x25519_pub format is pure (Size 32) and
// stays registered in the core's markl_registrations.
//
// Lifted from madder's internal/bravo/markl/format_family_agex25519.go
// per docs/plans/2026-06-20-markl-id-ownership-inversion.md.
package age

//go:generate dagnabit export

// Blank-import the native registrations so the age_x25519_sec stub this
// package swaps over is present before our init() runs (Go runs an
// imported package's init() before the importer's). Without it
// SwapFormat would fail with "no format registered to swap".
import (
	_ "code.linenisgreat.com/piggy/go/internal/charlie/markl_registrations"
)
