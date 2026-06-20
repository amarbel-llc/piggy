// Package agent is the ssh/pivy signer-discovery layer of piggy's markl
// module (piggy#183 / the #8 agent port). It is the heavy sub-package:
// importing it pulls golang.org/x/crypto/ssh + dewey/pivy, which the
// dep-light markl core (go/markl) deliberately excludes. Consumers that
// only need the registry/codec import go/markl/pkgs/markl (+
// .../pkgs/markl_registrations for the vocabulary); only consumers that
// sign or decrypt through an agent import this package.
//
// It swaps real, agent-backed impls over the erroring stubs the core's
// markl_registrations installs, via markl.SwapFormat:
//
//   - ecdsa_p256_ssh  -> RegisterEcdsaP256SSHFormat(signer): the consumer
//     first connects a signer (ConnectEcdsaP256AgentSigner) and hands it in.
//   - ed25519_ssh     -> RegisterSSHEd25519Format(signer): ditto, via
//     ConnectSSHAgentSigner.
//   - pivy_ecdh_p256  -> RegisterPivyEcdhP256Format(): no signer (the real
//     GetIOWrapper resolves the agent socket lazily), so it is fired at
//     init() for parity with madder's always-on pivy recipient.
//
// The age_x25519_sec stub is swapped by the sibling go/markl/age package
// (the #10 age port), not here.
//
// This package was lifted from madder's go/internal/bravo/markl
// signer-discovery layer (the dewey/pivy + x/crypto/ssh halves) per the
// dependency-layering direction in
// docs/plans/2026-06-20-markl-id-ownership-inversion.md. The Register*
// funcs were adapted from writing the core's package-private formats map
// directly to calling the exported markl.SwapFormat seam.
package agent

// Blank-import the native registrations so the stubs this package swaps
// over are present in the registry before our init() runs (Go runs an
// imported package's init() before the importer's). Without it
// SwapFormat would fail with "no format registered to swap".
import (
	_ "github.com/amarbel-llc/piggy/go/markl/pkgs/markl_registrations"
)
