piggy-markl(7)

# NAME

piggy-markl - the markl-id Go module, its grammar export, and its gates

# DESCRIPTION

_go/_ (module _code.linenisgreat.com/piggy/go_) is piggy's canonical
markl-id library: the purpose/format registry and the Id codec that RFC
0011 (_docs/rfcs/0011-markl-id-format.md_) specifies. It inverted the
historic relationship in which piggy's Rust crate was a port of madder's
registry; madder now consumes this module as an external dependency
(the _dewey → piggy → madder_ layering; design in
_docs/plans/2026-06-20-markl-id-ownership-inversion.md_, umbrella
piggy#183).

# TERMINOLOGY

*markl-id*
	The identifier type, _[purpose@]format-data_ (RFC 0011).

*piggy-ids file*
	A store's recipients file: one markl-id per line per RFC 0003
	(*piggy-ids*(5)), including the non-encryption 9A SSH-auth line type.

*piggy-ids crate/binary*
	Named after the file it manages, not the ID type. The _markl_ name is
	permanent (the rename was closed won't-do, piggy#184).

# LAYOUT

dagnabit layers _internal/<layer>/<pkg>_, each exported through a
_pkgs/<pkg>_ facade:

_internal/0/domain_interfaces_
	The markl-id interfaces.

_internal/alfa/blech32_
	The split-HRP blech32 codec.

_internal/bravo/markl_
	The pure framework: the Id codec, the registry _mechanism_
	(RegisterFormat / SwapFormat / GetFormatOrError), type and vocabulary
	constants, error sentinels, and the purpose-slot quoting codec
	(bare/quoted spelling per RFC 0011 §2.1). Installs no concrete format
	except the hash family. Home of _marklid.peg_, the normative grammar,
	which carries a sync obligation to RFC 0011 §2, §2.1, §2.3 and §3.

_internal/charlie/markl_registrations_
	piggy's native registrations (crypto, the four erroring stubs,
	piggy's purposes) and the RFC 0002 vector generator/replay. Opt-in:
	blank-import it to fire _init()_.

_internal/delta/agent_, _delta/age_, _delta/pigpen_
	The heavy layers, facades _pkgs/agent_, _pkgs/age_, _pkgs/pigpen_:
	ssh/pivy signer discovery (swaps real impls over the ssh/ecdh stubs;
	pulls x/crypto/ssh and dewey/pivy), age x25519 encryption, and the
	RFC 0008 pigpen document + recipient-set codec. They import the
	internal layers directly and carry _//go:generate dagnabit export_;
	external consumers import only the facades.

	_pkgs/pigpen_ is what a consumer sealing to a recipient set uses:
	*Seal* / *Document.Open*, *ParseRecipients* and
	*Document.EncryptionRecipients* (either _piggy-ids_ form, encryption
	recipients only), *CanonicalRecipientSet* / *SameRecipientSet* (the
	bytes to hash to notice a changed set), and *ParsePointer*. It imports
	no _os/exec_ and stays wasm-buildable. _pkgs/agent_ adds
	*AgentECDHOracle*, which opens a sealed document through an agent's
	_ecdh@joyent.com_ extension, and *ResolveAuthSock*
	(_PIGGY_AUTH_SOCK_, then _SSH_AUTH_SOCK_, then the legacy
	_PIVY_AUTH_SOCK_).

_internal/echo/pigpen_resolve_
	Facade _pkgs/pigpen_resolve_: RFC 0010 pointer resolution. *Resolve*
	runs _pigpen-resolver-<kind> resolve <locator>_ from PATH under the
	caller's context; *LoadRecipients* reads any of the three _piggy-ids_
	forms. It does not cache. Kept out of _delta/pigpen_ because it runs a
	subprocess.

_cmd/piggy-agent-conformance_, _cmd/piggy-test-sshd_
	The two Go test binaries the bats lanes need: the SSH-agent
	wire-protocol conformance tester and a test-only SSH server. Plain
	_package main_, not registry consumers.

# PRODUCER AND CONSUMERS

_go/gomod.nix_ calls igloo's *mkGoPkgs* scoped to _go/_ (name
_piggy-go_, bridging only dewey via _passthru.goFlakeInputs_); the flake
exposes _packages.<system>.{go-pkgs, go-pkgs-test}_. Downstreams
(madder, dodder, cutting-garden) bridge _code.linenisgreat.com/piggy/go_
to _go-pkgs_ with no subPath: the producer tree root carries _go.mod_.
_go/gomod2nix.toml_ pins the module's externals for consumers
(regenerate with *just update-gomod2nix*).

# GATES

*just build-go* and *just test-go* (compile, _go test -count=1 -tags test_)
are in the *build* and *test* aggregates. _-count=1_ is deliberate: the
go test cache tracks only files opened under the module root, and it
answered "ok (cached)" after a vector file under _docs/rfcs/_ changed.
For the same reason the tests read their vector files through
_testdata/_ symlinks that point at _docs/rfcs/_; a new test that reads a
file outside _go/_ must do the same. The two _cmd/_ binaries build with
*buildGoApplication* self-consuming _go-pkgs-test_; the conformance
binary's check phase runs _go vet -tags test ./..._ over the whole
module, so a source-filter regression or a stale _gomod2nix.toml_ fails
the gate. The library itself has no *buildGoModule* gate: facade drift
is what guards it, repaired at commit time by the *conformist-pre-commit*
hook's dewey-facade-export lane and checked at the gate by *just
lint-worktree*. Go is not covered by *nix fmt*; *just codemod-fmt-go*
formats the hand-written sources and the facades are formatted by the
export lane.

*Grammar gates.* *just validate-grammar* checks _marklid.peg_ is
well-formed under langlang; *just test-grammar-vectors* runs three tests
— the RFC 0011 conformance fixture (whole markl-ids), the §7.3 identifier
corpus (_docs/rfcs/0011-identifier-vectors.txt_: purpose slots with
parse / reject / parse-invalid verdicts, run unchanged by downstream
grammars, any divergence recorded in §7.4), and the @import contract.
The recipe's _-run_ alternation must be extended when a fourth test is
added, or it silently never runs.

*Pigpen vectors.* _docs/rfcs/0008-pigpen-vectors.txt_ is the normative
pigpen-v1 vector file (RFC 0008 §10). *just test-go* replays it in Go and
*just test-pigpen* replays the same file in Rust, including byte-exact
re-sealing from each record's file key, payload nonce and ephemeral
scalars, so the two implementations cannot drift from it or from each
other. *just codemod-pigpen-vectors* regenerates it from the fixed public
test secrets in _vectors_generate_test.go_; run it only for an intended
reader or writer change, which RFC 0008 §3 makes a _pigpen-v2_ matter
once it alters what conforming implementations emit or accept.

# GRAMMAR EXPORT SURFACE

piggy is the root of the ecosystem's langlang @import chain (piggy →
trellis → hyphence; papi consumes validators). The flake exports
_.#marklid-grammar_ (the peg) and _.#markl-identifier-vectors_ (the §7.3
corpus) as store paths so downstreams stage rather than vendor. The
peg's named rules _String_, _Char_, _FormatData_, _Format_, _Data_,
_PurposeBare_, _PurposeChar_ and _DataChar_ are a frozen contract:
renaming any of them fails _TestGrammarImportSurface_ on purpose,
meaning "breaking change for trellis/hyphence/papi", not "update the
test". _String_ and _Char_ are owned here (trellis imports them).
_DataChar_ is the blech32 alphabet exported bare so a consumer can
compose a length-agnostic digest (_Format '-' DataChar+_) under its own
length policy (RFC 0011 §4.1); piggy deliberately exports no composed
digest shape, because a frozen export with no in-repo consumer has
nothing keeping it honest. Producer conformance pattern: RFC 0011 §7.5.

Recipes: *build-go*, *test-go*, *update-go*, *update-gomod2nix*,
*codemod-fmt-go*, *codemod-rfc0002-fixture*, *codemod-pigpen-vectors*,
*validate-grammar*, *test-grammar-vectors*.

# SEE ALSO

*piggy*(1), *piggy-ids*(5), *markl-id*(7), *piggy-ci*(7)
