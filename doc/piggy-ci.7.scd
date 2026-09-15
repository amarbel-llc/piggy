piggy-ci(7)

# NAME

piggy-ci - continuous integration conventions for piggy

# DESCRIPTION

piggy has no hosted CI service. The integration gate is the spinclass
pre-merge hook: *merge-this-session* runs *just* (the repo's *default*
recipe, *lint build test*) in a detached build worktree on the shared Linux
build host, and only a green run fast-forwards the default branch. The
same *just* is what a contributor runs locally; there is no second
pipeline to keep in step with it. See *spinclass-merge-this-session*(1) and
the repo's *sweatfile* (*pre-merge = "just"*).

# THE GATE

*just lint*
	Formatting via conformist (*lint-fmt*), clippy with warnings as
	errors (*lint-rust*), and the impure eng-convention checks plus the
	go/ facade drift check (*lint-worktree*).

*just build*
	*build-nix* (the default piggy package, fibby, the Go test binaries),
	*build-rust* (the workspace), *build-go* (the go/ module) and
	*build-pigpen* (the standalone piggy-pigpen crate).

*just test*
	The grammar gates (*validate-grammar*, *test-grammar-vectors*), the
	sandboxed bats lane (*test-bats-default*, *nix build .#bats-default*),
	the conformance bats glob (*test-bats-conformance*), *cargo test*
	(*test-rust*), the go/ tests (*test-go*), the standalone piggy-pigpen
	crate (*test-pigpen*), and, on Linux only, the fibby-backed conformance
	lanes (*\_test-conformance-linux-only*) and the NixOS VM lanes
	(*\_test-vm-linux-only*: *test-vm-luks*, *test-vm-zfs*,
	*test-vm-agent*).

# LINUX-ONLY LANES

The fibby conformance lanes redirect PC/SC clients at a virtual card through
*PCSCLITE_CSOCK_NAME*, which macOS's PCSC.framework ignores, and the NixOS
VM lanes evaluate to nothing on darwin (*pkgs.mkVmChecks*). Both aggregates
are declared as a *[linux]* / *[macos]* recipe pair so *just test* stays a
single entry point on either platform; on macOS the Linux-only halves are
empty.

The VM lanes boot each guest under TCG (the build host has no /dev/kvm) and
take two to three minutes each once the guest closure is cached; a
*[clown-job]* wake or the recipe's own exit is the signal, never a poll.

# OUTSIDE THE GATE

*just test-optional*
	Not run by the gate: *test-bats-file* and *test-bats-piggy-local* (the
	fast, unsandboxed local-iteration paths), *test-bats-conformance-protocol*
	(the SSH-agent wire-protocol bats), *test-bats-conformance-pivy-agent-hardware*
	(needs a plugged-in card), and *test-nix-hm-module* (the home-manager
	module evaluation smoke test).

*just test-vm-coverage*
	The three VM lanes re-run on an instrumented piggy, merged into an
	llvm-cov report. Roughly thirteen minutes serialized; kept out of the
	gate until that cost is accepted.

*just verify-fib*
	Smoke-test of the legacy fib (jCardSim) virtual PIV card, retained as a
	fibby differential oracle. Linux only.

*just lint-justfile-profile*
	conformist's profile-delivered justfile linters (recipe verbs, orphaned
	doc summaries) over *conformist.profile* at the repo root, a verbatim
	copy of conformist's own. Linux only; outside the *lint* aggregate
	while the profile mechanism is experimental (conformist RFC 0005).

*darwin*
	No darwin build or test runs before a merge: the gate is the Linux
	build host. The macOS-specific code (clipboard, ramdisk tmpdir,
	askpass, the darwin devShell half) is covered only when a contributor
	runs *just* on a Mac.

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *piggy-piv-slots*(7),
*spinclass-merge-this-session*(1), *eng-design_patterns-justfile*(7)
