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
	The go/ module, the nix package set (*build-nix*: the default piggy
	package, fibby, the Go test binaries), and the Rust workspace.

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
	Lanes that need hardware, a tty, or a human: the C pivy-agent hardware
	lane, the wire-protocol conformance bats, the home-manager module
	evaluation smoke test.

*just test-vm-coverage*
	The three VM lanes re-run on an instrumented piggy, merged into an
	llvm-cov report. Roughly thirteen minutes serialized; kept out of the
	gate until that cost is accepted.

*just verify-fib*
	Smoke-test of the legacy fib (jCardSim) virtual PIV card, retained as a
	fibby differential oracle. Linux only.

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *piggy-piv-slots*(7),
*spinclass-merge-this-session*(1), *eng-design_patterns-justfile*(7)
