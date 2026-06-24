piggy-ci(7)

# NAME

piggy-ci - continuous integration workflow conventions for piggy

# DESCRIPTION

This page documents the GitHub Actions CI workflow for the piggy project:
its trigger policy, matrix strategy, job structure, and platform-specific
steps. It is intended as a reference for contributors and maintainers.

# WORKFLOW

The single workflow file lives at _.github/workflows/nix.yml_.

The workflow triggers on every *push* to any branch.

Concurrency is grouped by workflow name and git ref:

```
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

This means a new push to the same branch cancels any in-flight run for that
branch. Pushes to different branches run independently.

# MATRIX

The *build-nix-package* job runs on a two-entry matrix:

[[ *Runner*
:[ *Nix system*
|  ubuntu-22.04
:  x86_64-linux
|  macos-15
:  aarch64-darwin

*fail-fast* is set to *false*: a failure on one platform does not cancel the
sibling job on the other platform. This ensures a Darwin regression does not
mask a Linux failure (and vice versa).

# JOBS

*flakehub-publish*
	Publishes the flake to FlakeHub. Runs only on the default branch (master).
	Uses _DeterminateSystems/flakehub-push_ with rolling visibility.

*build-nix-package*
	The main build-and-test job. Runs only on the default branch. Steps:

	. *nix build* — build the piggy package
	. *just test* — full end-to-end suite: cargo build, bats tests (piggy
	  bash tests routed through the rust dispatcher), and cargo test
	. *just verify-fib* — smoke-test the legacy fib virtual PIV card stack,
	  retained as a fibby differential oracle (Linux only)
	. *just test-bats-conformance-interop-fibby* — interop tests between
	  piggy box and pivy-box against the fibby virtual card (Linux only)

# LINUX-ONLY STEPS

The fib (fake-it-backend) virtual PIV card stack depends on *pcscd*, *vpcd*,
and *jCardSim*, which are only available on the Linux runner. Two steps are
gated on _matrix.system == 'x86_64-linux'_:

*just verify-fib*
	Starts the virtual PIV card stack (pcscd + vpcd + jCardSim with
	PivApplet), runs basic card operations, and tears down.

*just test-bats-conformance-interop-fibby*
	Runs BATS interop tests that encrypt with piggy box and decrypt with
	pivy-box (and vice versa) against the fibby virtual card. (Pure-Rust;
	gated on Linux only because the PCSCLITE_CSOCK_NAME redirect is a no-op
	on macOS's PCSC.framework.)

These steps are skipped on the Darwin runner: fib has no macOS support, and
the fibby lanes' socket redirect is a no-op there.

# SEE ALSO

*piggy*(1), *piggy-agent*(1), *piggy-piv-slots*(7)
