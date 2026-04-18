
default: build test

# --- build ---

build: build-nix build-rust

build-nix:
    nix build --show-trace

build-rust:
    cargo build

build-rust-release:
    cargo build --release

run-nix *ARGS:
    nix run . -- {{ARGS}}

# --- test ---
#
# Bats tests are routed through the rust `piggy` binary so the full
# rust → bash dispatch path is exercised on every run. `cargo build`
# is a hard prerequisite — `zz-tests_bats/common.bash` aborts with a
# clear error if `target/debug/piggy` is missing.

test: build-rust test-bats test-rust

test-bats: test-bats-piggy test-bats-conformance

test-bats-piggy: build-rust
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/t*.bats

test-bats-conformance: build-rust
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/conformance/*.bats

test-bats-conformance-protocol: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  # Build the conformance binary on demand and resolve its store path
  # without creating a `./result-conformance` symlink in the worktree.
  # The binary is exposed as piggy.tests.conformance (see passthru in
  # flake.nix). nix caches aggressively, so repeat invocations are free.
  out=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)
  CONFORMANCE_BIN="$out/bin/piggy-agent-conformance" \
    BATS_TEST_TIMEOUT=30 bats --allow-unix-sockets --allow-local-binding \
    --tap zz-tests_bats/conformance/piggy_agent_protocol.bats

test-rust:
    cargo test

# --- debug ---

# Run the Go conformance binary against a freshly-started piggy agent and
# print per-test PASS/FAIL/SKIP lines. Useful for eyeballing which subtests
# pass without bats swallowing the output.
[group('debug')]
debug-conformance-run: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    conformance=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)/bin/piggy-agent-conformance
    tmpdir=$(mktemp -d /tmp/piggy-debug-conf.XXXXXX)
    sock="$tmpdir/agent.sock"
    trap 'kill "$agent_pid" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT
    ./target/debug/piggy agent -A -D -a "$sock" &
    agent_pid=$!
    for _ in $(seq 1 20); do [[ -S $sock ]] && break; sleep 0.1; done
    [[ -S $sock ]] || { echo "agent socket never appeared"; exit 1; }
    "$conformance" "$sock" || true

# Inspect which libpcsclite.so.1 each PIV client resolves against.
# Used to diagnose "PCSC error: The Smart card resource manager has shut
# down" when piggy can't reach pcscd but pivy-tool can.
# Try piggy agent -i under PCSCLITE_CSOCK_NAME override to see if it's a
# socket-path disagreement between piggy's libpcsclite and the running daemon.
[group('debug')]
debug-pcsclite-csock-override: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    for sock in /run/pcscd/pcscd.comm /var/run/pcscd/pcscd.comm; do
      [[ -S $sock ]] || { echo "skip: $sock not a socket"; continue; }
      echo "=== PCSCLITE_CSOCK_NAME=$sock ==="
      PCSCLITE_CSOCK_NAME="$sock" ./target/debug/piggy agent -A -i 2>&1 | head -20
      echo
    done

# Trace openat() during piggy agent -i vs pivy-tool list — reveals which
# libpcsclite.so.1 is loaded and which pcscd socket is connected.
[group('debug')]
debug-pcsclite-opens: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    for cmd in "./target/debug/piggy agent -A -i" "pivy-tool list"; do
      echo "=== strace: $cmd ==="
      strace -f -e trace=openat,connect -o /tmp/pcsc-strace.$$ -- $cmd >/dev/null 2>&1 || true
      grep -E 'libpcsclite|pcscd\.comm|pcscd\.pid' /tmp/pcsc-strace.$$ | head -30
      rm -f /tmp/pcsc-strace.$$
      echo
    done

# Probe versions of the running pcscd and the two libpcsclite candidates.
# Confirms the pcscd actually in use and whether Ubuntu's is older than nix's.
[group('debug')]
debug-pcsclite-versions:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== running pcscd ==="
    /usr/sbin/pcscd --version 2>&1 | head -3
    echo
    echo "=== nix pcscd (unused) ==="
    /nix/store/dzbw5iwazj3mmy12xk9491hip59x1m2g-pcsclite-2.3.0/bin/pcscd --version 2>&1 | head -3 || true
    echo
    echo "=== Ubuntu libpcsclite ==="
    for f in /usr/lib/x86_64-linux-gnu/libpcsclite.so.1* /lib/x86_64-linux-gnu/libpcsclite.so.1*; do
      [[ -e $f ]] || continue
      echo "  $f"
      [[ -L $f ]] && echo "    -> $(readlink -f "$f")"
    done
    echo
    echo "=== nix libpcsclite_real.so.1 ==="
    ls -la /nix/store/fl7ixhxn48nhincydz9b4sflmw84fmcg-pcsclite-2.3.0-lib/lib/libpcsclite_real.so.1

# Verify that the nix-built wrapper (./result/bin/piggy) sets
# LIBPCSCLITE_DELEGATE correctly on this host. Runs with the current
# LIBPCSCLITE_DELEGATE unset, and confirms the agent loads the card key.
# Serves as a regression guard for the makeWrapper --run snippet in
# flake.nix's piggy derivation (issue #6 fix).
[group('debug')]
debug-wrapper-env-sanity: build-nix
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== unset LIBPCSCLITE_DELEGATE, run wrapped piggy agent -A -i ==="
    unset LIBPCSCLITE_DELEGATE
    ./result/bin/piggy agent -A -i 2>&1 | head -5

# Point LIBPCSCLITE_DELEGATE at a nonexistent file to confirm whether the
# nix shim falls back to libpcsclite_real.so.1 or errors out. Result
# determines whether the #6 fix strictly needs [[ -f ]] guards or whether
# they are belt-and-suspenders.
[group('debug')]
debug-pcsclite-missing-delegate: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    LIBPCSCLITE_DELEGATE=/nonexistent/libpcsclite.so.1 \
      ./target/debug/piggy agent -A -i 2>&1 | head -10
    echo "exit: $?"

# Exercise the nix libpcsclite shim's LIBPCSCLITE_DELEGATE env-var escape
# hatch. If setting it to the Ubuntu system libpcsclite makes piggy talk
# to the card, we've confirmed the shim/real-lib protocol mismatch theory
# for issue #6 and have a clean workaround.
[group('debug')]
debug-pcsclite-delegate: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    for candidate in \
      /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \
      /lib/x86_64-linux-gnu/libpcsclite.so.1 \
      /usr/lib/libpcsclite.so.1; do
      [[ -f $candidate ]] || continue
      echo "=== LIBPCSCLITE_DELEGATE=$candidate ==="
      LIBPCSCLITE_DELEGATE="$candidate" ./target/debug/piggy agent -A -i 2>&1 | head -10
      echo
    done

# Inspect what the nix pcsclite shim does - strings and runtime linkage.
# Purpose: confirm or refute the polkit-wrapper theory for issue #6.
[group('debug')]
debug-pcsclite-shim-inspect:
    #!/usr/bin/env bash
    set -uo pipefail
    shim_dir=$(dirname "$(ldd ./target/debug/piggy | awk '/libpcsclite.so.1/{print $3}')")
    echo "=== shim dir: $shim_dir ==="
    for lib in libpcsclite.so.1 libpcsclite_real.so.1; do
      path="$shim_dir/$lib"
      [[ -f $path ]] || continue
      echo
      echo "--- $lib ($(stat -c%s "$path") bytes) ---"
      echo "-- ldd --"
      ldd "$path" 2>/dev/null
      echo "-- dynamic symbols (top 20) --"
      nm -D --defined-only "$path" 2>/dev/null | grep -v ' [a-z] ' | head -20 || true
      echo "-- interesting strings --"
      strings "$path" 2>/dev/null | grep -iE '(polkit|dbus|authoriz|pkcheck|getCapabilities|IsSystemEnabled|LoadModule|getenv|environ|PCSC|SCARD|pcscd|driver)' | grep -v '^%' | sort -u | head -40 || true
    done

[group('debug')]
debug-pcsclite-linkage:
    #!/usr/bin/env bash
    set -uo pipefail
    for bin in ./target/debug/piggy "$(command -v pivy-tool)" "$(command -v pcscd)"; do
      [[ -x $bin ]] || continue
      echo "=== $bin ==="
      echo "-- ldd pcsc deps --"
      ldd "$bin" 2>/dev/null | grep -i pcsc || echo "  (none direct)"
      echo "-- strings for pcscd socket path --"
      strings "$bin" 2>/dev/null | grep -E 'pcscd\.(comm|pid)|libpcsclite' | sort -u || true
      echo
    done

# Like debug-conformance-run, but with --hardware. Prompts for the card PIN
# via `ssh-add -X` so the sign test can actually execute against the card.
#
# LIBPCSCLITE_DELEGATE: works around the pcsc-lite 2.0.3 (Ubuntu system
# daemon) vs 2.3.0 (nix client lib) protocol mismatch described in #6. The
# nix libpcsclite shim reads this env var and dlopens the specified path in
# place of the bundled libpcsclite_real.so.1. Forcing Ubuntu's 2.0.3 lib
# lets piggy speak the same protocol as the running daemon.
[group('debug')]
debug-conformance-run-hw: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    export LIBPCSCLITE_DELEGATE=/usr/lib/x86_64-linux-gnu/libpcsclite.so.1
    [[ -f $LIBPCSCLITE_DELEGATE ]] || { echo "system libpcsclite not found at $LIBPCSCLITE_DELEGATE (#6 workaround)"; exit 1; }
    conformance=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)/bin/piggy-agent-conformance
    tmpdir=$(mktemp -d /tmp/piggy-debug-conf.XXXXXX)
    sock="$tmpdir/agent.sock"
    trap 'kill "$agent_pid" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT
    ./target/debug/piggy agent -A -D -a "$sock" &
    agent_pid=$!
    for _ in $(seq 1 20); do [[ -S $sock ]] && break; sleep 0.1; done
    [[ -S $sock ]] || { echo "agent socket never appeared"; exit 1; }
    echo "Unlocking agent via ssh-add -X (enter card PIN when prompted):"
    SSH_AUTH_SOCK="$sock" ssh-add -X
    "$conformance" --hardware "$sock" || true

# --- format / lint ---

codemod-fmt: codemod-fmt-nix codemod-fmt-shell codemod-fmt-rust

codemod-fmt-nix:
    nix run ./devenvs/nix#fmt -- flake.nix

codemod-fmt-shell:
    nix develop --command shfmt -s -i=2 -w src/

codemod-fmt-rust:
    cargo fmt

lint-rust:
    cargo clippy --workspace --all-targets -- -D warnings

# --- update / clean ---

update: update-nix

update-nix:
    nix flake update

clean: clean-build clean-rust

clean-build:
    rm -rf result

clean-rust:
    cargo clean
