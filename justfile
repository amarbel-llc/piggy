
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

check-box:
    cargo check -p piggy-box

check-piggy:
    cargo check -p piggy

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
[group('debug')]
debug-conformance-run-hw: build-rust
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

# --- fib: virtual PIV smart card ---
#
# `fib` is a software PIV card built from PivApplet + jCardSim + vsmartcard-vpcd.
# Packaged via nix/virtual-piv.nix; see docs/virtual-piv.md for architecture
# and troubleshooting.
#
# `fib-up` starts a private pcscd and the applet; `fib-down` tears them down.
# Callers must `eval .fib/env` after `fib-up` to redirect PC/SC clients at
# the private socket (via PCSCLITE_CSOCK_NAME). `fib-shell` is the
# interactive convenience wrapper — opens a subshell with the env set and
# cleans up on exit.

# Start a private pcscd + PivApplet pair. After this returns, run
# `eval $(cat .fib/env)` in your shell; then `pivy-tool list` etc. will
# see "Virtual PCD piggy fib" as the reader.
[group('test')]
fib-up:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .fib
    # Short-circuit if already running.
    if [[ -f .fib/pcscd.pid ]] && kill -0 "$(cat .fib/pcscd.pid)" 2>/dev/null; then
      echo "fib-up: already running (pid $(cat .fib/pcscd.pid)). eval \$(cat .fib/env)" >&2
      exit 0
    fi
    reader_conf=$(nix build --no-link --print-out-paths .#fib-reader-conf)
    pcscd_bin=$(nix build --no-link --print-out-paths .#fib-pcscd^out)/bin/pcscd
    # pcscd hardcodes its socket path at compile time via --enable-ipcdir.
    # Our fib-pcscd was built with -Dipcdir=/tmp/piggy-fib-ipc, so that's
    # where the socket lives. PCSCLITE_CSOCK_NAME only redirects CLIENTS,
    # not the server. We export that env var below so clients point here.
    sock="/tmp/piggy-fib-ipc/pcscd.comm"
    mkdir -p /tmp/piggy-fib-ipc
    # Clean stale state: the singleton check reads pcscd.pid and tries
    # kill(pid, 0); a stale pid from a dead process yields a confusing
    # error. Removing it (and the socket) bypasses that.
    rm -f /tmp/piggy-fib-ipc/pcscd.pid "$sock"
    # Private pcscd loading only vpcd.
    "$pcscd_bin" \
      --foreground \
      --config "$reader_conf" \
      --disable-polkit \
      >.fib/pcscd.log 2>&1 &
    pcscd_pid=$!
    echo "$pcscd_pid" >.fib/pcscd.pid
    # Wait for the socket.
    for _ in $(seq 1 30); do [[ -S $sock ]] && break; sleep 0.1; done
    if [[ ! -S $sock ]]; then
      echo "fib-up: pcscd socket never appeared — see .fib/pcscd.log" >&2
      kill "$pcscd_pid" 2>/dev/null || true
      exit 1
    fi
    # Start the applet — it connects to vpcd on localhost:35963.
    nix run .#fib >.fib/fib.log 2>&1 &
    fib_pid=$!
    echo "$fib_pid" >.fib/fib.pid
    # Export env for the caller.
    cat >.fib/env <<EOF
    export PCSCLITE_CSOCK_NAME="$sock"
    # fib pcscd pid: $pcscd_pid
    # fib jcardsim pid: $fib_pid
    EOF
    echo "fib: up — eval \$(cat .fib/env) to connect"

# Tear down the private pcscd + fib pair.
[group('test')]
fib-down:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ -f .fib/fib.pid ]]; then
      kill "$(cat .fib/fib.pid)" 2>/dev/null || true
    fi
    if [[ -f .fib/pcscd.pid ]]; then
      kill "$(cat .fib/pcscd.pid)" 2>/dev/null || true
    fi
    rm -rf .fib
    echo "fib: down"

# Open a subshell with fib up and the env preloaded; tears down on exit.
[group('test')]
fib-shell:
    #!/usr/bin/env bash
    set -euo pipefail
    just fib-up
    trap 'just fib-down' EXIT
    export PCSCLITE_CSOCK_NAME="/tmp/piggy-fib-ipc/pcscd.comm"
    PS1="(fib) $PS1" exec "$SHELL"

# --- update / clean ---

update: update-nix

update-nix:
    nix flake update

clean: clean-build clean-rust

clean-build:
    rm -rf result

clean-rust:
    cargo clean
