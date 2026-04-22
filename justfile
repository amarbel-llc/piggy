
default: build test

# --- build ---

build: build-nix build-rust

build-nix:
    nix build --show-trace

build-rust *ARGS:
    cargo build {{ARGS}}

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

test-bats-conformance-interop: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'just fib-down' EXIT
  just fib-up
  eval "$(cat .fib/env)"
  # Generate a key on the fib card's 9D slot (Key Management / ECDH)
  # so ebox encrypt/decrypt has something to work with.
  pivy-tool -P 123456 -K default generate 9d
  # Discover the card's GUID for template creation.
  guid=$(pivy-tool list 2>&1 | grep -oE '[0-9a-f]{32}' | head -1)
  # Create a template via the Rust CLI (tests will also create their own).
  export HOME="$PWD/.fib"
  "$PWD/target/debug/piggy" box tpl create interop primary local-guid "$guid"
  tpl_file="$HOME/.pivy/tpl/interop"
  INTEROP_TPL="$tpl_file" INTEROP_GUID="$guid" \
    PCSCLITE_CSOCK_NAME="$PCSCLITE_CSOCK_NAME" \
    BATS_TEST_TIMEOUT=30 bats --tap \
    zz-tests_bats/conformance/piggy_box_interop.bats

test-bats-file *FILES: build-rust
    BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap {{FILES}}

test-rust *ARGS:
    cargo test {{ARGS}}

check-rust *ARGS:
    cargo check {{ARGS}}

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
    # Readiness probe: wait for jCardSim/vpcd to come up and the PIV
    # applet to respond to SELECT. Uses SCardGetStatusChange (event-based,
    # not polling) + SCardConnect + PIV AID SELECT. The --activate flag
    # sends the jCardSim INSTALL APDU first. Replaces the former
    # opensc-tool + pivy-tool polling loops (see #20, #22).
    export PCSCLITE_CSOCK_NAME="$sock"
    reader="Virtual PCD piggy fib 00 00"
    fib_wait_bin="./target/debug/fib-wait-ready"
    if [[ ! -x "$fib_wait_bin" ]]; then
      cargo build -p fib-wait-ready --quiet
    fi
    activate_apdu='80b80000120ba000000308000010000100050000020F0F7f'
    if ! "$fib_wait_bin" \
        --reader "$reader" \
        --timeout 30 \
        --activate "$activate_apdu"; then
      echo "fib-up: fib-wait-ready failed — card never became ready" >&2
      kill "$fib_pid" "$pcscd_pid" 2>/dev/null || true
      exit 1
    fi
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

# Smoke test: bring up fib, verify pivy-tool sees the virtual card, tear down.
[group('test')]
fib-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'just fib-down' EXIT
    just fib-up
    eval "$(cat .fib/env)"

    # Minimal diagnostics — see #20 for full investigation history.
    echo "--- fib diagnostics ---"
    echo "PCSCLITE_CSOCK_NAME=${PCSCLITE_CSOCK_NAME:-<unset>}"
    echo "socket exists: $(test -S "${PCSCLITE_CSOCK_NAME:-}" && echo yes || echo no)"
    echo "pcscd alive: $(kill -0 "$(cat .fib/pcscd.pid 2>/dev/null)" 2>/dev/null && echo yes || echo no)"
    echo "fib alive: $(kill -0 "$(cat .fib/fib.pid 2>/dev/null)" 2>/dev/null && echo yes || echo no)"
    opensc-tool -l 2>&1 || echo "(opensc-tool -l failed)"

    echo "--- pivy-tool list (with retries) ---"
    found=false
    for attempt in $(seq 1 10); do
      output=$(pivy-tool list 2>&1) || true
      echo "attempt $attempt: $output"
      if echo "$output" | grep -q "Virtual PCD piggy fib"; then
        found=true
        break
      fi
      sleep 0.5
    done
    if [[ "$found" != true ]]; then
      echo "fib-smoke: FAIL — virtual card not visible after 10 attempts" >&2
      echo
      echo "--- dumping debug-fib-pivy-trace on failure (see #20) ---" >&2
      just debug-fib-pivy-trace >&2 || true
      exit 1
    fi
    echo "fib-smoke: PASS"

# Trace pivy-tool vs opensc-tool against a running fib stack.
# Fib must already be up (just fib-up). Used to investigate #20
# (pivy-tool list empty despite opensc-tool seeing the virtual card).
[group('debug')]
debug-fib-pivy-trace:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ ! -f .fib/env ]]; then
      echo "ERROR: .fib/env not found - run 'just fib-up' first" >&2
      exit 1
    fi
    eval "$(cat .fib/env)"

    echo "=== env ==="
    echo "PCSCLITE_CSOCK_NAME=${PCSCLITE_CSOCK_NAME:-<unset>}"
    echo "socket exists: $(test -S "${PCSCLITE_CSOCK_NAME:-}" && echo yes || echo no)"

    echo
    echo "=== opensc-tool -l (list only, no SCardConnect) ==="
    opensc-tool -l 2>&1 || echo "(opensc-tool -l failed: exit $?)"

    echo
    echo "=== opensc-tool PIV AID SELECT (forces SCardConnect) ==="
    opensc-tool --reader 0 --send-apdu 00A4040009A00000030800001000 2>&1 \
      || echo "(opensc-tool send-apdu failed: exit $?)"

    echo
    echo "=== pivy-tool -d list (bunyan TRACE output) ==="
    pivy-tool -d list 2>&1 || echo "(pivy-tool -d list failed: exit $?)"

    echo
    echo "=== pivy-tool -dd list (full APDU debug) ==="
    pivy-tool -dd list 2>&1 || echo "(pivy-tool -dd list failed: exit $?)"

# Capture the jcardsim Maven dependency closure into nix/jcardsim-m2/.
# Run once whenever the jcardsim flake input is bumped. The vendored .m2
# replaces buildMavenPackage's FOD so the nix build never fetches from
# Maven Central (eliminates hash drift). Maven is pure Java — works on
# any platform regardless of fib/vsmartcard Linux constraints.
[group('debug')]
debug-capture-jcardsim-m2:
    #!/usr/bin/env bash
    set -euo pipefail
    project_root="$PWD"
    tmpdir=$(mktemp -d /tmp/jcardsim-m2-capture.XXXXXX)
    trap 'rm -rf "$tmpdir"' EXIT

    echo "=== Resolving flake input store paths ==="
    archive=$(nix flake archive --json .)
    jcardsim_src=$(echo "$archive" | jq -r '.inputs.jcardsim.path // empty')
    if [[ -z $jcardsim_src ]]; then
      echo "ERROR: Could not resolve jcardsim source path from flake" >&2
      exit 1
    fi
    echo "jcardsim source: $jcardsim_src"

    oracle_sdks=$(echo "$archive" | jq -r '.inputs["oracle-javacard-sdks"].path // empty')
    if [[ -z $oracle_sdks ]]; then
      echo "ERROR: Could not resolve oracle-javacard-sdks source path from flake" >&2
      exit 1
    fi
    echo "oracle-javacard-sdks: $oracle_sdks"

    echo "=== Copying jcardsim source to writable tmpdir ==="
    cp -r "$jcardsim_src"/. "$tmpdir/jcardsim"
    chmod -R u+w "$tmpdir/jcardsim"

    echo "=== Patching pom.xml (same as nix/virtual-piv.nix postPatch) ==="
    sdk_jar="$oracle_sdks/jc305u3_kit/lib/api_classic.jar"
    if [[ ! -f "$sdk_jar" ]]; then
      echo "ERROR: Oracle SDK jar not found at $sdk_jar" >&2
      exit 1
    fi
    cd "$tmpdir/jcardsim"
    # Replace compile scope with system scope + absolute path to SDK jar.
    # Replace ${env.JC_CLASSIC_HOME} with the actual path.
    # Use temp file for BSD/GNU sed portability.
    sed \
      -e "s|<scope>compile</scope>|<scope>system</scope><systemPath>$sdk_jar</systemPath>|g" \
      -e "s|\${env.JC_CLASSIC_HOME}|$oracle_sdks/jc305u3_kit|g" \
      pom.xml > pom.xml.tmp
    mv pom.xml.tmp pom.xml

    echo "=== Running Maven to download dependency closure ==="
    m2repo="$tmpdir/m2-repo"
    mkdir -p "$m2repo"
    # Use nix shell to get Maven + JDK without polluting the devshell
    nix shell nixpkgs#maven nixpkgs#jdk21_headless --command \
      mvn package \
        "-Dmaven.repo.local=$m2repo" \
        -Dmaven.test.skip=true \
        -Dgpg.skip=true \
        -Djava.version=1.8

    echo "=== Stripping ephemeral Maven metadata (matches buildMavenPackage) ==="
    find "$m2repo" -name '*.lastUpdated' -delete
    find "$m2repo" -name 'resolver-status.properties' -delete
    find "$m2repo" -name '_remote.repositories' -delete

    echo "=== Installing to nix/jcardsim-m2/ ==="
    dest="$project_root/nix/jcardsim-m2"
    rm -rf "$dest"
    cp -r "$m2repo" "$dest"

    echo "=== Done. Vendored Maven deps at nix/jcardsim-m2/ ==="
    du -sh "$dest"

# --- explore ---

# Run pivy-tool bats tests against the nix-built pivy (not the devshell's).
# Validates that changes to vendor/pivy/src/ are picked up by the actual
# build artifact. Used to verify #23 (-K default fix).
[group('explore')]
explore-pivy-tool-bats: build-nix
    #!/usr/bin/env bash
    set -euo pipefail
    piggy_out=$(readlink -f ./result)
    # Extract the pivy store path from the piggy wrapper script.
    pivy_bin=$(grep -oP '/nix/store/[a-z0-9]+-pivy-[^/]+/bin' "$piggy_out/bin/piggy" | head -1)
    [[ -d "$pivy_bin" ]] || { echo "could not find pivy bin dir in piggy wrapper"; exit 1; }
    PATH="$pivy_bin:$PATH" \
      BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap \
      zz-tests_bats/conformance/pivy_tool_admin_key.bats

# --- update / clean ---

update: update-nix

update-nix:
    nix flake update

clean: clean-build clean-rust

clean-build:
    rm -rf result

clean-rust:
    cargo clean
