
default: lint build test

# Pre-build gate covering formatting (treefmt) and clippy. Both run on
# the default `just` chain, which is also the pre-merge hook.
lint: lint-fmt lint-rust

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

test: test-bats-default test-bats-conformance test-rust

# Sandboxed bats lane: runs every top-level t*.bats NOT tagged
# `# bats file_tags=hardware` inside the nix build sandbox. See
# ./bats.nix for the lane builder and CLAUDE.md "Architecture" for the
# tag convention. This replaces the previous `test-bats-piggy` recipe
# as the authoritative gate for the core suite; the bare-`bats`
# fallback lives at `test-bats-piggy-local` for fast iteration.
test-bats-default:
    nix build .#bats-default --no-link --print-build-logs

# Local-iteration shortcut: re-runs the same t*.bats files outside the
# nix sandbox against `target/debug/piggy`. Faster than `nix build` on
# small edits; CI / pre-merge should use `test-bats-default` instead.
test-bats-piggy-local: build-rust
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
  # Rebuild vendored pivy first so any changes to vendor/pivy/openssh.patch
  # (e.g. #81's chacha20-poly1305@piggy.amarbel.net cipher entry) take
  # effect — the freshly-built nix output lives at vendor/pivy/result.
  # Use that path explicitly rather than $(command -v pivy-box), which
  # may resolve to a stale direnv-cached binary.
  cd vendor/pivy && nix build && cd -
  real_pivy_box="$PWD/vendor/pivy/result/bin/pivy-box"
  if [[ ! -x "$real_pivy_box" ]]; then
    echo "vendor/pivy/result/bin/pivy-box not executable — nix build failed" >&2
    exit 1
  fi
  # Prepend it to PATH so subprocesses also see the fresh binary
  # (pivy-tool, etc.) consistently.
  export PATH="$PWD/vendor/pivy/result/bin:$PATH"
  just fib-up
  eval "$(cat .fib/env)"
  # Generate a key on the fib card's 9D slot (Key Management / ECDH)
  # so `pivy-box tpl create` and `piggy box tpl create` have a card
  # to read the GUID from. pivy-tool requires -a on `generate`;
  # eccp256 matches what the rust template path exercises today.
  pivy-tool -P 123456 -K default -a eccp256 generate 9d
  # Discover the card's GUID for template creation. pivy-tool prints
  # GUIDs in uppercase, so the grep must be case-insensitive.
  guid=$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
  # Safety net for PIN prompts. See CLAUDE.md "Test harness safety
  # net for PIN prompts" and amarbel-llc/piggy#35. Required by the
  # global policy for any recipe that could reach pivy's
  # `assert_pin()` interactive fallback, even though the remaining
  # template tests don't actually unlock anything.
  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  # Note: the agent provisioning that previously lived here (piggy
  # agent spawn + ssh-add -X unlock + SSH_AUTH_SOCK propagation) was
  # trimmed once #41 deleted the cipher interop tests. The remaining
  # template tests don't unlock anything. If a future test needs an
  # agent again, the recipe shape lives at commit `38df53c` —
  # restore from there rather than re-deriving.
  #
  # --allow-unix-sockets / --allow-local-binding are batman sandbox
  # escapes — without them subprocesses cannot connect to pcscd.comm
  # (a Unix socket) and libpcsclite reports "Smart card resource
  # manager is not running". See CLAUDE.md "Debugging → bats + PCSC".
  # PIGGY_IDS_REAL is set by zz-tests_bats/common.bash; tests under
  # conformance/ that bypass the mock-piggy-ids symlink (notably
  # piggy_box_decrypt_interop.bats) reference it directly.
  INTEROP_GUID="$guid" \
    REAL_PIVY_BOX="$real_pivy_box" \
    PCSCLITE_CSOCK_NAME="$PCSCLITE_CSOCK_NAME" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    BATS_TEST_TIMEOUT=30 bats --allow-unix-sockets --allow-local-binding --tap \
    zz-tests_bats/conformance/piggy_box_interop.bats \
    zz-tests_bats/conformance/piggy_box_decrypt_interop.bats

# Bring up fib, generate a P-256 key in 9D, and run the
# piggy_recipients_add_attached.bats conformance lane against the
# real PCSC stack. Linux-only (fib is Linux-only). Opt-in — not
# part of the default `just test` lane.
[group('test')]
test-bats-conformance-recipients-add-attached: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'just fib-down' EXIT
    just fib-up
    eval "$(cat .fib/env)"
    pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      BATS_TEST_TIMEOUT=30 bats --allow-unix-sockets --allow-local-binding --tap \
      zz-tests_bats/conformance/piggy_recipients_add_attached.bats

# Hardware lane for `piggy pass show-batch`. Seals real eboxes against
# fib's 9D slot and verifies the end-to-end NDJSON event stream
# including the single-PIN guarantee, the wrong-card bail-out, the
# heterogeneous-batch per-ebox failure path, and the SIGINT bail-out
# shape. Linux-only (fib is Linux-only). Opt-in — not part of the
# default `just test` lane. Companion to the sandbox surface that
# runs under `bats-default`; see #122.
[group('test')]
test-bats-conformance-show-batch: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'just fib-down' EXIT
    just fib-up
    eval "$(cat .fib/env)"
    pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
    # Discover the card's GUID for `piggy-ids detect-pubkey --guid` —
    # pivy-tool prints uppercase, so grep case-insensitively. Mirrors
    # the same dance in test-bats-conformance-interop.
    guid=$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    # BATS_TEST_TIMEOUT=60 (vs 30 elsewhere) — the SIGINT test
    # background-spawns piggy with a slow askpass and waits on the
    # first decrypt-ok line, which can take ~5–10s on a cold fib.
    INTEROP_GUID="$guid" \
      PCSCLITE_CSOCK_NAME="$PCSCLITE_CSOCK_NAME" \
      SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      BATS_TEST_TIMEOUT=60 bats --allow-unix-sockets --allow-local-binding --tap \
      zz-tests_bats/conformance/piggy_pass_show_batch_hardware.bats

# Hardware lane for the C pivy-agent built from vendor/pivy/. Runs
# pivy_agent_hardware.bats against the user's plugged-in PIV card.
# Read-only PIN-free operations (REQUEST_IDENTITIES). Verifies the
# piggy#107 (piggy#105 step 3) state-machine plumbing doesn't break
# the simple identity-listing case. Opt-in — not part of the default
# `just test` lane. Requires a real card plugged in.
[group('test')]
test-bats-conformance-pivy-agent-hardware: build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    # Build the C pivy-agent binary (and its wrapper) on demand and
    # resolve its store path without creating a `./result-pivy`
    # symlink in the worktree. The package is exposed as
    # `pivy` (see flake.nix); nix caches aggressively so repeat
    # invocations are free.
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    # PIGGY_TEST_REAL_CARD gates the entire lane (see the bats
    # setup()). PIGGY_TEST_FIB_PIN is DELIBERATELY NOT set — these
    # tests assert no PIN prompt occurs, so the askpass helper must
    # refuse rather than supply a PIN.
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      PIGGY_TEST_REAL_CARD=1 \
      SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap \
      zz-tests_bats/conformance/pivy_agent_hardware.bats

test-bats-file *FILES: build-rust
    BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap {{FILES}}

test-rust *ARGS:
    cargo test {{ARGS}}

# Smoke-test for the `services.piggy-agent` home-manager module (#52).
# Evaluates the module against synthetic configs and verifies the option
# schema, both platform code paths, and every assertion. Reports
# pass/fail per case.
test-nix-hm-module:
  #!/usr/bin/env bash
  set -euo pipefail
  expr='let
    flake = builtins.getFlake (toString ./.);
    pkgs = flake.inputs.nixpkgs.legacyPackages.${builtins.currentSystem};
    test = import ./nix/hm/eval-test.nix {
      inherit pkgs;
      module = flake.homeManagerModules.piggy-agent;
    };
  in test'
  json="$(nix eval --impure --json --expr "$expr")"
  printf '%s\n' "$json" | jq -r '"\(.summary)"'
  if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
    printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
    exit 1
  fi

# End-to-end ECDH round-trip: boot fib, generate a 9D key, spawn
# piggy-agent as a child of the test binary, and verify the agent's
# ecdh@joyent.com extension agrees with a locally-computed shared
# secret. Issue #32 checkpoint 2. Requires fib (just fib-up will be
# called automatically and torn down on exit).
test-rust-agent-ecdh: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'just fib-down' EXIT
  just fib-up
  eval "$(cat .fib/env)"
  # Generate a key on the fib card's 9D slot (Key Management / ECDH).
  # eccp256 matches both the oracle and the PIV card's ECDH codepath.
  pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
  export PIGGY_BIN="$PWD/target/debug/piggy"
  # Direct `cargo test` is fine here — the just recipe is the entry
  # point, not cargo (see CLAUDE.md: "Use just recipes for all cargo
  # ... operations" — the recipe *is* the single source of truth).
  cargo test --test agent_ecdh_integration -- --nocapture

# End-to-end unlock round-trip: boot fib, generate a 9D key, seal a
# random AEAD key to it, push the ebox through the wire format, and
# unlock it via a live piggy-agent (through the EcdhOracle trait).
# Issue #32 checkpoint 3A. Mirrors the shape of test-rust-agent-ecdh.
test-rust-agent-unlock: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'just fib-down' EXIT
  just fib-up
  eval "$(cat .fib/env)"
  # eccp256 matches the curve the Rust ECDH path exercises; 9D is the
  # Key-Management slot used by the EcP256 unlock flow.
  pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
  export PIGGY_BIN="$PWD/target/debug/piggy"
  cargo test --test unlock_ebox_agent_integration -- --nocapture

# End-to-end unlock round-trip via the direct-PCSC card path (no agent).
# Boots fib, generates a 9D key, seals a random AEAD key to it, pushes
# the ebox through the wire format, and unlocks it via CardEcdhOracle.
# Issue #31. SSH_ASKPASS routes to the refusing test askpass; the recipe
# exports PIGGY_TEST_FIB_PIN so the askpass non-interactively supplies
# the fib PIN. Any code path that falls through to a real askpass
# surfaces as a `[piggy-test-askpass]` stderr banner, not a GUI dialog.
test-rust-card-unlock: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'just fib-down' EXIT
  just fib-up
  eval "$(cat .fib/env)"
  pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
  export PIGGY_BIN="$PWD/target/debug/piggy"
  export PIGGY_TEST_FIB_PIN=123456
  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  export SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=""
  cargo test --test unlock_ebox_card_integration -- --nocapture

check-rust *ARGS:
    cargo check {{ARGS}}

check-box:
    cargo check -p piggy-box

check-piggy:
    cargo check -p piggy

# --- debug ---

# PIN-safe side-by-side of Rust-piggy and C-pivy stream encrypt byte layouts
# against the same fib template. Used to diagnose #29 wire-format issues.
# Only runs the encrypt paths — decrypt is intentionally omitted because it
# would prompt for a PIN on /dev/tty and consume PIV retries on fib's slot.
[group('debug')]
debug-interop-stream-bytes: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'just fib-down' EXIT
  just fib-up
  eval "$(cat .fib/env)"
  pivy-tool -P 123456 -K default -a eccp256 generate 9d >/dev/null
  guid=$(pivy-tool list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
  export HOME="$PWD/.fib"
  "$PWD/target/debug/piggy" box tpl create interop primary local-guid "$guid"
  tpl_file="$HOME/.pivy/tpl/interop"

  echo "--- rust encrypt first 80 bytes ---"
  printf "hello from rust" | "$PWD/target/debug/piggy" box stream encrypt "$tpl_file" > /tmp/stream-rust.ebox
  head -c 80 /tmp/stream-rust.ebox | xxd
  echo "total: $(wc -c < /tmp/stream-rust.ebox) bytes"
  echo
  echo "--- C encrypt first 80 bytes ---"
  printf "hello from c" | pivy-box stream encrypt "$tpl_file" > /tmp/stream-c.ebox
  head -c 80 /tmp/stream-c.ebox | xxd
  echo "total: $(wc -c < /tmp/stream-c.ebox) bytes"

# Generic driver for exploratory bats files. Each file brings up whatever
# infrastructure it needs in setup_file() / teardown_file(). We pass
# --no-sandbox because explore tests often need to talk to pcscd (Unix
# sockets), bind local ports, shell out to `just` to bring up fib (which
# writes .fib/ into CWD and /run/user/$UID), etc. The narrow-escape flags
# (--allow-unix-sockets, --allow-local-binding) cover sockets and ports
# but leave CWD read-only, which breaks fib-up. Explores are not part of
# the CI gate so the broader trust is fine.
[group('explore')]
explore-bats *FILES: build-rust
  BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap {{FILES}}

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

# Reproduce the launchd environment that pivy-agent invokes piggy-askpass.sh
# under: no controlling TTY, no DISPLAY, scrubbed env. `setsid` detaches the
# controlling terminal so the script's `/dev/tty` open-test fails the same
# way it does under pivy-agent's fork+pipe. Exercises both call shapes
# pivy-agent uses (askpass at pivy-agent.c:841, plain-branch confirm at
# pivy-agent.c:1055).
#
# Expected pre-fix output: `exit=2`, stderr says "no render target
# available". That's what pivy-agent saw on Nov 14 2026 when home-manager
# pointed SSH_ASKPASS/SSH_CONFIRM at this script and signing failed with
# "agent refused operation".
[group('debug')]
debug-askpass-launchd-env: build-nix
    #!/usr/bin/env bash
    set -uo pipefail
    askpass=./result/libexec/piggy/piggy-askpass.sh
    [[ -x $askpass ]] || { echo "missing $askpass — run 'just build-nix' first" >&2; exit 1; }

    # Detach from the controlling TTY before exec. `setsid` is Linux-only
    # (not in BSD/Darwin coreutils), so we shell out to python3 — present
    # by default on both macOS and most Linux distros — to call os.setsid()
    # before execve. Same effect: child has no controlling terminal, so
    # opening /dev/tty fails, mirroring pivy-agent's fork+pipe context.
    detach_and_exec() {
      python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@"
    }

    run_case() {
      local label="$1" prompt="$2"
      local stderr_file
      stderr_file=$(mktemp -t piggy-askpass-stderr.XXXXXX)
      echo "=== $label ==="
      local stdout exit_code
      # `env -i` reproduces the scrubbed environment a launchd-spawned
      # process sees. `< /dev/null` closes stdin like pivy-agent's fork does.
      # Export the detach helper via a function-export so the env -i child
      # can still call it; simpler to inline the python invocation.
      stdout=$(env -i HOME="$HOME" PATH="/usr/bin:/bin" \
        python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
        "$askpass" "$prompt" 2>"$stderr_file" < /dev/null)
      exit_code=$?
      echo "exit=$exit_code"
      echo "stdout=[$stdout]"
      echo "stderr=[$(cat "$stderr_file")]"
      rm -f "$stderr_file"
      echo
    }

    run_case "askpass-call (pivy-agent.c:841)" "Enter PIV PIN for token 12345"
    run_case "confirm-call (pivy-agent.c:1055)" "A new client is trying to use PIV token 12345"

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

[group('codemod')]
codemod-fmt: codemod-fmt-treefmt

# Run treefmt via the flake's `formatter.${system}` wrapper, which
# composes nixfmt + shfmt + rustfmt under one CLI. See treefmt.nix
# for the program config.
[group('codemod')]
codemod-fmt-treefmt:
    nix fmt

[group('pre-build')]
lint-rust:
    cargo clippy --workspace --all-targets -- -D warnings

# Read-only formatting gate: builds the `checks.formatting`
# derivation, which runs treefmt against a /nix/store snapshot of
# the source tree and fails if anything would change. Does NOT
# modify files in the worktree -- the modifying counterpart is
# `codemod-fmt`.
[group('pre-build')]
lint-fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.formatting" --no-link --print-build-logs

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
      # -d so piv_enumerate's BNY_DEBUG "eliminated reader" messages surface
      # during any retry window (#27). Match the "device:" field emitted by
      # pivy-tool's successful enumeration — this line only appears when the
      # reader passes piv_enumerate's probes, so it won't false-positive on
      # debug log fields that mention the reader name.
      output=$(pivy-tool -d list 2>&1) || true
      echo "attempt $attempt: $output"
      if echo "$output" | grep -qE "^\s*device: Virtual PCD piggy fib"; then
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

# Send a pivy-shaped query extension request directly to $SSH_AUTH_SOCK
# (typically ssh-agent-mux) and hex-dump the response. Hardware-free:
# query does not touch the card. Used to investigate piggy#119 where
# pivy's piv_box_open_agent() fails parsing the query response through
# ssh-agent-mux at vendor/pivy/src/piv.c:7014.
[group('explore')]
explore-trace-agent-query sock="":
    #!/usr/bin/env bash
    set -euo pipefail
    sock_arg="{{sock}}"
    export PIGGY_PROBE_SOCK="${sock_arg:-${SSH_AUTH_SOCK:?set SSH_AUTH_SOCK or pass a socket arg}}"
    python3 <<'PY'
    import os, socket, struct, sys
    sock_path = os.environ['PIGGY_PROBE_SOCK']
    print(f"probing socket = {sock_path}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    SSH_AGENTC_EXTENSION = 27
    name = b"query"
    payload = bytes([SSH_AGENTC_EXTENSION]) \
        + struct.pack(">I", len(name)) + name \
        + struct.pack(">I", 0)
    framed = struct.pack(">I", len(payload)) + payload
    print(f"--- request ({len(framed)} bytes) ---")
    print(framed.hex(' '))
    s.sendall(framed)
    raw = b''
    while len(raw) < 4:
        chunk = s.recv(4 - len(raw))
        if not chunk: break
        raw += chunk
    length = struct.unpack(">I", raw)[0]
    print(f"--- response (length={length}) ---")
    body = b''
    while len(body) < length:
        chunk = s.recv(length - len(body))
        if not chunk: break
        body += chunk
    print(body.hex(' '))
    print()
    if len(body) < 1:
        print("response too short"); sys.exit(0)
    code = body[0]
    code_name = 'SSH2_AGENT_EXT_RESPONSE' if code==29 else 'SSH_AGENT_SUCCESS' if code==6 else '???'
    print(f"code byte = {code} ({code_name})")
    i = 1
    idx = 0
    while i + 4 <= len(body):
        slen = struct.unpack(">I", body[i:i+4])[0]
        i += 4
        if i + slen > len(body):
            print(f"  string[{idx}] OVERRUN: claimed_len={slen}, remaining={len(body)-i}")
            print(f"  from-len4 hex: {body[i-4:].hex(' ')}")
            break
        s_bytes = body[i:i+slen]
        i += slen
        try:
            s_str = s_bytes.decode('utf-8')
        except UnicodeDecodeError:
            s_str = f"<non-utf8: {s_bytes.hex(' ')}>"
        nul_at = s_bytes.find(b'\x00')
        nul_note = ""
        if nul_at != -1:
            if nul_at == len(s_bytes) - 1:
                nul_note = "  [trailing NUL]"
            else:
                nul_note = f"  [!! embedded NUL at byte {nul_at} — pivy sshbuf_get_cstring -4 !!]"
        print(f"  string[{idx}] len={slen} {s_str!r}{nul_note}")
        idx += 1
    if i < len(body):
        print(f"trailing bytes ({len(body)-i}): {body[i:].hex(' ')}")
    s.close()
    PY

# Verify the #119/#123 ssh-agent-mux ecdh decrypt fix end-to-end against the
# real card, using a piggy built from THIS worktree. The worktree binary
# bundles the patched vendored pivy-box on its PATH (flake.nix runtimeDeps),
# so its `pass show` exercises the #119 query-response parse fix; its dispatch
# honors PIGGY_AUTH_SOCK (#123). The installed nix-profile piggy predates the
# fix, so this recipe deliberately builds + runs the worktree binary instead.
#
# Pins the mux scenario the issues describe: route piggy's own decrypts at
# piggy-agent (PIGGY_AUTH_SOCK — advertises ecdh@joyent.com) while the ambient
# SSH_AUTH_SOCK is ssh-agent-mux (drops ecdh, see ssh-agent-mux#10). Mirrors
# eng/zz-pocs/piggy_pass_rcm_hook but against the freshly-built binary.
#
# INTERACTIVE + HARDWARE: piggy-agent prompts for your PIV PIN on the cold
# show. SIDE EFFECTS: inserts then removes two throwaway entries in your real
# piggy store (sign-commits if piggy.signcommits=true) and restarts your
# piggy-agent to start from a cold PIN cache. Linux-only.
#
# NOT part of `just` / the pre-merge CI lane, and must never be: it needs
# interactive PIN entry, so it stays an out-of-band manual verification
# (explore group only, run by hand when you want to re-confirm the live path).
#
# Primary signal: `pass show` through the mux env succeeds with no
# sshbuf_get_cstring / "failed to unlock ebox with agent" line. The client-side
# askpass count is supplementary (a nonzero count means pivy-box fell back to a
# direct-card unlock because the agent ecdh path failed; the agent's own PIN
# prompt is rendered by piggy-agent and is NOT counted here).
[group('explore')]
[linux]
explore-verify-auth-sock-cache piggy_auth_sock=env_var_or_default("PIGGY_AUTH_SOCK", "") ssh_auth_sock=env_var_or_default("SSH_AUTH_SOCK", ""):
    #!/usr/bin/env bash
    set -euo pipefail

    piggy_sock="{{piggy_auth_sock}}"
    mux_sock="{{ssh_auth_sock}}"
    : "${piggy_sock:?set PIGGY_AUTH_SOCK (piggy-agent socket) or pass piggy_auth_sock=...}"
    : "${mux_sock:?set SSH_AUTH_SOCK (mux socket) or pass ssh_auth_sock=...}"

    echo "=== building worktree piggy (nix build .#piggy) ==="
    out=$(nix build .#piggy --no-link --print-out-paths)
    PIGGY="$out/bin/piggy"
    echo "piggy        = $PIGGY ($("$PIGGY" version 2>/dev/null || echo '?'))"
    echo "PIGGY_AUTH_SOCK (piggy-agent) = $piggy_sock"
    echo "SSH_AUTH_SOCK   (mux)         = $mux_sock"

    probe_dir="$HOME/.tmp/piggy-auth-sock-probe"
    shim="$probe_dir/askpass-shim.sh"
    counter="$probe_dir/askpass-count"
    p1=piggy-authsock-probe-1
    p2=piggy-authsock-probe-2
    mkdir -p "$probe_dir"

    # Every piggy call runs with the mux as the ambient SSH_AUTH_SOCK; the #123
    # routing should redirect the decrypt at PIGGY_AUTH_SOCK.
    export SSH_AUTH_SOCK="$mux_sock"
    export PIGGY_AUTH_SOCK="$piggy_sock"

    cleanup() {
      "$PIGGY" pass rm -f "$p1" >/dev/null 2>&1 || true
      "$PIGGY" pass rm -f "$p2" >/dev/null 2>&1 || true
      rm -rf "$probe_dir"
    }
    trap cleanup EXIT

    echo
    echo "=== inserting throwaway probes into the real store ==="
    printf 'authsock-probe-1\n' | "$PIGGY" pass insert -e -f "$p1"
    printf 'authsock-probe-2\n' | "$PIGGY" pass insert -e -f "$p2"

    # Counting shim: one line per invocation, then exec the real askpass.
    # Catches CLIENT-side prompts (pivy-box falling back to a direct PCSC card
    # unlock because the agent ecdh path failed). PIN prompts the agent renders
    # itself are NOT counted here.
    cat >"$shim" <<'SHIM'
    #!/usr/bin/env bash
    printf 'askpass invoked at %s\n' "$(date +%s.%N)" >>"$COUNTER"
    exec "$REAL_SSH_ASKPASS" "$@"
    SHIM
    chmod +x "$shim"
    : >"$counter"

    echo
    echo "=== restarting piggy-agent (cold PIN cache) ==="
    systemctl --user restart piggy-agent || echo "WARN: could not restart piggy-agent (continuing)"
    for _ in 1 2 3 4 5; do [[ -S "$piggy_sock" ]] && break; sleep 1; done
    [[ -S "$piggy_sock" ]] || echo "WARN: $piggy_sock is not a live socket — is piggy-agent running?"

    run_show() {
      local name="$1" errf rc
      errf="$probe_dir/$name.err"
      echo
      echo "=== piggy pass show $name (through mux env) ==="
      set +e
      env REAL_SSH_ASKPASS="${SSH_ASKPASS:-}" COUNTER="$counter" SSH_ASKPASS="$shim" \
        "$PIGGY" pass show "$name" >/dev/null 2>"$errf"
      rc=$?
      set -e
      echo "exit=$rc"
      [[ -s "$errf" ]] && { echo "--- stderr ---"; cat "$errf"; }
      if grep -qiE 'sshbuf_get_cstring|invalid format|failed to unlock ebox with agent' "$errf"; then
        echo ">> agent-unlock error present (the #119/#123 symptom)"
        return 1
      fi
      return "$rc"
    }

    show1_ok=0; show2_ok=0
    run_show "$p1" && show1_ok=1 || true
    run_show "$p2" && show2_ok=1 || true

    count=$(wc -l <"$counter"); count="${count// /}"
    echo
    echo "=== summary ==="
    echo "show1 clean: $([[ $show1_ok == 1 ]] && echo yes || echo NO)"
    echo "show2 clean: $([[ $show2_ok == 1 ]] && echo yes || echo NO)"
    echo "client-side askpass (direct-card fallback) invocations: $count"
    if [[ $show1_ok == 1 && $show2_ok == 1 ]]; then
      echo "RESULT: PASS — pass-show decrypts through the mux env with no agent-unlock error. #119/#123 verified end-to-end."
    else
      echo "RESULT: FAIL — at least one show hit the agent-unlock error path. See stderr above."
    fi

# Probe PivApplet (running under fib) for X25519 / Ed25519 algorithm
# support. Sends GENERATE ASYMMETRIC KEY PAIR for several alg bytes and
# captures each SW. Hardware-free: only touches the virtual card behind
# fib. Used to settle issue #11 (X25519 ECDH) — see findings on the
# issue. Bring fib up with `just fib-up` first; this recipe fails fast
# if it isn't running rather than managing the lifecycle.
[group('explore')]
explore-x25519-pivapplet:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ ! -f .fib/env ]]; then
      echo "ERROR: .fib/env not found - run 'just fib-up' first" >&2
      exit 1
    fi
    eval "$(cat .fib/env)"
    reader="Virtual PCD piggy fib 00 00"
    aid="00:a4:04:00:0b:a0:00:00:03:08:00:00:10:00:01:00"

    probe() {
      local label="$1" alg="$2"
      echo
      echo "=== Probe $label (alg=0x$alg) ==="
      echo "--- SELECT PIV AID ---"
      opensc-tool -r "$reader" -s "$aid" 2>&1 || echo "(SELECT failed: $?)"
      echo "--- GENERATE ASYMMETRIC KEY PAIR slot=9D ---"
      opensc-tool -r "$reader" -s "$aid" \
        -s "00:47:00:9d:05:ac:03:80:01:$alg" 2>&1 \
        || echo "(GEN ASYM failed: $?)"
    }

    probe "Yubico/pivy X25519"             "e1"
    probe "Yubico/pivy ED25519"            "e0"
    probe "piggy-piv apdu.rs X25519"       "23"
    probe "piggy-piv apdu.rs ED25519"      "22"
    probe "ECCP256 (control, supported)"   "11"
    probe "RSA2048 (control, supported)"   "07"

# --- update / clean ---

update: update-nix

update-nix:
    nix flake update

clean: clean-build clean-rust

clean-build:
    rm -rf result

clean-rust:
    cargo clean

# --- maint: version bump + tag + release ---
#
# Three recipes per eng-versioning(7). `version.env` is the single
# source of truth: `bump-version` is a pure mutation, `tag` reads the
# current value and pushes a signed tag, `release` orchestrates the
# whole flow (changelog → bump → commit → tag → gh release).
# `version.env` is also read by `flake.nix` at eval time and by
# `crates/piggy/build.rs` at compile time.

# Rewrite the PIGGY_VERSION line in version.env. Touches no other
# file — committing is `release`'s job. Usage: just bump-version 0.1.1
[group("maint")]
bump-version new_version:
    sed -E -i "s/^(export PIGGY_VERSION)=.*/\1={{new_version}}/" version.env

# Sign + push a tag named after the current version.env. The "v"
# prefix is added for you. Usage: just tag "release v0.1.1"
[group("maint")]
tag message:
    #!/usr/bin/env bash
    set -euo pipefail
    . version.env
    tag="v${PIGGY_VERSION:?missing PIGGY_VERSION in version.env}"
    git tag -s -m "{{message}}" "$tag"
    gum log --level info "Created tag: $tag"
    git push origin "$tag"
    gum log --level info "Pushed $tag"
    git tag -v "$tag"

# Cut a release: must be run on master. Generates an auto-changelog
# (commits since the previous v* tag) BEFORE bumping so the bump
# commit doesn't appear in its own changelog, then bumps version.env,
# commits, signs+pushes a v<sem> tag, and creates a GitHub release
# whose body is the changelog. Usage: just release 0.1.1
[group("maint")]
release new_version:
    #!/usr/bin/env bash
    set -euo pipefail

    branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$branch" != "master" ]]; then
        gum log --level error "release only allowed from master (on '$branch')"
        exit 1
    fi

    prev=$(git tag --sort=-v:refname -l "v*" | head -1)
    header="release v{{new_version}}"
    if [[ -n "$prev" ]]; then
        summary=$(git log --format='- %s' "$prev"..HEAD)
        if [[ -n "$summary" ]]; then
            msg="$header"$'\n\n'"$summary"
        else
            msg="$header"
        fi
    else
        msg="$header"
    fi

    just bump-version "{{new_version}}"
    git add version.env
    git commit -m "$header"

    just tag "$msg"

    gh release create "v{{new_version}}" --title "$header" --notes "$msg"
