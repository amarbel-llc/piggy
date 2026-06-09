
default: lint build test

[group('pre-build')]
lint: lint-fmt lint-rust

# --- build ---

[group('build')]
build: build-nix build-rust

[group('build')]
build-nix:
    nix build --show-trace
    # Also build the standalone fibby package — `nix build` (no args)
    # defaults to `.#default` (= piggy), which doesn't transitively
    # depend on `.#fibby`. Without an explicit second build, a broken
    # flake.nix change to the fibby package would only surface the
    # next time someone ran `nix build .#fibby` directly or
    # `just fibby-up` (#129).
    nix build .#fibby --no-link --show-trace
    # Same rationale for the Go piggy-test-sshd binary (piggy#135): it's
    # not a transitive dep of `.#default`, so build it explicitly here to
    # catch flake.nix / vendorHash regressions at the merge gate rather
    # than only when `just debug-piggy-test-sshd` or the Phase D bats run.
    nix build .#piggy-test-sshd --no-link --show-trace

[group('build')]
build-rust *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build {{ARGS}}
    # Linux-only second pass: build fibby with --features hardware-proxy
    # so pcsc-sys's build.rs (which pkg-configs for libpcsclite at
    # compile time) runs in the merge gate. Clippy doesn't link, so a
    # missing/wrong libpcsclite-dev would slip past `lint-rust`. Same
    # Linux gating rationale as `lint-rust`'s second pass (flake.nix:166
    # adds pcsclite to rustBuildInputs only on isLinux). Skipped when
    # ARGS is set on the assumption that the caller is specifying a
    # narrower build scope on purpose.
    if [ -z "{{ARGS}}" ] && [ "$(uname -s)" = Linux ]; then
      cargo build -p fibby --features hardware-proxy
    fi

[group('build')]
build-rust-release:
    cargo build --release

run-nix *ARGS:
    nix run . -- {{ARGS}}

# --- test ---

[group('post-build')]
test: test-bats-default test-bats-conformance test-rust _test-conformance-linux-only

# The fibby-backed conformance lanes are Linux-only: fibby is a virtual PCSC
# card reached via libpcsclite's PCSCLITE_CSOCK_NAME socket redirect, which
# macOS's PCSC.framework ignores — so the virtual card is invisible there and
# every pivy/piggy card op reports "no PIV cards". (`just` also won't even
# parse a `[linux]`-only recipe named as an unconditional dependency on
# macOS.) Gate them all behind a per-platform shim: the real dependencies on
# Linux, a no-op on macOS, keeping the `test` dep list single-source.
[linux]
_test-conformance-linux-only: test-bats-conformance-fibby-pivy-agent-smoke test-bats-conformance-piggy-ssh-via-fibby test-bats-conformance-box-agentless-fibby test-bats-conformance-agent-pin-on-demand test-bats-conformance-age-plugin-piggy

[macos]
_test-conformance-linux-only:

# Sandboxed bats lane: runs every top-level t*.bats NOT tagged
# `# bats file_tags=hardware` inside the nix build sandbox. See
# ./bats.nix for the lane builder and CLAUDE.md "Architecture" for the
# tag convention. This replaces the previous `test-bats-piggy` recipe
# as the authoritative gate for the core suite; the bare-`bats`
# fallback lives at `test-bats-piggy-local` for fast iteration.
[group('post-build')]
test-bats-default:
    nix build .#bats-default --no-link --print-build-logs

# Local-iteration shortcut: re-runs the same t*.bats files outside the
# nix sandbox against `target/debug/piggy`. Faster than `nix build` on
# small edits; CI / pre-merge should use `test-bats-default` instead.
#
# Bats tests route through the rust `piggy` binary so the full
# rust → bash dispatch path is exercised; `build-rust` is a hard
# prerequisite — `zz-tests_bats/common.bash` aborts if
# `target/debug/piggy` is missing.
[group('post-build')]
test-bats-piggy-local: build-rust
  BATS_TEST_TIMEOUT=30 bats --jobs {{num_cpus()}} --tap zz-tests_bats/t*.bats

[group('post-build')]
test-bats-conformance: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  # On Linux, hand pivy_tool_admin_key.bats a real pivy-tool (PIVY_TOOL) and a
  # fibby binary (FIBBY_BIN) so it routes its PC/SC context at a virtual card
  # instead of the host's system pcscd, which denies SCardEstablishContext
  # (SCARD_W_SECURITY_VIOLATION) in headless/polkit sessions. macOS ignores
  # PCSCLITE_CSOCK_NAME, so there's nothing to redirect — run the glob
  # unchanged and skip the (pointless) fibby build. The agent-backed fibby
  # tests still skip here: they gate on PIVY_AGENT/PIGGY_BIN, left unset so
  # they run only via their dedicated [linux] recipes.
  fibby_env=()
  if [[ "$(uname -s)" == Linux ]]; then
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    fibby_env=(PIVY_TOOL="$pivy_out/bin/pivy-tool" FIBBY_BIN="$fibby_out/bin/fibby")
  fi
  env "${fibby_env[@]}" BATS_TEST_TIMEOUT=30 \
    bats --jobs {{ num_cpus() }} --tap zz-tests_bats/conformance/*.bats

[group('post-build')]
test-bats-conformance-protocol: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  # Build the conformance binary on demand and resolve its store path
  # without creating a `./result-conformance` symlink in the worktree.
  # The binary is exposed as piggy.tests.conformance (see passthru in
  # flake.nix). nix caches aggressively, so repeat invocations are free.
  out=$(nix build .#piggy.tests.conformance --no-link --print-out-paths)
  CONFORMANCE_BIN="$out/bin/piggy-agent-conformance" \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding \
    --tap zz-tests_bats/conformance/piggy_agent_protocol.bats

[group('post-build')]
test-bats-conformance-interop: build-rust
  #!/usr/bin/env bash
  set -euo pipefail
  trap 'just fib-down' EXIT
  # Rebuild vendored pivy first so any changes to vendor/pivy/openssh.patch
  # (e.g. #81's chacha20-poly1305@piggy.amarbel.net cipher entry) take
  # effect. The C pivy package is built by the parent flake as a nested
  # derivation (nix/pivy.nix, src = ./vendor/pivy); resolve its store path
  # via --print-out-paths rather than $(command -v pivy-box), which may
  # resolve to a stale direnv-cached binary. Mirrors the
  # test-bats-conformance-pivy-agent-hardware pattern. See #124 — the
  # vendor/pivy nested flake was removed, so the parent flake is the single
  # build entry for the vendored pivy tree.
  pivy_out=$(nix build .#pivy --no-link --print-out-paths)
  real_pivy_box="$pivy_out/bin/pivy-box"
  if [[ ! -x "$real_pivy_box" ]]; then
    echo "$real_pivy_box not executable — nix build .#pivy failed" >&2
    exit 1
  fi
  # Prepend it to PATH so subprocesses also see the fresh binary
  # (pivy-tool, etc.) consistently.
  export PATH="$pivy_out/bin:$PATH"
  # The dev piggy binary (built by the build-rust dep) for
  # piggy_box_decrypt_agentless.bats (#57): `piggy box stream decrypt` now
  # runs the Rust impl, whose CardEcdhOracle decrypts directly against the
  # card with no agent. The dev binary suffices — the agentless decrypt path
  # needs no makeWrapper env, and the C fallback finds pivy-box on $PATH.
  piggy_bin="$PWD/target/debug/piggy"
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
  # --allow-local-binding is a batman sandbox escape needed by the pcscd
  # path. (batman 0.1.3 removed the older --allow-unix-sockets flag;
  # passing it now is fatal — batman forwards it to upstream bats-core,
  # which rejects it. The pcscd.comm Unix socket is reachable via fence's
  # filesystem allowRead.) See CLAUDE.md "Debugging → bats + PCSC".
  # PIGGY_IDS_REAL is set by zz-tests_bats/common.bash; tests under
  # conformance/ that bypass the mock-piggy-ids symlink (notably
  # piggy_box_decrypt_interop.bats) reference it directly.
  INTEROP_GUID="$guid" \
    REAL_PIVY_BOX="$real_pivy_box" \
    PIGGY="$piggy_bin" \
    PCSCLITE_CSOCK_NAME="$PCSCLITE_CSOCK_NAME" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding --tap \
    zz-tests_bats/conformance/piggy_box_interop.bats \
    zz-tests_bats/conformance/piggy_box_decrypt_interop.bats \
    zz-tests_bats/conformance/piggy_box_decrypt_agentless.bats

# Agentless box decrypt against FIBBY (the Rust VirtualCard) — the fibby
# companion to the piggy_box_decrypt_agentless test above (which runs against
# fib/jcardsim). Brings up fibby with a seeded slot-9D ECDH key, then runs the
# SAME card-agnostic bats test against it: Rust `piggy-ids encrypt` ->
# `piggy box stream decrypt` with no agent -> Rust CardEcdhOracle -> fibby's
# 9D ECDH (piggy#57). Pure-Rust card-under-test, no Java/jcardsim/hardware, so
# it runs in the default `just test` lane unlike the fib interop recipe.
[group('post-build')]
[linux]
test-bats-conformance-box-agentless-fibby: build-rust
  #!/usr/bin/env bash
  set -uo pipefail
  pivy_out=$(nix build .#pivy --no-link --print-out-paths)
  export PATH="$pivy_out/bin:$PATH"
  pivy_tool="$pivy_out/bin/pivy-tool"
  fibby_bin="$PWD/target/debug/fibby"
  piggy_bin="$PWD/target/debug/piggy"
  [[ -x $fibby_bin ]] || { echo "missing $fibby_bin (build-rust)"; exit 1; }

  workdir=$(mktemp -d /tmp/pbox-agentless-fibby-XXXXXX)
  fibby_sock="$workdir/pcscd.comm"
  fibby_log="$workdir/fibby.log"
  fibby_pid=""
  cleanup() { [[ -n "$fibby_pid" ]] && kill "$fibby_pid" 2>/dev/null || true; rm -rf "$workdir"; }
  trap cleanup EXIT

  echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
  FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
    --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
  fibby_pid=$!
  for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
  [[ -S $fibby_sock ]] || { echo "fibby socket never appeared"; cat "$fibby_log"; exit 1; }

  echo "=== discover fibby GUID via pivy-tool list ==="
  guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$pivy_tool" list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
  [[ -n $guid ]] || { echo "no GUID from fibby"; cat "$fibby_log"; exit 1; }
  echo "  guid: $guid"

  askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
  INTEROP_GUID="$guid" \
    PIGGY="$piggy_bin" \
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
    SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY="" \
    PIGGY_TEST_FIB_PIN=123456 \
    BATS_TEST_TIMEOUT=30 bats --allow-local-binding --tap \
    zz-tests_bats/conformance/piggy_box_decrypt_agentless.bats

# Bring up fib, generate a P-256 key in 9D, and run the
# piggy_recipients_add_attached.bats conformance lane against the
# real PCSC stack. Linux-only (fib is Linux-only). Opt-in — not
# part of the default `just test` lane.
[group('post-build')]
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
      BATS_TEST_TIMEOUT=30 bats --allow-local-binding --tap \
      zz-tests_bats/conformance/piggy_recipients_add_attached.bats

# Bring up fib, generate a P-256 key in 9D, and run the
# piggy_pass_init.bats conformance lane against the real PCSC stack.
# Exercises `piggy pass init`'s auto-detect path (no -k, and -g <guid>)
# against the live card; the declarative -k path is covered by t0002
# (mocked). Linux-only (fib is Linux-only). Opt-in — not part of the
# default `just test` lane.
[group('post-build')]
test-bats-conformance-init: build-rust
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
      BATS_TEST_TIMEOUT=30 bats --allow-local-binding --tap \
      zz-tests_bats/conformance/piggy_pass_init.bats

# Hardware lane for `piggy pass show-batch`. Seals real eboxes against
# fib's 9D slot and verifies the end-to-end NDJSON event stream
# including the single-PIN guarantee, the wrong-card bail-out, the
# heterogeneous-batch per-ebox failure path, and the SIGINT bail-out
# shape. Linux-only (fib is Linux-only). Opt-in — not part of the
# default `just test` lane. Companion to the sandbox surface that
# runs under `bats-default`; see #122.
[group('post-build')]
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
      BATS_TEST_TIMEOUT=60 bats --allow-local-binding --tap \
      zz-tests_bats/conformance/piggy_pass_show_batch_hardware.bats

# Hardware-free Phase 0 smoke for piggy#135: stand up fibby (virtual
# backend, empty slots) and pivy-agent against it, run ssh-add -L,
# assert the substrate works. Lives in the default `just test` lane
# (no hardware dependency); the bats file gracefully skips if PIVY_
# AGENT / FIBBY_BIN aren't supplied (e.g. when invoked via the
# conformance glob without this recipe's env setup).
#
# Both binaries come from nix derivations (.#pivy + .#fibby) rather
# than the workspace's target/debug/. This is the same pattern as the
# hardware lane recipes and matches what production users would run;
# the cached store paths are free on repeat invocations.
[group('post-build')]
[linux]
test-bats-conformance-fibby-pivy-agent-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    # The wrapped piggy (.#default) bakes the real pivy-box on its PATH and
    # the real piggy-ids via PIGGY_IDS_PATH, so the agent-rebox decrypt test
    # (piggy_rebox_decrypts_via_seeded_fibby_slot_9d, the piggy#138 gate)
    # exercises the real crypto path even though common.bash puts mock
    # pivy-box/piggy-ids on PATH.
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      PIVY_TOOL="$pivy_out/bin/pivy-tool" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_fibby_pivy_agent_smoke.bats

# piggy#135 Phase D: end-to-end SSH-forwarded decrypt lane. Stands up
# fibby + pivy-agent + piggy-test-sshd and drives a "remote" `piggy pass
# show` over `ssh -A` so the decrypt routes through the forwarded agent
# socket back to pivy-agent <-> fibby. No hardware. The wrapped piggy
# (.#default) bypasses common.bash's mock crypto (see the smoke recipe);
# .#piggy-test-sshd is the Go fixture server (#135 Phase A/B). The
# `just debug-ssh-decrypt-via-fibby` recipe is the non-bats scaffold.
[group('post-build')]
[linux]
test-bats-conformance-piggy-ssh-via-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    sshd_out=$(nix build .#piggy-test-sshd --no-link --print-out-paths)
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      SSHD_BIN="$sshd_out/bin/piggy-test-sshd" \
      BATS_TEST_TIMEOUT=90 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_ssh_via_fibby.bats

# piggy#58: prompt-on-demand PIN entry parity. Drives a slot-9D decrypt
# at the agent (via PIGGY_AUTH_SOCK) WITHOUT pushing a PIN first, so the
# agent must fork SSH_ASKPASS on demand. Baselines the C pivy-agent; the
# Rust `piggy agent` is held to the same scenario once re-pointed. Uses
# the wrapped piggy (.#default, real pivy-box) over fibby — no hardware,
# no SSH forwarding (unlike piggy-ssh-via-fibby). Agent dev-loop: this is
# the CI gate for the #58 prompt-on-demand work. [linux]-only like the
# other fibby lanes (fibby's PCSCLITE_CSOCK_NAME redirect is ignored by
# macOS's PCSC.framework).
[group('post-build')]
[linux]
test-bats-conformance-agent-pin-on-demand:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_agent_pin_on_demand.bats

# Fibby-backed end-to-end gate for `age-plugin-piggy`: derive the age
# recipient/identity from fib's slot-9D key (`generate`), encrypt a secret with
# `age`, then decrypt it back through piggy-agent's ecdh@joyent.com against fib
# with on-demand PIN. Confirms on real card-side crypto the X-coordinate
# assumption the Rust unit tests pin only in software. Serves the
# age-plugin-piggy dev loop (Phase 2).
[group('post-build')]
[linux]
test-bats-conformance-age-plugin-piggy:
    #!/usr/bin/env bash
    set -euo pipefail
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    age_out=$(nix build .#age --no-link --print-out-paths)
    FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      AGE_BIN="$age_out/bin/age" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/age_plugin_piggy_fibby.bats

# Fibby-backed gate for `recipients sync` with NO file: re-encrypt the store
# (whole or `-p` subtree) to the current piggy-ids recipients, then prove the
# result still decrypts through the agent <-> fibby slot-9D rebox path. The
# wrapped piggy (.#default, real pivy-box + piggy-ids) bypasses common.bash's
# mock crypto so the re-encrypt produces real fresh ciphertext. No hardware.
# [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME redirect is a
# no-op on macOS's PCSC.framework).
[group('post-build')]
[linux]
test-bats-conformance-recipients-sync-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_recipients_sync_fibby.bats

# Fibby-backed proof that `piggy pass show -r` annotates each ebox with its
# REAL recipient, read offline from the ebox wire header (no card/PIN). The
# wrapped piggy (.#default, real pivy-box + piggy-ids) writes genuine eboxes via
# init/insert so the rendered markl prefix can be cross-checked against the
# card's recipient in piggy-ids. Mock-mode coverage (the [?] degrade path) lives
# in t0020-show.bats. [linux]-only like the other fibby lanes (PCSCLITE_CSOCK_NAME
# redirect is a no-op on macOS's PCSC.framework).
[group('post-build')]
[linux]
test-bats-conformance-pass-ls-recipients-fibby:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    PIVY_AGENT="$pivy_out/bin/pivy-agent" \
      FIBBY_BIN="$fibby_out/bin/fibby" \
      PIGGY_BIN="$piggy_out/bin/piggy" \
      BATS_TEST_TIMEOUT=60 bats --no-sandbox --tap \
      zz-tests_bats/conformance/piggy_pass_ls_recipients_fibby.bats

# Hardware lane for the C pivy-agent built from vendor/pivy/. Runs
# pivy_agent_hardware.bats against the user's plugged-in PIV card.
# Read-only PIN-free operations (REQUEST_IDENTITIES). Verifies the
# piggy#107 (piggy#105 step 3) state-machine plumbing doesn't break
# the simple identity-listing case. Opt-in — not part of the default
# `just test` lane. Requires a real card plugged in.
[group('post-build')]
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

[group('post-build')]
test-bats-file *FILES: build-rust
    BATS_TEST_TIMEOUT=30 bats --no-sandbox --tap {{FILES}}

[group('post-build')]
test-rust *ARGS:
    cargo test {{ARGS}}

# Smoke-test for the `services.piggy-agent` home-manager module (#52).
# Evaluates the module against synthetic configs and verifies the option
# schema, both platform code paths, and every assertion. Reports
# pass/fail per case.
[group('post-build')]
test-nix-hm-module:
  #!/usr/bin/env bash
  set -euo pipefail
  expr='let
    flake = builtins.getFlake (toString ./.);
    pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
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
[group('post-build')]
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
[group('post-build')]
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
[group('post-build')]
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

# `cargo check` type-evals without codegen — a pre-build validation
# (hard failure on type errors), distinct from the `lint-rust` clippy
# opinion pass. `validate-rust` covers the whole workspace; the
# per-crate variants are faster iteration subsets.
[group('pre-build')]
validate-rust *ARGS:
    cargo check {{ARGS}}

[group('pre-build')]
validate-box:
    cargo check -p piggy-box

[group('pre-build')]
validate-piggy:
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

# Dump the recipient pubkey(s) baked into one or more .ebox files, rendered
# as piggy-recipient-v1@pivy_ecdh_p256_pub-… markl IDs so they compare
# byte-for-byte against piggy-ids and `piggy pass recipients list-available`.
# Non-destructive: parses the ebox off-disk, touches no card, prompts for no
# PIN. Diagnoses "card present but cannot decrypt" — if no recipient matches
# an attached card's pubkey, the box was encrypted to a different recipient
# set. Usage: just debug-ebox-recipients ~/.local/share/piggy/foo.ebox …
[group('debug')]
debug-ebox-recipients *EBOXES:
    cargo run -q -p piggy-box --example dump-recipients -- {{EBOXES}}

# EXPLORE (#task darwin-fibby) — prove/refute whether macOS's PCSC.framework
# honors PCSCLITE_CSOCK_NAME. Starts fibby (virtual, seeded slot 9D) on a temp
# socket, points PCSCLITE_CSOCK_NAME at it, and runs the framework-linked
# `pivy-tool list`. If the card appears, the framework DOES honor the var
# (darwin-fibby is trivial); if it reports no readers / no card, the var is
# ignored (fibby needs a different interpose on darwin). Pure probe, no PIN.
[group('explore')]
explore-darwin-fibby-csock: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    # Short path: AF_UNIX sun_path is 104 bytes on macOS; the worktree
    # .tmp/ prefix overruns it. Use a short /tmp dir (TMPDIR points into
    # the worktree, so override it explicitly).
    workdir="$(TMPDIR=/tmp mktemp -d /tmp/fibcsock.XXXXXX)"
    sock="$workdir/pcscd.comm"
    log="$workdir/fibby.log"
    fibby="$PWD/target/debug/fibby"
    trap 'kill "$fibby_pid" 2>/dev/null; rm -rf "$workdir"' EXIT
    FIBBY_LOG=wire "$fibby" --socket "$sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $sock ]] && break; sleep 0.1; done
    [[ -S $sock ]] || { echo "fibby socket never appeared"; cat "$log"; exit 1; }
    echo "=== fibby up at $sock (pid $fibby_pid) ==="
    echo "=== pivy-tool list WITH PCSCLITE_CSOCK_NAME pointed at fibby ==="
    PCSCLITE_CSOCK_NAME="$sock" pivy-tool list; echo "pivy-tool exit=$?"
    echo "=== fibby wire log (did the framework client ever connect?) ==="
    cat "$log"

# EXPLORE (#task darwin-fibby) — does nixpkgs vsmartcard-vpcd actually BUILD on
# this darwin, or is its `broken = isDarwin` flag a stale blanket? The package
# already scaffolds the darwin path (`--enable-infoplist` → ifd-vpcd.bundle).
# If it builds, the bundle is one nix build away; if it fails, we learn the
# real blocker cheaply. Uses NIXPKGS_ALLOW_BROKEN + --impure to bypass the
# broken assertion.
[group('explore')]
explore-darwin-vpcd-build:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== attempting nixpkgs#vsmartcard-vpcd build on $(uname -sm) with broken override ==="
    NIXPKGS_ALLOW_BROKEN=1 nix build --impure --no-link --print-out-paths \
      'nixpkgs#vsmartcard-vpcd' 2>&1 | tail -40
    echo "=== nix build exit=$? ==="

# EXPLORE (#task darwin-fibby) — vpcd's darwin build fails at link: the IFD
# handler (libifdvpcd) references `_log_msg`, which the loader daemon provides
# at runtime, but darwin ld rejects the undefined symbol. Override the nixpkgs
# derivation to add `-undefined dynamic_lookup` (the standard darwin
# loadable-bundle flag) and drop the broken gate, then rebuild. If it links and
# emits ifd-vpcd.bundle, this is both a buildable path AND a nixpkgs-unbreak PR.
[group('explore')]
explore-darwin-vpcd-build-patched:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== building patched vsmartcard-vpcd (darwin dynamic_lookup) ==="
    NIXPKGS_ALLOW_BROKEN=1 nix build --impure --no-link --print-out-paths --expr '
      let
        flake = builtins.getFlake "nixpkgs";
        pkgs = import flake.outPath { system = "aarch64-darwin"; config.allowBroken = true; };
      in
      pkgs.vsmartcard-vpcd.overrideAttrs (old: {
        # The IFD handler is a loadable bundle; _log_msg is resolved at
        # runtime by com.apple.ifdreader. Tell darwin ld to allow it.
        env = (old.env or {}) // {
          NIX_LDFLAGS = (old.env.NIX_LDFLAGS or "") + " -undefined dynamic_lookup";
        };
        meta = old.meta // { broken = false; };
      })
    ' 2>&1 | tail -45
    echo "=== nix build exit=$? ==="

# Generic driver for exploratory bats files. Each file brings up whatever
# infrastructure it needs in setup_file() / teardown_file(). We pass
# --no-sandbox because explore tests often need to talk to pcscd (Unix
# sockets), bind local ports, shell out to `just` to bring up fib (which
# writes .fib/ into CWD and /run/user/$UID), etc. The narrow-escape flag
# (--allow-local-binding) covers local binding but leaves CWD read-only,
# which breaks fib-up. Explores are not part of the CI gate so the
# broader trust is fine.
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

# Survey the wet-env PCSC state: pcscd process, system sockets, readers
# visible to libpcsclite (opensc-tool + pcsc_scan), ATR of any inserted
# card, and the USB device side via lsusb. Read-only — does not connect
# to the card or consume PIN retries. Serves the fibby hardware-proxy
# validation dev-loop (does the right card show up before we wire fibby
# to it?) and any other recipe that depends on a real card being present.
[group('debug')]
debug-pcsc-env:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== pcscd process ==="
    pgrep -a pcscd 2>/dev/null || echo "no pcscd process"
    echo
    echo "=== system sockets ==="
    for s in /run/pcscd/pcscd.comm /var/run/pcscd/pcscd.comm; do
      if [[ -S $s ]]; then ls -la "$s"; else echo "$s: not a socket"; fi
    done
    echo
    echo "=== PCSCLITE_CSOCK_NAME ==="
    echo "${PCSCLITE_CSOCK_NAME:-(unset)}"
    echo
    echo "=== opensc-tool readers ==="
    timeout 5 opensc-tool -l 2>&1
    echo
    echo "=== pcsc_scan one round ==="
    timeout 3 pcsc_scan -n 2>&1 | tail -8
    echo
    echo "=== lsusb (Yubico/CCID/smartcard) ==="
    lsusb 2>&1 | grep -iE 'yubico|yubikey|ccid|smart' || echo "no Yubico/CCID USB device"

# Verify stats-me telemetry end-to-end (#141 + the piggy.pass/box/agent
# coverage expansion): report whether anything is collecting on the
# configured 127.0.0.1:8125, then prove piggy emits by running an
# instrumented `pass` command against a throwaway local UDP listener and
# printing the captured statsd datagram. No card needed. Serves the
# stats-me wiring dev-loop.
[group('debug')]
debug-stats-me-roundtrip: build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== configured endpoint: ${STATSD_HOST:-(unset)}:${STATSD_PORT:-(unset)} ==="
    echo "=== UDP listeners on :8125 (the real stats-me daemon, if any) ==="
    ss -ulnp 2>/dev/null | grep 8125 || echo "(nothing listening on UDP 8125 — no stats-me daemon)"
    echo
    port=18125
    cap="$(mktemp)"
    # Capture datagrams on a throwaway port for ~3s, then exit.
    timeout 3 socat -u UDP-RECV:"$port" - >"$cap" 2>/dev/null &
    sock_pid=$!
    sleep 0.4
    store="$(mktemp -d)"
    echo "=== emit: piggy pass find (STATSD_PORT=$port) ==="
    STATSD_HOST=127.0.0.1 STATSD_PORT="$port" PIGGY_STORE_DIR="$store" \
      target/debug/piggy pass find nonexistent-term || true
    wait "$sock_pid" 2>/dev/null || true
    rm -rf "$store"
    echo
    echo "=== captured datagram(s) ==="
    if [[ -s "$cap" ]]; then cat "$cap"; echo; else echo "(none captured)"; fi
    rm -f "$cap"
    echo
    echo "=== stats-me collected piggy.* counters (statsd admin :8126) ==="
    if ss -tlnp 2>/dev/null | grep -q 8126; then
      # Emit one to the REAL endpoint, then query the live accumulators.
      STATSD_HOST=127.0.0.1 STATSD_PORT=8125 PIGGY_STORE_DIR="$(mktemp -d)" \
        target/debug/piggy pass find "roundtrip-marker-$$" >/dev/null 2>&1 || true
      sleep 0.3
      printf 'counters\nquit\n' | timeout 3 nc 127.0.0.1 8126 2>/dev/null \
        | tr ',' '\n' | grep -i piggy || echo "(no piggy.* counters returned)"
    else
      echo "(no statsd admin interface on :8126)"
    fi

# Bring fibby up with the hardware-proxy backend (proxying to the system
# pcscd/YubiKey), run an arbitrary client command pointed at fibby's
# socket via PCSCLITE_CSOCK_NAME, then tear fibby down and dump the
# FIBBY_LOG=wire trace. Single-shot, transactional — no leftover
# processes. Serves the fibby wet-env validation dev-loop: pivy-tool /
# piggy / opensc-tool exercises driven through fibby's protocol layer.
#
# Usage:
#   just debug-fibby-proxy pivy-tool list
#   just debug-fibby-proxy pivy-tool init
#   just debug-fibby-proxy pivy-tool -P 123456 generate 9e
#   just debug-fibby-proxy piggy pass show -v some/entry
#
# The recipe rebuilds with --features hardware-proxy on every call so
# you don't have to remember the feature flag.
#
# Env overrides (all optional):
#   FIBBY_BACKEND_PCSCD=<socket>  Tell fibby's HardwareProxy to talk to
#                                 a non-default pcscd (e.g. fib's
#                                 private pcscd at /tmp/piggy-fib-ipc/pcscd.comm).
#                                 Default: system pcscd at /run/pcscd/pcscd.comm.
#   FIBBY_READER=<substr>         Reader-name substring HardwareProxy
#                                 selects on. Default: "Yubico". Set to
#                                 e.g. "piggy fib" for the fib virtual
#                                 reader.
#   FIBBY_KEEP_LOGS=<dir>         Copy the FIBBY_LOG=wire trace to this
#                                 directory before the cleanup trap erases
#                                 the tmp dir. Output file is named
#                                 wire-<UTC timestamp>-<pid>.log. Default:
#                                 unset (trace is ephemeral).
[group('debug')]
debug-fibby-proxy *CLIENT_CMD:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ -z "{{CLIENT_CMD}}" ]]; then
      echo "usage: just debug-fibby-proxy <client cmd...>" >&2
      exit 2
    fi
    cargo build -p fibby --features hardware-proxy >/dev/null 2>&1 || {
      echo "fibby --features hardware-proxy build failed; rerun to see why" >&2
      cargo build -p fibby --features hardware-proxy
      exit 1
    }
    sock_dir="${TMPDIR:-/tmp}/fibby-proxy.$$"
    mkdir -p "$sock_dir"
    sock="$sock_dir/pcscd.comm"
    log="$sock_dir/wire.log"
    reader="${FIBBY_READER:-Yubico}"
    # Last-resort cleanup: kill fibby + remove the tmp socket dir on any
    # exit path. Before the rm, copy the wire trace under
    # FIBBY_KEEP_LOGS if requested. Fibby itself rm -f's a stale socket
    # on startup, so a crashed previous run won't block restart. The
    # trailing `:` keeps cleanup's exit status from polluting the
    # script's final exit code — without it, `wait $fibby_pid`
    # propagates fibby's SIGTERM (143) and the recipe spuriously
    # reports failure.
    cleanup() {
      [[ -n "${fibby_pid:-}" ]] && kill "$fibby_pid" 2>/dev/null
      wait "${fibby_pid:-}" 2>/dev/null
      if [[ -n "${FIBBY_KEEP_LOGS:-}" && -f "$log" ]]; then
        mkdir -p "$FIBBY_KEEP_LOGS"
        stamp=$(date -u +%Y%m%dT%H%M%SZ)
        kept="$FIBBY_KEEP_LOGS/wire-$stamp-$$.log"
        cp "$log" "$kept" 2>/dev/null && \
          echo "  wire log kept: $kept" >&2
      fi
      rm -rf "$sock_dir"
      :
    }
    trap cleanup EXIT
    # FIBBY_BACKEND_PCSCD redirects fibby's *upstream* pcsc-lite client
    # (the one HardwareProxy uses internally). The CLIENT_CMD below uses
    # a fresh PCSCLITE_CSOCK_NAME=$sock that overrides this for the
    # client itself.
    if [[ -n "${FIBBY_BACKEND_PCSCD:-}" ]]; then
      echo "=== fibby backend pcscd → $FIBBY_BACKEND_PCSCD (reader=\"$reader\") ==="
      PCSCLITE_CSOCK_NAME="$FIBBY_BACKEND_PCSCD" \
        FIBBY_LOG=wire ./target/debug/fibby --backend hardware --reader "$reader" \
        --socket "$sock" >"$log" 2>&1 &
    else
      FIBBY_LOG=wire ./target/debug/fibby --backend hardware --reader "$reader" \
        --socket "$sock" >"$log" 2>&1 &
    fi
    fibby_pid=$!
    # Wait up to 5s for the socket to appear; if it doesn't, fibby crashed
    # at startup (usually pcsc init failure) — dump the log and bail.
    for _ in $(seq 1 50); do
      [[ -S "$sock" ]] && break
      sleep 0.1
    done
    if [[ ! -S "$sock" ]]; then
      echo "!!! fibby socket never appeared; log:" >&2
      cat "$log" >&2
      exit 1
    fi
    echo "=== fibby up on $sock (pid $fibby_pid); running client ==="
    PCSCLITE_CSOCK_NAME="$sock" {{CLIENT_CMD}}
    client_exit=$?
    echo
    echo "=== client exit: $client_exit ==="
    echo
    echo "=== fibby wire log ==="
    cat "$log"
    # Propagate the client's exit, not cleanup's. EXIT trap still runs
    # after this — but its exit status no longer overrides ours.
    exit "$client_exit"

# Tier-4 differential gate for fibby's hardware-proxy backend: run a
# real pivy-box stream encrypt + decrypt round-trip against the inserted
# PIV card, routed entirely through fibby's pcsc-lite protocol server.
# Calls debug-fibby-proxy with the in-repo helper script — the helper
# discovers the card GUID at runtime via `pivy-tool list`, so it works
# on any throwaway with slot 9D already initialized.
#
# Bootstrap a throwaway card before invoking this recipe:
#   just debug-fibby-proxy pivy-tool -K default init
#   just debug-fibby-proxy pivy-tool -P 123456 -K default -a eccp256 generate 9d
# Then:
#   just debug-fibby-roundtrip
# Expected tail of output: `=== ROUND-TRIP OK ===` and `client exit: 0`.
[group('debug')]
debug-fibby-roundtrip:
    just debug-fibby-proxy bash zz-tests_bats/helpers/fibby-roundtrip.sh

# Tier-4 differential gate at the **piggy** layer: pass init / insert /
# show round-trip against the inserted PIV card via fibby. Companion to
# debug-fibby-roundtrip (which exercises the same crypto at the
# pivy-box layer). Gitless store: piggy's find_inner_git_dir returns
# None and the post-write commit is silently skipped — proves the
# wet-env path without dragging in git config plumbing.
#
# Bootstrap as for debug-fibby-roundtrip. Build deps:
#   just build-rust   # debug piggy + piggy-ids on target/debug/
[group('debug')]
debug-fibby-piggy-roundtrip: build-rust
    just debug-fibby-proxy bash zz-tests_bats/helpers/fibby-piggy-roundtrip.sh

# Tier-4 round-trip with persistent wire-log capture: same as
# debug-fibby-roundtrip but the FIBBY_LOG=wire trace is preserved
# under crates/fibby/tests/fixtures/captures/yubikey/wire-<timestamp>.log
# instead of being torn down with the recipe's tmp dir. Run this when
# a real YubiKey is inserted; the captured trace is the canonical
# input for the future per-APDU fixture set that VirtualCard's step-5
# tests will replay/diff against.
[group('debug')]
debug-fibby-roundtrip-capture:
    FIBBY_KEEP_LOGS=crates/fibby/tests/fixtures/captures/yubikey \
      just debug-fibby-roundtrip

# Variant of debug-fibby-roundtrip-capture that routes the wire log into
# the `test-vector/` subdir, so captures against a throwaway YK with the
# RFC 6979 §A.2.5 scalar imported at slot 9D (see debug-yk-throwaway-
# import-rfc6979) stay segregated from the existing generated-key
# fixtures. Serves the fibby #134 byte-deterministic ECDH replay dev-loop.
[group('debug')]
debug-fibby-roundtrip-capture-test-vector:
    FIBBY_KEEP_LOGS=crates/fibby/tests/fixtures/captures/yubikey/test-vector \
      just debug-fibby-roundtrip

# Tier-4 round-trip routed through fib (the Java virtual PIV card)
# instead of a real YubiKey. fib provides a second oracle — same APDU
# script, second capture — so we have differential fixtures even when
# no hardware is around. Brings fib up first (idempotent); does NOT
# tear it down on exit (run `just fib-down` when you're done).
#
# Prereq: fib's slot 9D must already have an ECDH key. Bootstrap once
# per fib-up session:
#   just debug-fibby-proxy-via-fib pivy-tool -K default init
#   just debug-fibby-proxy-via-fib pivy-tool -P 123456 -K default -a eccp256 generate 9d
#
# The captured trace lands under crates/fibby/tests/fixtures/captures/fib/.
[group('debug')]
debug-fibby-roundtrip-via-fib: build-rust fib-up
    FIBBY_BACKEND_PCSCD=/tmp/piggy-fib-ipc/pcscd.comm \
    FIBBY_READER="piggy fib" \
    FIBBY_KEEP_LOGS=crates/fibby/tests/fixtures/captures/fib \
      just debug-fibby-roundtrip

# Companion to debug-fibby-roundtrip-via-fib: run an arbitrary client
# command via fibby-via-fib. Used to bootstrap fib's slot 9D (init +
# generate) before the round-trip recipe is meaningful.
#
# Usage:
#   just debug-fibby-proxy-via-fib pivy-tool list
#   just debug-fibby-proxy-via-fib pivy-tool -K default init
[group('debug')]
debug-fibby-proxy-via-fib *CLIENT_CMD: build-rust fib-up
    FIBBY_BACKEND_PCSCD=/tmp/piggy-fib-ipc/pcscd.comm \
    FIBBY_READER="piggy fib" \
      just debug-fibby-proxy {{CLIENT_CMD}}

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
    #!/usr/bin/env bash
    set -euo pipefail
    cargo clippy --workspace --all-targets -- -D warnings
    # Linux-only second pass: clippy fibby with --features hardware-proxy
    # so wet-env-path regressions (status2 signature drift, protocol2
    # Option<T> mismatches, missing pcsc::Error variants) are caught at
    # the merge gate — the same lane the host-devshell-unblock fixes at
    # c0c59f0 + 653ca77 fell through silently before they were in CI.
    # Gated on Linux because flake.nix:166 only adds pcsclite to
    # rustBuildInputs on isLinux (vsmartcard is broken on darwin; the
    # hardware-proxy build needs libpcsclite-dev via pcsc-sys).
    if [ "$(uname -s)" = Linux ]; then
      cargo clippy -p fibby --all-targets --features hardware-proxy -- -D warnings
    fi

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
[group('operational')]
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
[group('operational')]
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

# Bring up the standalone `fibby` server in hardware-proxy mode, fronted
# by the system pcscd. Mirrors fib-up's UX: short-circuits if already
# running, drops a PID file under .fibby/, and writes an env file
# (.fibby/env) consumers `eval` to set PCSCLITE_CSOCK_NAME.
#
# Unlike fib (which brings up its own pcscd + jcardsim + applet),
# fibby-up assumes a real PC/SC reader + card are already plugged in
# and the system pcscd is up — its sole job is to translate pcsc-lite
# daemon-protocol traffic into PC/SC client traffic against the system
# pcscd. If no card is present, fibby's startup error surfaces via the
# log and the recipe bails with a clear hint.
#
# The fibby binary comes from `nix build .#fibby` (Linux-only at the
# moment because hardware-proxy needs libpcsclite — flake.nix gates it
# on isLinux). Use the dev-loop alternative `debug-fibby-proxy` if you
# need fast iteration off `./target/debug/fibby` instead.
[group('operational')]
fibby-up:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p .fibby
    sock="/tmp/piggy-fibby-ipc/pcscd.comm"
    # Short-circuit if already running.
    if [[ -f .fibby/fibby.pid ]] && kill -0 "$(cat .fibby/fibby.pid)" 2>/dev/null; then
      echo "fibby-up: already running (pid $(cat .fibby/fibby.pid)). eval \$(cat .fibby/env)" >&2
      exit 0
    fi
    # System pcscd sanity check: HardwareProxy::new fails noisily if
    # neither standard socket is present; check first for a better
    # error than a stack trace.
    if [[ ! -S /run/pcscd/pcscd.comm && ! -S /var/run/pcscd/pcscd.comm ]]; then
      echo "fibby-up: no system pcscd socket — start pcscd first" >&2
      exit 1
    fi
    fibby_bin=$(nix build --no-link --print-out-paths .#fibby)/bin/fibby
    mkdir -p "$(dirname "$sock")"
    rm -f "$sock"
    FIBBY_LOG=info "$fibby_bin" \
      --backend hardware \
      --socket "$sock" \
      >.fibby/fibby.log 2>&1 &
    fibby_pid=$!
    echo "$fibby_pid" >.fibby/fibby.pid
    # Wait for the socket; if it doesn't appear, fibby crashed at
    # startup — most commonly "no reader matching Yubico" when the
    # card isn't plugged in.
    for _ in $(seq 1 50); do
      [[ -S "$sock" ]] && break
      sleep 0.1
    done
    if [[ ! -S "$sock" ]]; then
      echo "fibby-up: socket never appeared — see .fibby/fibby.log" >&2
      cat .fibby/fibby.log >&2
      kill "$fibby_pid" 2>/dev/null || true
      rm -f .fibby/fibby.pid
      exit 1
    fi
    cat >.fibby/env <<EOF
    export PCSCLITE_CSOCK_NAME="$sock"
    # fibby pid: $fibby_pid
    EOF
    echo "fibby: up — eval \$(cat .fibby/env) to connect"

# Tear down the standalone fibby server brought up by `fibby-up`.
[group('operational')]
fibby-down:
    #!/usr/bin/env bash
    set -uo pipefail
    if [[ -f .fibby/fibby.pid ]]; then
      kill "$(cat .fibby/fibby.pid)" 2>/dev/null || true
    fi
    rm -rf .fibby
    rm -f /tmp/piggy-fibby-ipc/pcscd.comm
    rmdir /tmp/piggy-fibby-ipc 2>/dev/null || true
    echo "fibby: down"

# Open a subshell with fib up and the env preloaded; tears down on exit.
[group('operational')]
fib-shell:
    #!/usr/bin/env bash
    set -euo pipefail
    just fib-up
    trap 'just fib-down' EXIT
    export PCSCLITE_CSOCK_NAME="/tmp/piggy-fib-ipc/pcscd.comm"
    PS1="(fib) $PS1" exec "$SHELL"

# Smoke test: bring up fib, verify pivy-tool sees the virtual card, tear down.
[group('post-build')]
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

# HARDWARE + out-of-band — piggy#56: exercise the REAL Rust PinSession on a
# real card. Unlike a `piggy agent` invocation (which execs the C pivy-agent),
# this runs the in-process `unlock_ebox_card_integration`
# test, which drives piggy's Rust `CardEcdhOracle` → `begin_pin_session` →
# `PinSession::{verify_pin,ecdh_derive}` DIRECTLY against the card. First time
# the Rust #56 PinSession code runs on real hardware (it has only seen fib).
# Pins to the throwaway via PIGGY_TEST_CARD_GUID so a co-resident prod card is
# never selected; one fail-fast PIN check first. NEVER pass your prod PIN.
[group('explore')]
[linux]
explore-rust-card-unlock-hw guid="5DA19C98257243EFCD29BE3AE91EA7F8" pin="123456": build-rust
    #!/usr/bin/env bash
    set -euo pipefail
    guid="{{guid}}"; pin="{{pin}}"
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    tmpdir=$(mktemp -d /tmp/piggy-rust-card-hw.XXXXXX); trap 'rm -rf "$tmpdir"' EXIT
    pub="$tmpdir/9d.pub"

    echo "=== pre-flight: throwaway $guid present + single PIN check ==="
    "$pivy_tool" -g "$guid" pubkey 9d >"$pub" 2>/dev/null || { echo "no 9d key on $guid"; exit 1; }
    if ! "$pivy_tool" -g "$guid" -P "$pin" ecdh 9d <"$pub" >/dev/null 2>&1; then
      echo "REFUSING: PIN/ECDH check failed on $guid slot 9d. NOT running."; exit 1
    fi
    echo "PIN OK."

    echo "=== unlock_ebox_card_integration vs the real throwaway (Rust PinSession) ==="
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    PIGGY_TEST_CARD_GUID="$guid" \
      PIGGY_TEST_FIB_PIN="$pin" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      cargo test --test unlock_ebox_card_integration -- --nocapture

# HARDWARE, read-only — enumerate every PIV card currently visible to
# pcscd. Prints each card's reader, GUID, CHUID, and slots via
# `pivy-tool list`, then a YubiKey factory serial per card via the
# 0xF8 vendor INS. No PIN, no sign, no retry consumption. Use this to
# confirm which physical card is the throwaway vs prod (by GUID/serial)
# before running hardware recipes like explore-rust-card-unlock-hw.
[group('debug')]
[linux]
debug-list-piv-cards:
    #!/usr/bin/env bash
    set -euo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    echo "=== pivy-tool list (all visible PIV cards) ==="
    "$pivy_tool" list
    echo
    echo "=== per-card YubiKey serial (0xF8), keyed by GUID ==="
    # Pull each GUID from the list output and query its serial individually.
    "$pivy_tool" list 2>/dev/null | awk '/guid:/ {print $2}' | while read -r g; do
      serial="$("$pivy_tool" -g "$g" list 2>/dev/null | awk '/serial:/ {print $2; exit}')"
      printf '  guid %s  serial %s\n' "$g" "${serial:-<not reported>}"
    done

# DIAGNOSTIC (piggy#56) — hold an SCardBeginTransaction lock on the card at
# <guid> for <secs>s via the piggy-piv hold_lock example, so a co-resident
# client must block on the lock. Read-only (no PIN). Kill/Ctrl-C to release.
[group('debug')]
[linux]
debug-hold-card-lock guid="5DA19C98257243EFCD29BE3AE91EA7F8" secs="3600":
    cargo run -q -p piggy-piv --example hold_lock -- "{{guid}}" "{{secs}}"

# DIAGNOSTIC (piggy#56) — run the faithful reset-loop contender standalone
# for <secs>s and report how many begin+verify+end(ResetCard) cycles it
# completes. Confirms the contender actually exercises the card (a low/zero
# count would mean the "race" tests had no real reset contention). HARDWARE;
# verifies the PIN repeatedly (correct PIN does not decrement the counter).
[group('debug')]
[linux]
debug-reset-loop guid="5DA19C98257243EFCD29BE3AE91EA7F8" pin="123456" secs="5":
    cargo run -q -p piggy-piv --example reset_loop -- "{{guid}}" "{{pin}}" "{{secs}}"

# DIAGNOSTIC (piggy#56) — is a second client's card lock actually visible to
# other clients on the throwaway, or do they run in isolation? Holds an
# SCardBeginTransaction (the hold_lock example) on <guid>, then checks
# whether `pivy-tool ecdh 9d` BLOCKS on that lock (times out) and runs once
# the holder is killed. A clean block→unblock proves lock-level contention
# is REAL on this card (=> a non-reproducing reset race is a reset-semantics
# issue, e.g. deferred disconnect-reset — switch the contender to a real
# pivy-agent). Instant success despite the held lock means the clients are
# NOT sharing the card (deeper isolation; the race test was hollow).
# HARDWARE; the lock-hold is read-only, the ecdh probe verifies the PIN once.
[group('debug')]
[linux]
debug-lock-contention-probe guid="5DA19C98257243EFCD29BE3AE91EA7F8" pin="123456": build-rust
    #!/usr/bin/env bash
    set -uo pipefail
    guid="{{guid}}"; pin="{{pin}}"
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"

    tmpdir=$(mktemp -d /tmp/piggy-lockprobe.XXXXXX)
    pub="$tmpdir/9d.pub"; hold_log="$tmpdir/hold.log"; hold_pid=""
    cleanup() { [[ -n "$hold_pid" ]] && kill "$hold_pid" 2>/dev/null || true; rm -rf "$tmpdir"; }
    trap cleanup EXIT

    "$pivy_tool" -g "$guid" pubkey 9d >"$pub" 2>/dev/null || { echo "no 9d key on $guid"; exit 1; }

    echo "=== starting lock holder (SCardBeginTransaction, never releases) ==="
    cargo run -q -p piggy-piv --example hold_lock -- "$guid" 120 >"$hold_log" 2>&1 &
    hold_pid=$!
    for _ in $(seq 1 120); do grep -q HOLDING "$hold_log" 2>/dev/null && break; sleep 0.5; done
    if ! grep -q HOLDING "$hold_log" 2>/dev/null; then
      echo "holder never acquired the lock:"; cat "$hold_log"; exit 1
    fi
    echo "  holder holds the lock (pid $hold_pid)"

    echo "=== Test 1: pivy-tool ecdh WHILE lock held (expect BLOCK -> timeout) ==="
    if timeout 8 "$pivy_tool" -g "$guid" -P "$pin" ecdh 9d <"$pub" >/dev/null 2>&1; then
      echo "  pivy-tool ecdh SUCCEEDED despite the held lock"; locked_blocks=no
    else
      echo "  pivy-tool ecdh did NOT complete (rc=$?; 124=timeout) while the lock was held"; locked_blocks=yes
    fi

    echo "=== releasing the lock (kill holder) ==="
    kill "$hold_pid" 2>/dev/null || true; wait "$hold_pid" 2>/dev/null || true; hold_pid=""
    sleep 1

    echo "=== Test 2: pivy-tool ecdh with lock RELEASED (expect SUCCESS) ==="
    if timeout 8 "$pivy_tool" -g "$guid" -P "$pin" ecdh 9d <"$pub" >/dev/null 2>&1; then
      echo "  pivy-tool ecdh SUCCEEDED after release"; freed_ok=yes
    else
      echo "  pivy-tool ecdh still failing after release (rc=$?) — unexpected"; freed_ok=no
    fi

    echo
    echo "=== conclusion ==="
    if [[ "${locked_blocks:-}" == yes && "${freed_ok:-}" == yes ]]; then
      echo "Lock-level contention is REAL (blocked while held, ran when freed)."
      echo "=> the race not reproducing is a RESET-semantics issue; switch the"
      echo "   contender to a real pivy-agent (persistent conn + end-txn reset)."
    elif [[ "${locked_blocks:-}" == no ]]; then
      echo "Clients are NOT sharing the card lock — deeper isolation; the race test was hollow."
    else
      echo "Inconclusive — see output above."
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

[group('maintenance')]
update: update-nix

[group('maintenance')]
update-nix:
    nix flake update

[group('maintenance')]
clean: clean-build clean-rust

[group('maintenance')]
clean-build:
    rm -rf result

[group('maintenance')]
clean-rust:
    cargo clean

# --- maintenance: version bump + tag + release ---
#
# Three recipes per eng-versioning(7). `version.env` is the single
# source of truth: `bump-version` is a pure mutation, `tag` reads the
# current value and pushes a signed tag, `release` orchestrates the
# whole flow (changelog → bump → commit → tag → gh release).
# `version.env` is also read by `flake.nix` at eval time and by
# `crates/piggy/build.rs` at compile time.
#
# Grouped under the canonical `maintenance` lifecycle group of
# eng-design_patterns-justfile(7) (alongside update-*/clean-*);
# eng-versioning(7) still says "maint" — reconciling that wording
# onto `maintenance` is tracked at amarbel-llc/eng#122.

# Rewrite the PIGGY_VERSION line in version.env. Touches no other
# file — committing is `release`'s job. Usage: just bump-version 0.1.1
[group('maintenance')]
bump-version new_version:
    sed -E -i "s/^(export PIGGY_VERSION)=.*/\1={{new_version}}/" version.env

# Sign + push a tag named after the current version.env. The "v"
# prefix is added for you. Usage: just tag "release v0.1.1"
[group('maintenance')]
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
[group('maintenance')]
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

# Factory-reset a YubiKey 4 throwaway so its PIV applet is wiped and the
# CHUID GUID rolls. DESTRUCTIVE — the recipe refuses to run unless the
# inserted card reports firmware 4.x (so an accidentally-inserted YK5
# primary is not blocked/reset). Sequence: 3 wrong PIN attempts to block
# PIN → 3 wrong PUK attempts to block PUK → --action=reset → re-probe
# status. Serves the fibby #134 test-vector capture dev-loop.
[group('debug')]
debug-yk-throwaway-reset:
    #!/usr/bin/env bash
    set -uo pipefail
    unset PCSCLITE_CSOCK_NAME  # talk to system pcscd, not fibby
    status=$(yubico-piv-tool --action=status 2>&1) || {
      echo "ERROR: yubico-piv-tool --action=status failed:" >&2
      echo "$status" >&2
      exit 1
    }
    version=$(echo "$status" | awk '/^Version:/ {print $2}')
    serial=$(echo "$status" | awk '/^Serial Number:/ {print $3}')
    if [[ "$version" != 4.* ]]; then
      echo "ERROR: refusing to reset — firmware '$version' is not 4.x" >&2
      echo "this recipe is hard-coded for the throwaway YK4; primary YK5 must be swapped out" >&2
      exit 1
    fi
    echo "Pre-reset: firmware=$version serial=$serial"
    echo
    echo "=== Blocking PIN with 3 wrong attempts ==="
    for _ in 1 2 3; do
      yubico-piv-tool --action=verify-pin --pin=000000 2>&1 || true
    done
    echo
    echo "=== Blocking PUK with 3 wrong attempts ==="
    for _ in 1 2 3; do
      yubico-piv-tool --action=change-puk -P 00000000 -N 11111111 2>&1 || true
    done
    echo
    echo "=== Running reset ==="
    yubico-piv-tool --action=reset
    echo
    echo "=== Post-reset status ==="
    yubico-piv-tool --action=status

# Import the RFC 6979 §A.2.5 P-256 test-vector key into slot 9D of a
# freshly-reset throwaway YK4, so subsequent GA ECDH wire captures are
# byte-deterministic against any VirtualCard implementation that uses
# the same scalar. DESTRUCTIVE — overwrites slot 9D. Requires the card
# to be at factory mgmt-key (auto on freshly-reset card). Same 4.x
# firmware safety as debug-yk-throwaway-reset. Serves the fibby #134
# test-vector capture dev-loop.
[group('debug')]
debug-yk-throwaway-import-rfc6979:
    #!/usr/bin/env bash
    set -uo pipefail
    unset PCSCLITE_CSOCK_NAME
    status=$(yubico-piv-tool --action=status 2>&1) || {
      echo "ERROR: yubico-piv-tool --action=status failed:" >&2
      echo "$status" >&2
      exit 1
    }
    version=$(echo "$status" | awk '/^Version:/ {print $2}')
    if [[ "$version" != 4.* ]]; then
      echo "ERROR: refusing to import — firmware '$version' is not 4.x" >&2
      exit 1
    fi
    pem="crates/fibby/tests/fixtures/test-vectors/rfc6979-a-2-5-priv.pem"
    if [[ ! -f "$pem" ]]; then
      echo "ERROR: test-vector PEM not found: $pem" >&2
      exit 1
    fi
    echo "Importing $pem to slot 9d (algorithm ECCP256)..."
    yubico-piv-tool \
      --action=import-key \
      --slot=9d \
      --algorithm=ECCP256 \
      --key-format=PEM \
      --input="$pem"
    echo
    echo "=== Post-import status ==="
    yubico-piv-tool --action=status

# Phase 0 smoke probe for piggy#135: stand up fibby with the virtual
# backend, point pivy-agent at it via PCSCLITE_CSOCK_NAME, and run
# `ssh-add -L` against the agent. Dumps the wire trace + agent stderr
# inline so the dev-loop sees what pivy-agent expects from a PIV card
# that VirtualCard doesn't yet provide (slot cert objects, mgmt-key
# validation, etc.). Read-only on the host; no hardware involved.
# Hard-kills both children on exit; safe to re-run repeatedly.
#
# Both binaries come from nix derivations (.#pivy + .#fibby); matches
# the production wire surface and avoids stale target/debug artifacts.
# The CI gate for this same probe lives at
# `test-bats-conformance-fibby-pivy-agent-smoke`.
[group('debug')]
debug-fibby-pivy-agent-smoke:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_agent ]] || { echo "missing $pivy_agent"; exit 1; }

    # Short-path workdir under /tmp so AF_UNIX sun_path doesn't overflow
    # (108 bytes Linux / 104 darwin). $BATS_TEST_TMPDIR-style nesting
    # would overflow against $TMPDIR inside the spinclass worktree.
    workdir=$(mktemp -d /tmp/p0-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"

    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual backend, Yk4 model, empty slots) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do
      [[ -S $fibby_sock ]] && break
      sleep 0.1
    done
    if [[ ! -S $fibby_sock ]]; then
      echo "fibby socket never appeared:" >&2
      cat "$fibby_log" >&2 || true
      exit 1
    fi
    echo "fibby up (pid=$fibby_pid, socket=$fibby_sock)"
    echo

    # Refusal askpass: any PIN prompt should be visible as a banner in
    # stderr, never a GUI dialog. We don't supply PIGGY_TEST_FIB_PIN
    # because the smoke shouldn't reach a PIN-gated path.
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"

    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" \
      SSH_ASKPASS_REQUIRE=force \
      DISPLAY="" \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do
      [[ -S $agent_sock ]] && break
      sleep 0.1
    done
    if [[ ! -S $agent_sock ]]; then
      echo "agent socket never appeared:" >&2
      echo "--- agent log ---" >&2
      cat "$agent_log" >&2 || true
      echo "--- fibby log ---" >&2
      cat "$fibby_log" >&2 || true
      exit 1
    fi
    echo "pivy-agent up (pid=$agent_pid, socket=$agent_sock)"
    echo

    echo "=== Probe: ssh-add -L ==="
    SSH_AUTH_SOCK="$agent_sock" ssh-add -L
    add_status=$?
    echo "(exit=$add_status)"
    echo

    echo "=== pivy-agent stderr ==="
    cat "$agent_log"
    echo

    echo "=== fibby wire trace (last 80 lines) ==="
    tail -80 "$fibby_log"

# piggy#135 slot-9A sign dev-loop: a non-batman mirror of the
# `pivy_agent_signs_and_verifies_via_seeded_fibby_slot_9a` bats test. Seeds
# fibby's slot 9A (cert + RFC 6979 §A.2.5 key), points pivy-agent at it,
# and drives a real `ssh-keygen -Y sign -U` (agent-sign) + verify
# round-trip — proving the slot-9A ECDSA sign path works end-to-end through
# pivy-agent. Runs OUTSIDE batman so it works in dev containers where the
# batman/sandcastle wrapper can't create namespaces (piggy#136 /
# amarbel-llc/bats#31). Supplies the VirtualCard default PIN
# non-interactively. Exits non-zero on any failure. No hardware.
[group('debug')]
debug-fibby-slot-9a-sign:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_agent ]] || { echo "missing $pivy_agent"; exit 1; }

    workdir=$(mktemp -d /tmp/p0sign-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-rfc6979-slot-9a-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc6979-slot-9a-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    # Supply the VirtualCard default PIN non-interactively so pivy-agent
    # can unlock the slot-9A sign (PIN policy "once").
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    export SSH_AUTH_SOCK="$agent_sock"
    echo "=== ssh-add -L ==="
    ssh-add -L | tee "$workdir/all.pub"
    grep '^ecdsa-sha2-nistp256 ' "$workdir/all.pub" >"$workdir/id.pub" || {
      echo "no ecdsa-sha2-nistp256 identity"; cat "$agent_log"; exit 1; }

    echo "phase0-fibby-slot-9a-sign-smoke" >"$workdir/data"
    read -r ktype kdata _ <"$workdir/id.pub"
    printf 'smoke@fibby %s %s\n' "$ktype" "$kdata" >"$workdir/allowed_signers"

    echo "=== ssh-keygen -Y sign (agent-sign via slot 9A) ==="
    if ! ssh-keygen -Y sign -f "$workdir/id.pub" -U -n file "$workdir/data"; then
      echo "!!! SIGN FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    echo "=== ssh-keygen -Y verify ==="
    if ! ssh-keygen -Y verify -f "$workdir/allowed_signers" -I smoke@fibby \
        -n file -s "$workdir/data.sig" <"$workdir/data"; then
      echo "!!! VERIFY FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    grep -q "GA ECDSA 9A -> 9000" "$fibby_log" || {
      echo "!!! no successful slot-9A GA ECDSA sign in fibby trace"
      tail -80 "$fibby_log"; exit 1; }
    echo
    echo "=== SLOT-9A SIGN ROUND-TRIP OK ==="

# piggy#135 Phase A+B smoke: build piggy-test-sshd, start it (RFC-0001
# handshake over stdout, shutdown on stdin EOF), then (A) connect with an
# ephemeral key and assert a remote `exec`'s stdout + exit-status
# propagate, and (B) connect with agent forwarding (`ssh -A`) and assert
# the remote side sees the forwarded key via `ssh-add -l`. No fibby yet —
# that's Phase D. Exits non-zero on any failure. No hardware.
[group('debug')]
debug-piggy-test-sshd:
    #!/usr/bin/env bash
    set -uo pipefail
    sshd_out=$(nix build .#piggy-test-sshd --no-link --print-out-paths)
    sshd_bin="$sshd_out/bin/piggy-test-sshd"
    [[ -x $sshd_bin ]] || { echo "missing $sshd_bin"; exit 1; }

    workdir=$(mktemp -d /tmp/p135a-XXXXXX)
    hs="$workdir/handshake"
    err="$workdir/stderr"
    fifo="$workdir/stdin.fifo"
    mkfifo "$fifo"
    cookie=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')

    sshd_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $sshd_pid ]] && kill "$sshd_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      exec 9>&- 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    # Start the server with stdin from a fifo so we control EOF (= the
    # RFC-0001 shutdown signal). The child blocks opening the fifo for
    # read until we open it for write on fd 9.
    PIGGY_PLUGIN_COOKIE="$cookie" "$sshd_bin" <"$fifo" >"$hs" 2>"$err" &
    sshd_pid=$!
    exec 9>"$fifo"

    for _ in $(seq 1 50); do [[ -s $hs ]] && break; sleep 0.1; done
    [[ -s $hs ]] || { echo "no handshake line; stderr:"; cat "$err"; exit 1; }
    line=$(head -1 "$hs")
    echo "handshake: $line"

    IFS='|' read -r got_cookie version _transport addr kh_field subproto <<<"$line"
    [[ $got_cookie == "$cookie" ]] || { echo "cookie mismatch"; exit 1; }
    [[ $version == 1 ]] || { echo "version: $version"; exit 1; }
    [[ $subproto == ssh ]] || { echo "subproto: $subproto"; exit 1; }
    port="${addr##*:}"
    kh="${kh_field#known_hosts=}"
    [[ -s $kh ]] || { echo "known_hosts missing: $kh"; exit 1; }

    key="$workdir/id"
    ssh-keygen -t ed25519 -N '' -f "$key" -q

    # Env isolation: run the ssh client with a pristine HOME under
    # `env -i` so the test neither inherits nor fights the operator's ssh
    # config or the home-manager ssh wrapper (which injects
    # `-o UserKnownHostsFile=$SSH_HOME/known_hosts -F $SSH_HOME/config`,
    # winning over our flags via ssh's first-wins -o rule). Both stock
    # ssh ($HOME/.ssh/known_hosts) and the wrapper ($SSH_HOME) then read
    # our ephemeral known_hosts. PATH is preserved so `ssh` resolves.
    client_home="$workdir/clienthome"
    mkdir -p "$client_home/.ssh"
    chmod 700 "$client_home/.ssh"
    cp "$kh" "$client_home/.ssh/known_hosts"
    : >"$client_home/.ssh/config"

    echo "=== remote exec (echo + exit 7) ==="
    out=$(env -i \
      HOME="$client_home" \
      SSH_HOME="$client_home/.ssh" \
      PATH="$PATH" \
      ssh -i "$key" \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o BatchMode=yes \
        -p "$port" testuser@127.0.0.1 \
        'echo hello-from-piggy-sshd; exit 7')
    rc=$?
    echo "stdout: $out"
    echo "exit:   $rc"
    [[ $out == hello-from-piggy-sshd ]] || { echo "!!! unexpected stdout"; cat "$err"; exit 1; }
    [[ $rc -eq 7 ]] || { echo "!!! exit-status not propagated (want 7, got $rc)"; cat "$err"; exit 1; }
    echo "=== PHASE A (exec) OK ==="
    echo

    # --- Phase B: agent forwarding ---
    # Stand up a throwaway local ssh-agent holding the same ephemeral key,
    # connect with `ssh -A`, and confirm the remote `ssh-add -l` (talking
    # to the SSH_AUTH_SOCK piggy-test-sshd injected) sees the key — i.e.
    # the agent channel is forwarded all the way back to our agent.
    agentsock="$workdir/agent.sock"
    eval "$(ssh-agent -a "$agentsock")" >/dev/null
    agent_pid="${SSH_AGENT_PID:-}"
    SSH_AUTH_SOCK="$agentsock" ssh-add "$key" 2>/dev/null
    fp=$(ssh-keygen -lf "$key.pub" | awk '{print $2}')
    echo "local key fingerprint: $fp"

    echo "=== remote ssh-add -l over forwarded agent ==="
    remote_keys=$(env -i \
      HOME="$client_home" \
      SSH_HOME="$client_home/.ssh" \
      SSH_AUTH_SOCK="$agentsock" \
      PATH="$PATH" \
      ssh -A -i "$key" \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o BatchMode=yes \
        -p "$port" testuser@127.0.0.1 \
        'ssh-add -l')
    echo "remote: $remote_keys"
    grep -qF "$fp" <<<"$remote_keys" || {
      echo "!!! forwarded agent did not expose the key"; cat "$err"; exit 1; }
    echo "=== PHASE B (agent forwarding) OK ==="
    echo
    echo "=== PHASE A+B SMOKE OK ==="

# piggy#138 repro: the SSH-forwarded-style agent decrypt against fibby's
# virtual slot-9D. Stands up fibby (virtual, --seed-rfc5903-slot-9d-cert
# + CHUID), points pivy-agent at it (PCSCLITE_CSOCK_NAME), builds a piggy
# store (init + insert — both client-side / direct to fibby), then runs
# `piggy pass show` with PIGGY_AUTH_SOCK=<agent> so the decrypt routes
# through the C `pivy-box stream decrypt` → `piv_box_open_agent`
# ecdh-rebox path (NOT the direct-PCSC path). Dumps the TRACE-level agent
# log + fibby wire trace. No hardware, no SSH transport — this is the
# minimal (transport-free) reproduction of the failing combination from
# #138's 3-axis bisection: C rebox client + on-demand agent unlock +
# fibby. Exits 0 if the decrypt round-trips, non-zero (reproducing #138)
# otherwise.
[group('debug')]
debug-ssh-via-fibby GDB="":
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    pivy_tool="$pivy_out/bin/pivy-tool"
    fibby_bin="$fibby_out/bin/fibby"
    piggy_bin="$piggy_out/bin/piggy"
    for b in "$pivy_agent" "$pivy_tool" "$fibby_bin" "$piggy_bin"; do
      [[ -x $b ]] || { echo "missing $b"; exit 1; }
    done

    workdir=$(mktemp -d /tmp/p138-XXXXXX)
    keepdir=/tmp/p138-last
    rm -rf "$keepdir"; mkdir -p "$keepdir"
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    export PIGGY_STORE_DIR="$workdir/store"
    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      # Preserve logs under a stable path for post-mortem (the agent
      # SIGABRTs on the #138 bug; its stderr holds the fatal line).
      cp "$agent_log" "$fibby_log" "$workdir/show.err" "$keepdir/" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    # Test askpass: hands the agent the VirtualCard default PIN (123456)
    # non-interactively so slot 9D can unlock on-demand during the rebox.
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"

    echo "=== Starting pivy-agent (-A -d TRACE, PCSCLITE_CSOCK_NAME=fibby) ==="
    # Passing GDB=1 (`just debug-ssh-via-fibby 1`) wraps the agent in
    # gdb --batch so the SIGABRT (the #138 bug) is caught and a backtrace
    # lands in the agent log. Requires gdb on PATH; symbols depend on the
    # pivy build (see nix/pivy.nix).
    agent_argv=("$pivy_agent" -A -d -a "$agent_sock")
    if [[ -n "{{ GDB }}" ]]; then
      # gdb can't exec pivy's makeWrapper shell shim — target the real
      # ELF (.pivy-agent-unwrapped, not stripped) and replicate the
      # wrapper's libpcsclite LD_PRELOAD ourselves.
      agent_unwrapped="${pivy_agent%/pivy-agent}/.pivy-agent-unwrapped"
      [[ -x $agent_unwrapped ]] || { echo "missing $agent_unwrapped"; exit 1; }
      for lib in /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 \
                 /usr/lib/libpcsclite.so.1 /lib/x86_64-linux-gnu/libpcsclite.so.1; do
        [[ -e $lib ]] && { export LD_PRELOAD="$lib${LD_PRELOAD:+:$LD_PRELOAD}"; break; }
      done
      agent_argv=(gdb -q -batch \
        -ex 'set pagination off' \
        -ex 'set print frame-arguments all' \
        -ex run \
        -ex 'printf "\n=== BACKTRACE ===\n"' \
        -ex 'bt' \
        -ex 'printf "\n=== BACKTRACE FULL ===\n"' \
        -ex 'bt full' \
        --args "$agent_unwrapped" -A -d -a "$agent_sock")
    fi
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "${agent_argv[@]}" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    echo "=== discover GUID via pivy-tool list (through fibby) ==="
    guid=$(PCSCLITE_CSOCK_NAME="$fibby_sock" "$pivy_tool" list 2>&1 | grep -oiE '[0-9a-f]{32}' | head -1)
    [[ -n $guid ]] || { echo "no GUID found"; cat "$fibby_log"; exit 1; }
    echo "  guid: $guid"

    echo "=== piggy pass init -g $guid (direct to fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" "$piggy_bin" pass init -g "$guid" \
      || { echo "init failed"; tail -40 "$fibby_log"; exit 1; }

    plaintext="secret-via-fibby-138"
    echo "=== piggy pass insert -e foo/bar (direct to fibby) ==="
    printf '%s\n' "$plaintext" | PCSCLITE_CSOCK_NAME="$fibby_sock" \
      "$piggy_bin" pass insert -e foo/bar \
      || { echo "insert failed"; tail -40 "$fibby_log"; exit 1; }

    # Decrypt via the agent. PIGGY_AUTH_SOCK overrides SSH_AUTH_SOCK for
    # piggy's own pivy-box child only, so the decrypt hits piv_box_open_agent
    # (rebox) against the agent, NOT fibby's direct-PCSC path. PCSCLITE_CSOCK_NAME
    # is intentionally NOT set here, mirroring the SSH-remote side that has
    # no fibby socket of its own.
    echo "=== piggy pass show foo/bar (PIGGY_AUTH_SOCK=agent → rebox path) ==="
    got=$(PIGGY_AUTH_SOCK="$agent_sock" "$piggy_bin" pass show foo/bar 2>"$workdir/show.err")
    show_rc=$?
    echo "  show exit: $show_rc"
    echo "  show stderr:"; sed 's/^/    /' "$workdir/show.err"
    echo "  got: '$got'"
    echo
    if grep -q '=== BACKTRACE ===' "$agent_log"; then
      echo "=== pivy-agent gdb backtrace ==="
      sed -n '/=== BACKTRACE ===/,$p' "$agent_log"
      echo
    fi
    echo "=== agent crash / extension lines (grep) ==="
    grep -nE 'FATAL|fatal|assert|VERIFY|abort|panic|rebox|ecdh|EXTENSION|extension|failed to process' "$agent_log" || true
    echo
    echo "=== pivy-agent log (last 30 lines) ==="
    tail -30 "$agent_log"
    echo
    echo "=== logs preserved under $keepdir ==="

    if [[ $show_rc -eq 0 && $got == "$plaintext" ]]; then
      echo "=== DECRYPT OK (rebox path works) ==="
      exit 0
    else
      echo "=== DECRYPT FAILED — reproduces #138 ==="
      exit 1
    fi

# piggy#135 Phase D: end-to-end SSH-forwarded decrypt — the realistic
# deployment shape this whole arc is about. Stands up the full stack:
# fibby (virtual, seeded slot-9D ECDH cert) + pivy-agent over fibby + a
# piggy store (init + insert, direct to fibby) + the piggy-test-sshd
# fixture server. Then runs a *remote* `piggy pass show` over `ssh -A`,
# so the decrypt routes through the FORWARDED agent socket back to
# pivy-agent ↔ fibby (not a direct path). No hardware. Exits 0 iff the
# remote decrypt round-trips. This is the debug-recipe scaffold for the
# Phase D bats lane (conformance/piggy_ssh_via_fibby.bats).
[group('debug')]
debug-ssh-decrypt-via-fibby:
    #!/usr/bin/env bash
    set -uo pipefail
    unset PIGGY_AUTH_SOCK  # the remote must use the FORWARDED SSH_AUTH_SOCK
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    piggy_out=$(nix build .#default --no-link --print-out-paths)
    sshd_out=$(nix build .#piggy-test-sshd --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    piggy_bin="$piggy_out/bin/piggy"
    sshd_bin="$sshd_out/bin/piggy-test-sshd"
    for b in "$pivy_agent" "$fibby_bin" "$piggy_bin" "$sshd_bin"; do
      [[ -x $b ]] || { echo "missing $b"; exit 1; }
    done

    workdir=$(mktemp -d /tmp/p135d-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    sshd_hs="$workdir/handshake"
    sshd_err="$workdir/sshd.err"
    sshd_fifo="$workdir/sshd.fifo"
    store="$workdir/store"
    fibby_pid=""; agent_pid=""; sshd_pid=""
    cleanup() {
      [[ -n $sshd_pid ]] && kill "$sshd_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      exec 9>&- 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-rfc5903-slot-9d-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-rfc5903-slot-9d-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    # pivy-agent unlocks slot 9D on-demand during the (forwarded) rebox via
    # the test askpass; the unlock happens at this local agent process, the
    # SSH channel only proxies the agent protocol.
    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    echo "=== piggy pass init + insert (direct to fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" PIGGY_STORE_DIR="$store" \
      "$piggy_bin" pass init || { echo "init failed"; tail -40 "$fibby_log"; exit 1; }
    plaintext="ssh-forwarded-decrypt-135d"
    printf '%s\n' "$plaintext" | PCSCLITE_CSOCK_NAME="$fibby_sock" \
      PIGGY_STORE_DIR="$store" "$piggy_bin" pass insert -e foo/bar \
      || { echo "insert failed"; tail -40 "$fibby_log"; exit 1; }

    # piggy-test-sshd: RFC-0001 handshake on stdout, shutdown on stdin EOF.
    mkfifo "$sshd_fifo"
    cookie=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    echo "=== Starting piggy-test-sshd ==="
    PIGGY_PLUGIN_COOKIE="$cookie" "$sshd_bin" <"$sshd_fifo" >"$sshd_hs" 2>"$sshd_err" &
    sshd_pid=$!
    exec 9>"$sshd_fifo"
    for _ in $(seq 1 50); do [[ -s $sshd_hs ]] && break; sleep 0.1; done
    [[ -s $sshd_hs ]] || { echo "no sshd handshake; stderr:"; cat "$sshd_err"; exit 1; }
    line=$(head -1 "$sshd_hs")
    IFS='|' read -r got_cookie _version _transport addr kh_field _subproto <<<"$line"
    [[ $got_cookie == "$cookie" ]] || { echo "cookie mismatch"; exit 1; }
    port="${addr##*:}"
    kh="${kh_field#known_hosts=}"
    [[ -s $kh ]] || { echo "known_hosts missing: $kh"; exit 1; }

    key="$workdir/id"
    ssh-keygen -t ed25519 -N '' -f "$key" -q
    client_home="$workdir/clienthome"
    mkdir -p "$client_home/.ssh"; chmod 700 "$client_home/.ssh"
    cp "$kh" "$client_home/.ssh/known_hosts"
    : >"$client_home/.ssh/config"

    # `ssh -A` forwards THIS shell's SSH_AUTH_SOCK (= pivy-agent). The
    # server injects a forwarded SSH_AUTH_SOCK into the remote command's
    # env; PIGGY_AUTH_SOCK is unset, so the remote piggy decrypts through
    # the forwarded socket → SSH channel → pivy-agent ↔ fibby.
    echo "=== ssh -A remote 'piggy pass show foo/bar' (forwarded decrypt) ==="
    remote_out=$(env -i \
      HOME="$client_home" \
      SSH_HOME="$client_home/.ssh" \
      SSH_AUTH_SOCK="$agent_sock" \
      PATH="$PATH" \
      ssh -A -i "$key" \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o BatchMode=yes \
        -p "$port" testuser@127.0.0.1 \
        "PIGGY_STORE_DIR=$store $piggy_bin pass show foo/bar")
    rc=$?
    echo "  ssh exit: $rc"
    echo "  remote stdout: $remote_out"
    echo

    if [[ $rc -eq 0 ]] && printf '%s\n' "$remote_out" | grep -Fxq "$plaintext"; then
      echo "=== PHASE D SSH-FORWARDED DECRYPT OK ==="
      exit 0
    else
      echo "=== PHASE D FAILED ==="
      echo "--- agent log tail ---"; tail -60 "$agent_log"
      echo "--- fibby log tail ---"; tail -60 "$fibby_log"
      echo "--- sshd stderr ---"; cat "$sshd_err"
      exit 1
    fi

# piggy#135: regenerate fibby's slot-9C (Digital Signature) test cert. One-shot
# generator — produces a FRESH P-256 key each run. The slot-9C SIGN path uses
# RFC 6979 deterministic ECDSA, so (unlike 9D's ECDH, piggy#134) there is no
# captured wire to byte-replay against: a published vector isn't required, only
# a key distinct from 9A (§A.2.5) and 9D (§8.1). Saves the key PEM under
# tests/fixtures/test-vectors/ as the reproducibility anchor and prints Rust
# byte arrays (scalar + PIV cert-object) to paste into virtual_card.rs as
# FIBBY_SLOT_9C_TEST_PRIV / FIBBY_SLOT_9C_CERT_OBJECT. The cert's ECDSA sig
# uses a random k, so re-running re-pins the const — only do so deliberately.
# Cross-check the printed pubkey is distinct from the 9A/9D points.
[group('debug')]
debug-fibby-gen-slot-9c-cert:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="crates/fibby/tests/fixtures/test-vectors"
    pem="$dir/fibby-slot-9c-test-priv.pem"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    # Generate until the raw scalar is exactly 32 bytes (64 hex) so the text
    # extraction below is unambiguous (no leading-zero short form).
    scalar=""
    for _ in $(seq 1 16); do
      openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/key.pem"
      scalar=$(openssl pkey -in "$tmp/key.pem" -text -noout 2>/dev/null \
        | sed -n '/priv:/,/pub:/{/priv:/d;/pub:/d;p}' | tr -dc '0-9a-f')
      [[ ${#scalar} -eq 64 ]] && break
      scalar=""
    done
    [[ ${#scalar} -eq 64 ]] || { echo "could not extract a 32-byte scalar" >&2; exit 1; }

    # Self-sign the cert (fixed subject + serial; 100-year validity).
    openssl req -x509 -key "$tmp/key.pem" -subj "/CN=fibby-test-slot-9c" \
      -set_serial 1 -days 36500 -sha256 -outform DER -out "$tmp/cert.der"
    der=$(od -An -tx1 "$tmp/cert.der" | tr -dc '0-9a-f')
    der_len=$(( ${#der} / 2 ))

    ber_len() { # echo BER length bytes (hex) for $1
      local n=$1
      if [[ $n -lt 128 ]]; then printf '%02x' "$n"
      elif [[ $n -lt 256 ]]; then printf '81%02x' "$n"
      else printf '82%02x%02x' $(( (n >> 8) & 255 )) $(( n & 255 )); fi
    }

    # PIV cert object TLV: 53 L1 [ 70 L2 <DER> 71 01 00  FE 00 ]
    inner="70$(ber_len "$der_len")${der}710100fe00"
    inner_len=$(( ${#inner} / 2 ))
    obj="53$(ber_len "$inner_len")${inner}"

    rust_array() { fold -w2 | awk 'BEGIN{ORS=""}{printf "0x%s, ", toupper($0)}'; echo; }

    cp "$tmp/key.pem" "$pem"
    echo "=== wrote $pem ==="
    echo
    echo "=== pubkey (verify DISTINCT from 9A 60FED4BA… / 9D DAD0B653…) ==="
    openssl pkey -in "$pem" -text -noout 2>/dev/null | sed -n '/pub:/,/ASN1 OID/p'
    echo
    echo "=== FIBBY_SLOT_9C_TEST_PRIV (32 bytes) ==="
    printf '%s' "$scalar" | rust_array
    echo
    echo "=== FIBBY_SLOT_9C_CERT_OBJECT ($(( ${#obj} / 2 )) bytes) ==="
    printf '%s' "$obj" | rust_array

# piggy#135 slot-9C sign dev-loop: a non-batman mirror of the
# `pivy_agent_signs_and_verifies_via_seeded_fibby_slot_9c` bats test. Seeds
# fibby's slot 9C (cert + key), points pivy-agent at it, and drives a real
# `ssh-keygen -Y sign -U` + verify round-trip — proving the slot-9C ECDSA sign
# path works end-to-end through pivy-agent. Supplies the VirtualCard PIN
# non-interactively. Exits non-zero on any failure. No hardware.
[group('debug')]
debug-fibby-slot-9c-sign:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_agent="$pivy_out/bin/pivy-agent"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_agent ]] || { echo "missing $pivy_agent"; exit 1; }

    workdir=$(mktemp -d /tmp/p9csign-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    agent_sock="$workdir/a.sock"
    fibby_log="$workdir/fibby.log"
    agent_log="$workdir/agent.log"
    fibby_pid=""
    agent_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      [[ -n $agent_pid ]] && kill "$agent_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-slot-9c-cert) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-slot-9c-cert >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    askpass="$PWD/zz-tests_bats/helpers/piggy-test-askpass.sh"
    echo "=== Starting pivy-agent (PCSCLITE_CSOCK_NAME=fibby) ==="
    PCSCLITE_CSOCK_NAME="$fibby_sock" \
      SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY="" \
      PIGGY_TEST_FIB_PIN=123456 \
      "$pivy_agent" -A -D -a "$agent_sock" >"$agent_log" 2>&1 &
    agent_pid=$!
    for _ in $(seq 1 50); do [[ -S $agent_sock ]] && break; sleep 0.1; done
    [[ -S $agent_sock ]] || { echo "agent socket never appeared:"; cat "$agent_log"; cat "$fibby_log"; exit 1; }

    export SSH_AUTH_SOCK="$agent_sock"
    ssh-add -L >"$workdir/id.pub" 2>/dev/null
    grep -q '^ecdsa-sha2-nistp256 ' "$workdir/id.pub" || {
      echo "no ecdsa-sha2-nistp256 identity"; cat "$agent_log"; exit 1; }

    echo "phase-fibby-slot-9c-sign-smoke" >"$workdir/data"
    read -r ktype kdata _ <"$workdir/id.pub"
    printf 'smoke@fibby %s %s\n' "$ktype" "$kdata" >"$workdir/allowed_signers"

    echo "=== ssh-keygen -Y sign (agent-sign via slot 9C) ==="
    if ! ssh-keygen -Y sign -f "$workdir/id.pub" -U -n file "$workdir/data"; then
      echo "!!! SIGN FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    echo "=== ssh-keygen -Y verify ==="
    if ! ssh-keygen -Y verify -f "$workdir/allowed_signers" -I smoke@fibby \
        -n file -s "$workdir/data.sig" <"$workdir/data"; then
      echo "!!! VERIFY FAILED"; echo "--- agent log ---"; cat "$agent_log"
      echo "--- fibby trace tail ---"; tail -80 "$fibby_log"; exit 1
    fi

    grep -q "GA ECDSA 9C -> 9000" "$fibby_log" || {
      echo "!!! no successful slot-9C GA ECDSA sign in fibby trace"
      tail -80 "$fibby_log"; exit 1; }
    echo
    echo "=== SLOT-9C SIGN ROUND-TRIP OK ==="

# piggy#135 GENERATE ASYMMETRIC dev-loop: drive the real `pivy-tool generate`
# client against fibby's virtual card to validate the INS 0x47 request/response
# wire format (no captured fixture exists, so the real client accepting fibby's
# 7F49/86 response is the authoritative format check). Stands up fibby virtual
# with just a CHUID (initialized, empty slots), then runs `pivy-tool -K default
# -a eccp256 generate 9a` (SELECT + mgmt-key auth + GENERATE) and asserts it
# prints a public key. Exits non-zero on failure. No hardware.
[group('debug')]
debug-fibby-generate:
    #!/usr/bin/env bash
    set -uo pipefail
    pivy_out=$(nix build .#pivy --no-link --print-out-paths)
    fibby_out=$(nix build .#fibby --no-link --print-out-paths)
    pivy_tool="$pivy_out/bin/pivy-tool"
    fibby_bin="$fibby_out/bin/fibby"
    [[ -x $fibby_bin ]] || { echo "missing $fibby_bin"; exit 1; }
    [[ -x $pivy_tool ]] || { echo "missing $pivy_tool"; exit 1; }

    workdir=$(mktemp -d /tmp/pgen-XXXXXX)
    fibby_sock="$workdir/pcscd.comm"
    fibby_log="$workdir/fibby.log"
    fibby_pid=""
    cleanup() {
      [[ -n $fibby_pid ]] && kill "$fibby_pid" 2>/dev/null || true
      rm -rf "$workdir"
    }
    trap cleanup EXIT

    echo "=== Starting fibby (virtual, --seed-chuid: initialized, empty slots) ==="
    FIBBY_LOG=wire "$fibby_bin" --socket "$fibby_sock" --backend virtual \
      --seed-chuid >"$fibby_log" 2>&1 &
    fibby_pid=$!
    for _ in $(seq 1 50); do [[ -S $fibby_sock ]] && break; sleep 0.1; done
    [[ -S $fibby_sock ]] || { echo "fibby socket never appeared:"; cat "$fibby_log"; exit 1; }

    echo "=== pivy-tool -P 123456 -K default -a eccp256 generate 9a (mgmt-auth + GENERATE) ==="
    # -P supplies the PIN non-interactively; stdin from /dev/null + a timeout
    # so any unexpected interactive prompt fails fast instead of hanging.
    out=$(PCSCLITE_CSOCK_NAME="$fibby_sock" timeout 30 "$pivy_tool" \
      -P 123456 -K default -a eccp256 generate 9a </dev/null 2>&1)
    rc=$?
    echo "$out"
    echo "  pivy-tool exit: $rc"
    echo
    echo "=== fibby wire trace (tail 40) ==="
    tail -40 "$fibby_log"
    echo

    # pivy-tool prints the generated public key as an `ecdsa-sha2-nistp256 ...`
    # SSH line on success.
    if [[ $rc -eq 0 ]] && printf '%s\n' "$out" | grep -q 'ecdsa-sha2-nistp256 ' \
        && grep -q "GENERATE slot=0x9a ECCP256 -> 9000" "$fibby_log"; then
      echo "=== GENERATE OK (pivy-tool generated a key on fibby slot 9A) ==="
      exit 0
    else
      echo "=== GENERATE FAILED ==="
      exit 1
    fi

# Dump the real launchd state of the piggy-agent agent so the `piggy
# health` macOS service probe (point 1) can be grounded in actual
# `launchctl print` output rather than guessed. Read-only: print +
# list only, no load/unload. Serves the piggy-health darwin-service
# design loop.
[macos]
[group('explore')]
explore-launchd-piggy-agent label="piggy-agent":
    #!/usr/bin/env bash
    set -uo pipefail
    uid=$(id -u)
    echo "=== launchctl print gui/$uid/{{label}} ==="
    launchctl print "gui/$uid/{{label}}" 2>&1 || echo "  (exit $?)"
    echo
    echo "=== launchctl list {{label}} (legacy) ==="
    launchctl list "{{label}}" 2>&1 || echo "  (exit $?)"
    echo
    echo "=== launchctl print gui/$uid | grep piggy-agent ==="
    launchctl print "gui/$uid" 2>&1 | grep -i piggy-agent || echo "  (no match)"

# Run the dev `piggy health -v` against the live local agent/cards so the
# macOS launchd service probe (point 1) can be eyeballed end-to-end.
# `-v` forces diags onto passing points; `--format tap` keeps output
# deterministic regardless of tty. Serves the piggy-health verify loop.
[group('explore')]
explore-piggy-health *ARGS:
    cargo run -q -p piggy -- health -v --format tap {{ARGS}}
