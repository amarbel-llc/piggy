#! /usr/bin/env bats
#
# piggy#215 step 3 — end-to-end gate for `piggy agent --upstream`: one
# `SSH_AUTH_SOCK` serving fibby-backed native PIV keys AND proxying a
# real software agent (stock OpenSSH `ssh-agent`).
#
# The stack per test:
#
#   fibby (virtual, seeded slot 9A + CHUID)
#     <- pcsc -> piggy agent --upstream soft=<sock>  <- ssh-add/ssh-keygen
#   ssh-agent -D -a <sock> (an ed25519 software key)  <- proxied
#
# Covered here (the binary-level complement to the in-crate unit tests):
#   - merged listing: native 9A first, software key after
#   - native sign (card via fibby) and routed sign (ssh-agent) both verify
#   - mixed concurrent burst: native + proxied signs interleaved, all
#     succeed (extends the #213 burst gate across the proxy split)
#   - dead upstream degrades: native keys still served
#   - add_identity routing: ssh-add lands the key in the designated
#     upstream; refused without --add-new-keys-to
#
# Required env (supplied by the `test-bats-conformance-agent-upstream`
# recipe):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)
#
# When invoked via the conformance glob without those env vars set, the
# suite gracefully skips — same convention as the sibling fibby lanes.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-agent-upstream"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v ssh-agent >/dev/null || skip "ssh-agent not on PATH"
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  export PIGGY_TEST_FIB_PIN=123456

  # Short-path workdir under /tmp — $BATS_TEST_TMPDIR can overrun AF_UNIX
  # sun_path's 108-byte limit under deep nix sandbox prefixes.
  WORKDIR="$(mktemp -d -t agup.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  SOFT_SOCK="$WORKDIR/s.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=
  SOFT_PID=

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${SOFT_PID:-} ]] && kill "$SOFT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${SOFT_PID:-} ]]; then wait "$SOFT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Start a stock OpenSSH ssh-agent on SOFT_SOCK holding one fresh ed25519
# key (comment "soft-upstream-key"); its pubkey line lands in
# $WORKDIR/soft.pub.
_spawn_soft_agent_with_key() {
  ssh-agent -D -a "$SOFT_SOCK" >/dev/null 2>&1 &
  SOFT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $SOFT_SOCK ]] && break
    sleep 0.1
  done
  [[ -S $SOFT_SOCK ]] || {
    echo "ssh-agent socket never appeared at $SOFT_SOCK" >&2
    return 1
  }
  ssh-keygen -t ed25519 -N '' -q -C "soft-upstream-key" \
    -f "$WORKDIR/softkey" </dev/null
  SSH_AUTH_SOCK="$SOFT_SOCK" ssh-add -q "$WORKDIR/softkey" 2>/dev/null || {
    echo "ssh-add into the software agent failed" >&2
    return 1
  }
  grep '^ssh-ed25519 ' "$WORKDIR/softkey.pub" >"$WORKDIR/soft.pub"
}

# Spawn the Rust `piggy agent` pointed at fibby, proxying SOFT_SOCK as
# upstream "soft". Extra args (e.g. --add-new-keys-to soft) pass through.
_spawn_rust_agent_with_upstream() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent -A \
    --upstream "soft=$SOFT_SOCK" "$@" -a "$AGENT_SOCK" \
    >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && return 0
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  return 1
}

# Bring up the full stack and capture both pubkeys: the agent-served 9A
# (native, $WORKDIR/id9a.pub) and the software key ($WORKDIR/soft.pub).
_stack_up() {
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-chuid
  _spawn_soft_agent_with_key
  _spawn_rust_agent_with_upstream "$@"

  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status against the piggy agent" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" >"$WORKDIR/listing"
  grep '^ecdsa-sha2-nistp256 ' "$WORKDIR/listing" >"$WORKDIR/id9a.pub" || {
    echo "no native 9A identity in merged listing" >&2
    cat "$WORKDIR/listing" >&2
    return 1
  }
}

# Sign $2 with pubkey file $1 via the piggy agent socket and verify the
# signature against it. Signer identity for the allow-list is $3.
_sign_and_verify_via_agent() {
  local pubfile=$1 datafile=$2 ident=$3
  local ktype kdata _rest
  read -r ktype kdata _rest <"$pubfile"
  printf '%s %s %s\n' "$ident" "$ktype" "$kdata" >"$datafile.signers"

  SSH_AUTH_SOCK="$AGENT_SOCK" \
    ssh-keygen -Y sign -f "$pubfile" -U -n file "$datafile" || return 1
  ssh-keygen -Y verify -f "$datafile.signers" -I "$ident" \
    -n file -s "$datafile.sig" <"$datafile" >/dev/null
}

# The merged listing offers the native PIV key FIRST, then the proxied
# software key — ssh tries identities in offer order and the native key
# must win ties.
function merged_listing_native_first_then_upstream { # @test
  _stack_up

  local first_line soft_key
  first_line=$(head -1 "$WORKDIR/listing")
  [[ $first_line == ecdsa-sha2-nistp256\ * ]] || {
    echo "first offered identity is not the native 9A key:" >&2
    cat "$WORKDIR/listing" >&2
    return 1
  }
  grep -q '^ssh-ed25519 .* soft-upstream-key$' "$WORKDIR/listing" || {
    echo "software upstream key missing from merged listing:" >&2
    cat "$WORKDIR/listing" >&2
    echo "--- agent log ---" >&2
    tail -40 "$AGENT_LOG" >&2 || true
    return 1
  }
}

# A native sign (fibby 9A, via the card) and a routed sign (ed25519, via
# the proxied ssh-agent) both succeed through the same socket and both
# verify.
function native_and_routed_signs_verify { # @test
  _stack_up

  echo "native-payload" >"$WORKDIR/native"
  _sign_and_verify_via_agent "$WORKDIR/id9a.pub" "$WORKDIR/native" "native@fibby" || {
    echo "native 9A sign/verify failed" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
  grep -q "GA ECDSA 9A -> 9000" "$FIBBY_LOG" || {
    echo "native sign never reached fibby's slot 9A" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  echo "routed-payload" >"$WORKDIR/routed"
  _sign_and_verify_via_agent "$WORKDIR/soft.pub" "$WORKDIR/routed" "soft@upstream" || {
    echo "routed ed25519 sign/verify failed" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
}

# Mixed concurrent burst: native (card) and proxied (software) signs
# interleaved; every one must succeed. Extends the #213 burst gate
# across the proxy split — proxied signs must not queue behind or
# perturb the card serialization.
function mixed_concurrent_sign_burst_all_succeed { # @test
  _stack_up

  # Warm the PIN cache so the burst measures contention, not prompts.
  echo "warmup" >"$WORKDIR/warmup"
  SSH_AUTH_SOCK="$AGENT_SOCK" \
    ssh-keygen -Y sign -f "$WORKDIR/id9a.pub" -U -n file "$WORKDIR/warmup" || {
    echo "warmup native sign failed" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }

  local n=8
  local -a pids=()
  local i pubfile
  for i in $(seq 1 "$n"); do
    echo "mixed-burst-$i" >"$WORKDIR/mix$i"
  done
  for i in $(seq 1 "$n"); do
    if ((i % 2)); then pubfile="$WORKDIR/id9a.pub"; else pubfile="$WORKDIR/soft.pub"; fi
    SSH_AUTH_SOCK="$AGENT_SOCK" \
      ssh-keygen -Y sign -f "$pubfile" -U -n file "$WORKDIR/mix$i" \
      >"$WORKDIR/mix$i.log" 2>&1 &
    pids+=("$!")
  done

  local fails=0
  for i in $(seq 1 "$n"); do
    if ! wait "${pids[i - 1]}"; then
      fails=$((fails + 1))
      echo "--- mixed signer $i failed ---" >&2
      cat "$WORKDIR/mix$i.log" >&2 || true
    fi
  done
  [[ $fails -eq 0 ]] || {
    echo "$fails/$n mixed concurrent signs failed" >&2
    echo "--- agent log tail ---" >&2
    tail -80 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "agent died during the mixed burst" >&2
    tail -80 "$AGENT_LOG" >&2 || true
    return 1
  }
}

# A dead upstream must not take the native keys with it: kill the
# software agent, and the merged listing degrades to the native key.
function dead_upstream_degrades_to_native_keys { # @test
  _stack_up

  kill "$SOFT_PID" 2>/dev/null || true
  wait "$SOFT_PID" 2>/dev/null || true
  SOFT_PID=
  rm -f "$SOFT_SOCK"

  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "listing failed outright after upstream death (status $status)" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -q '^ecdsa-sha2-nistp256 ' || {
    echo "native 9A key vanished with the dead upstream" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  ! printf '%s\n' "$output" | grep -q 'soft-upstream-key' || {
    echo "dead upstream's key still offered" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# With --add-new-keys-to soft, an ssh-add against the piggy socket lands
# the key in the software upstream (visible on its socket directly).
function add_identity_routes_to_designated_upstream { # @test
  _stack_up --add-new-keys-to soft

  ssh-keygen -t ed25519 -N '' -q -C "added-via-piggy" \
    -f "$WORKDIR/addkey" </dev/null
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -q "$WORKDIR/addkey"
  [[ $status -eq 0 ]] || {
    echo "ssh-add via piggy agent exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$AGENT_LOG" >&2 || true
    return 1
  }

  SSH_AUTH_SOCK="$SOFT_SOCK" run ssh-add -L
  printf '%s\n' "$output" | grep -q 'added-via-piggy' || {
    echo "added key did not land in the designated upstream" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}

# piggy#215 step 5: `piggy health` gains per-upstream points from the
# agent's upstream-status@piggy self-report. Fibby is seeded 9A+9D+CHUID
# so every card point can pass; the run must exit 0 with a passing
# point for the proxied upstream.
function health_reports_upstream_point { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert --seed-chuid
  _spawn_soft_agent_with_key
  _spawn_rust_agent_with_upstream

  PIGGY_AUTH_SOCK="$AGENT_SOCK" PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    run "$PIGGY_BIN" health --format ndjson
  [[ $status -eq 0 ]] || {
    echo "piggy health exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$AGENT_LOG" >&2 || true
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }
  local line
  line=$(printf '%s\n' "$output" | grep 'agent: upstream soft answers') || {
    echo "no upstream point in health output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  [[ $line == *'"ok":true'* ]] || {
    echo "upstream point present but not ok: $line" >&2
    return 1
  }
}

# eng#295 — the remote-host role. A PROXY-ONLY `piggy agent` (no card;
# PCSC deliberately unreachable) fronts the fibby-backed card agent as
# upstream "fwd", behind a dead upstream listed FIRST (a stable-but-down
# backing, like a RemoteForward'd socket whose connection dropped). The
# stack:
#
#   fibby <- pcsc -> piggy agent -A            (the "workstation" agent)
#                      ^ upstream fwd
#   piggy agent --proxy-only --upstream dead=… --upstream fwd=…  <- clients
#
# Gates: the proxy lists the card's 9A key; `piggy pass show` routed at the
# proxy decrypts — the ecdh-rebox native-miss forwards to the card agent
# (which prompts the PIN on demand); `piggy health` against the proxy exits
# 0 with the local-card points SKIPped and the dead alternative backing
# SKIPped (one backing is live).
function proxy_only_agent_fronts_forwarded_card_agent { # @test
  spawn_fibby --seed-rfc6979-slot-9a-cert --seed-rfc5903-slot-9d-cert --seed-chuid

  # The card-backed agent (no upstreams of its own).
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent -A -a "$AGENT_SOCK" \
    >"$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && break
    sleep 0.1
  done
  [[ -S $AGENT_SOCK ]] || {
    echo "card agent socket never appeared" >&2
    cat "$AGENT_LOG" >&2 || true
    return 1
  }

  # The proxy-only agent. PCSCLITE_CSOCK_NAME points nowhere: a
  # proxy-only agent must never open PCSC, and if it did, it would fail
  # loudly here rather than silently borrow fibby.
  local proxy_sock="$WORKDIR/p.sock" proxy_log="$WORKDIR/proxy.log"
  PCSCLITE_CSOCK_NAME="$WORKDIR/no-such-pcscd" "$PIGGY_BIN" agent --proxy-only \
    --upstream "dead=$WORKDIR/dead.sock" --upstream "fwd=$AGENT_SOCK" \
    -a "$proxy_sock" >"$proxy_log" 2>&1 &
  SOFT_PID=$! # reuse the teardown slot
  for _ in $(seq 1 50); do
    [[ -S $proxy_sock ]] && break
    sleep 0.1
  done
  [[ -S $proxy_sock ]] || {
    echo "proxy-only agent socket never appeared" >&2
    cat "$proxy_log" >&2 || true
    return 1
  }

  # 1. Listing through the proxy shows the card's key (served by fwd).
  SSH_AUTH_SOCK="$proxy_sock" run ssh-add -L
  [[ $status -eq 0 ]] || {
    echo "ssh-add -L exited $status against the proxy-only agent" >&2
    cat "$proxy_log" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -q '^ecdsa-sha2-nistp256 ' || {
    echo "proxy-only listing lacks the forwarded 9A key" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # 2. Decrypt through the proxy: init/insert talk to fibby directly
  # (offline encrypt); `pass show` is routed at the PROXY, whose
  # ecdh-rebox native-miss must forward to the card agent.
  local store="$WORKDIR/store" secret="proxied-decrypt-secret"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$secret" | PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
    PIGGY_STORE_DIR="$store" "$PIGGY_BIN" pass insert -e foo/bar
  [[ -f "$store/foo/bar.ebox" ]] || {
    echo "piggy pass insert produced no ebox" >&2
    return 1
  }
  PIGGY_AUTH_SOCK="$proxy_sock" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass show foo/bar
  [[ $status -eq 0 ]] || {
    echo "piggy pass show via the proxy-only agent exited $status" >&2
    printf '%s\n' "$output" >&2
    echo "--- proxy log ---" >&2
    cat "$proxy_log" >&2 || true
    echo "--- card agent log ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "proxied decrypt output missing the secret line" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }
  # The ECDH ran on the CARD agent (fibby), not anywhere in the proxy.
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no slot-9D GA ECDH in fibby trace — where did the decrypt happen?" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
  ! grep -qi "PCSC" "$proxy_log" || {
    echo "proxy-only agent touched PCSC:" >&2
    grep -i "PCSC" "$proxy_log" >&2
    return 1
  }

  # 3. Health against the proxy: exit 0; local-card points SKIP with the
  # proxy-only reason; fwd ok; dead SKIPs (an alternative backing is live).
  PIGGY_AUTH_SOCK="$proxy_sock" PCSCLITE_CSOCK_NAME="$WORKDIR/no-such-pcscd" \
    run "$PIGGY_BIN" health --format ndjson
  [[ $status -eq 0 ]] || {
    echo "piggy health against the proxy-only agent exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  local line
  line=$(printf '%s\n' "$output" | grep '"pcsc: daemon reachable"') || {
    echo "no pcsc point in health output" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  [[ $line == *'proxy-only'* ]] || {
    echo "pcsc point not SKIPped with the proxy-only reason: $line" >&2
    return 1
  }
  line=$(printf '%s\n' "$output" | grep 'agent: upstream fwd answers')
  [[ $line == *'"ok":true'* ]] || {
    echo "fwd upstream point not ok: $line" >&2
    return 1
  }
  line=$(printf '%s\n' "$output" | grep 'agent: upstream dead answers')
  [[ $line == *'other upstream'* ]] || {
    echo "dead upstream point not SKIPped as an alternative backing: $line" >&2
    return 1
  }
}

# Without --add-new-keys-to, adds are refused and nothing reaches the
# upstream.
function add_identity_without_target_is_refused { # @test
  _stack_up

  ssh-keygen -t ed25519 -N '' -q -C "should-be-refused" \
    -f "$WORKDIR/refkey" </dev/null
  SSH_AUTH_SOCK="$AGENT_SOCK" run ssh-add -q "$WORKDIR/refkey"
  [[ $status -ne 0 ]] || {
    echo "ssh-add unexpectedly succeeded without --add-new-keys-to" >&2
    return 1
  }

  SSH_AUTH_SOCK="$SOFT_SOCK" run ssh-add -L
  ! printf '%s\n' "$output" | grep -q 'should-be-refused' || {
    echo "refused key leaked into the upstream anyway" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
}
