#! /usr/bin/env bats
#
# FDR 0006 phase (d), piggy#383: the holder agent mode. A `piggy agent
# --holder` over a yk5.7 fibby mints a key on a fresh virtual card
# (`mint@piggy`), bound to the calling connection's own cgroup under the
# scope definition `piggy-mint-v1=caller`; the key signs through the
# ordinary agent path with NO PIN prompt (the card reports PIN `never`,
# item 4); a mint naming no scope, an undefined scope, or a scope whose
# fixed cgroup the caller is not inside is refused by name; a retire
# destroys the card; the 16-card cap is its own refusal; and when the
# bound cgroup's directory disappears from under the staged cgroup root
# the card is torn down by itself.
#
# The cgroup root is a directory the test stages (`--cgroup-root`), so
# the teardown is driven here without systemd. A SIBLING scope needs a
# second cgroup, which only the `explore-fdr0006-d` hand pass and the VM
# lane can make.
#
# Required env (supplied by `just test-bats-conformance-holder-mint-fibby`):
#   FIBBY_BIN=/path/to/fibby   (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${FIBBY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/fibby ]]; then
    FIBBY_BIN="$REPO_ROOT/target/debug/fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/piggy ]]; then
    PIGGY_BIN="$REPO_ROOT/target/debug/piggy"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable; run via just test-bats-conformance-holder-mint-fibby"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable"
  fi
  command -v ssh-add >/dev/null || skip "ssh-add not on PATH"
  command -v ssh-keygen >/dev/null || skip "ssh-keygen not on PATH"

  # piggy-testing(7) PIN PROMPT SAFETY NET. PIGGY_TEST_FIB_PIN is left
  # UNSET on purpose: a minted key must sign without any PIN, so a prompt
  # would make the helper refuse loudly and the sign fail.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset WAYLAND_DISPLAY PIGGY_TEST_FIB_PIN

  WORKDIR="$(mktemp -d -t hold.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  FIBBY_CTL="$WORKDIR/ctl.sock"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  CGROUP_ROOT="$WORKDIR/cgroup"
  FIBBY_PID=
  AGENT_PID=

  # The calling connection's own cgroup (v2), which `piggy-mint-v1=caller`
  # binds a mint to; staged as a directory under the test's cgroup root.
  OWN_CGROUP="$(sed -n 's/^0:://p' /proc/self/cgroup | head -n1)"
  [[ -n $OWN_CGROUP ]] || skip "no cgroup v2 line in /proc/self/cgroup"
  mkdir -p "$CGROUP_ROOT$OWN_CGROUP"

  unset SSH_AUTH_SOCK PIGGY_AUTH_SOCK
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# fibby (yk5.7, so Ed25519 can be minted) with its control socket, its
# initial blank card destroyed so every reader slot is the holder's.
_spawn_holder_fibby() {
  spawn_fibby --model yk5.7 --control-socket "$FIBBY_CTL" 3>&-
  "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" destroy "Virtual PCD piggy fibby 00 00" >/dev/null
}

# The holder agent: scope piggy-mint-v1 binds to the caller's cgroup,
# elsewhere-v1 to a fixed cgroup nothing here is inside.
_spawn_holder_agent() {
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" \
    --scope piggy-mint-v1=caller \
    --scope elsewhere-v1=cgroup:/piggy-test/elsewhere.scope \
    --cgroup-root "$CGROUP_ROOT" --scope-poll-interval 1 \
    -a "$AGENT_SOCK" "$@" >"$AGENT_LOG" 2>&1 3>&- &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && { export SSH_AUTH_SOCK="$AGENT_SOCK"; return 0; }
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  cat "$AGENT_LOG" "$FIBBY_LOG" >&2 || true
  return 1
}

_dump_logs() {
  echo "--- agent log ---" >&2
  cat "$AGENT_LOG" >&2 || true
  echo "--- fibby log (tail) ---" >&2
  tail -60 "$FIBBY_LOG" >&2 || true
}

function a_minted_key_is_listed_and_signs_with_no_pin_prompt { # @test
  _spawn_holder_fibby
  _spawn_holder_agent

  run "$PIGGY_BIN" holder mint --scope piggy-mint-v1
  [[ $status -eq 0 ]] || { echo "mint failed ($status): $output" >&2; _dump_logs; return 1; }
  printf '%s\n' "$output" >"$WORKDIR/id.pub"
  local ktype kdata comment
  read -r ktype kdata comment <"$WORKDIR/id.pub"
  [[ $ktype == ssh-ed25519 ]] || { echo "not an ed25519 key: $output" >&2; return 1; }
  [[ $comment == "holder:piggy-holder 1" ]] || { echo "unexpected comment: $comment" >&2; return 1; }

  run ssh-add -L
  [[ $status -eq 0 && $output == *"$kdata"* ]] || {
    echo "the minted key is not listed: $output" >&2; _dump_logs; return 1; }

  printf 'piggy-test@holder %s %s\n' "$ktype" "$kdata" >"$WORKDIR/allowed_signers"
  echo "piggy-test: signed by a minted key" >"$WORKDIR/data"
  run ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/data"
  [[ $status -eq 0 && -f $WORKDIR/data.sig ]] || {
    echo "sign with the minted key failed ($status): $output" >&2; _dump_logs; return 1; }
  ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I piggy-test@holder \
    -n file -s "$WORKDIR/data.sig" <"$WORKDIR/data" >/dev/null
  grep -q "GA ED25519 9A -> 9000" "$FIBBY_LOG" || {
    echo "fibby saw no Ed25519 sign on 9A" >&2; _dump_logs; return 1; }
  # No VERIFY reached the card: the slot is PIN never and the agent
  # honoured it (piggy#383 item 4).
  if grep -q "VERIFY" "$FIBBY_LOG"; then
    echo "the agent verified a PIN for a PIN-never slot" >&2; _dump_logs; return 1
  fi
  # The factory PIN is gone: the holder keeps a random one. The minted
  # card is the only card fibby serves, so `piggy tool` needs no GUID.
  run env PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" tool -P 123456 -P 654321 change-pin
  [[ $status -ne 0 ]] || { echo "the factory PIN still unlocks the minted card" >&2; return 1; }
}

function a_p256_key_can_be_minted_too { # @test
  _spawn_holder_fibby
  _spawn_holder_agent
  run "$PIGGY_BIN" holder mint --scope piggy-mint-v1 --type p256
  [[ $status -eq 0 && $output == ecdsa-sha2-nistp256* ]] || {
    echo "p256 mint failed ($status): $output" >&2; _dump_logs; return 1; }
}

function mints_are_refused_by_name_for_no_scope_an_unknown_scope_and_a_scope_the_caller_is_outside { # @test
  _spawn_holder_fibby
  _spawn_holder_agent

  run "$PIGGY_BIN" holder mint
  [[ $status -eq 1 && $output == *"scope-unbound"* ]] || {
    echo "no scope: want exit 1 scope-unbound, got $status: $output" >&2; return 1; }

  run "$PIGGY_BIN" holder mint --scope piggy-mint-v9
  [[ $status -eq 1 && $output == *"unknown-scope"* && $output == *"piggy-mint-v1"* ]] || {
    echo "unknown scope: want exit 1 unknown-scope naming the defined ones, got $status: $output" >&2; return 1; }

  # The name is a claim; the peer is not inside elsewhere-v1's cgroup.
  run "$PIGGY_BIN" holder mint --scope elsewhere-v1
  [[ $status -eq 1 && $output == *"not-bound-scope"* ]] || {
    echo "foreign scope: want exit 1 not-bound-scope, got $status: $output" >&2; return 1; }

  run "$PIGGY_BIN" holder mint --scope piggy-mint-v1 --type rsa
  [[ $status -eq 2 ]] || { echo "bad type: want exit 2, got $status: $output" >&2; return 1; }

  run "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" list
  [[ $output == "ok" ]] || { echo "a refused mint created a card: $output" >&2; return 1; }
}

function a_retire_destroys_the_card_and_a_second_retire_finds_no_key { # @test
  _spawn_holder_fibby
  _spawn_holder_agent
  "$PIGGY_BIN" holder mint --scope piggy-mint-v1 >"$WORKDIR/id.pub"
  run "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" list
  [[ $output == *"piggy-holder 1"* ]] || { echo "no card after the mint: $output" >&2; return 1; }

  run "$PIGGY_BIN" holder retire "$WORKDIR/id.pub"
  [[ $status -eq 0 ]] || { echo "retire failed ($status): $output" >&2; _dump_logs; return 1; }
  run "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" list
  [[ $output == "ok" ]] || { echo "the card survived the retire: $output" >&2; return 1; }
  run ssh-add -L
  [[ $output != *"piggy-holder 1"* ]] || { echo "the key is still listed: $output" >&2; return 1; }

  run "$PIGGY_BIN" holder retire "$WORKDIR/id.pub"
  [[ $status -eq 1 && $output == *"no-such-key"* ]] || {
    echo "second retire: want exit 1 no-such-key, got $status: $output" >&2; return 1; }
}

function the_card_is_torn_down_when_the_bound_cgroup_disappears { # @test
  [[ $OWN_CGROUP != / ]] || skip "this process is in the root cgroup; nothing to remove"
  _spawn_holder_fibby
  _spawn_holder_agent
  "$PIGGY_BIN" holder mint --scope piggy-mint-v1 >"$WORKDIR/id.pub"
  local kdata
  kdata="$(cut -d' ' -f2 "$WORKDIR/id.pub")"
  run ssh-add -L
  [[ $output == *"$kdata"* ]] || { echo "the minted key is not listed" >&2; return 1; }

  # The scope exits: its cgroup directory goes.
  rmdir "$CGROUP_ROOT$OWN_CGROUP"
  local _ gone=0
  for _ in $(seq 1 50); do
    if ! "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" list | grep -q "piggy-holder 1"; then
      gone=1
      break
    fi
    sleep 0.2
  done
  [[ $gone -eq 1 ]] || { echo "the card outlived its scope" >&2; _dump_logs; return 1; }
  run ssh-add -L
  [[ $output != *"$kdata"* ]] || { echo "the key outlived its scope: $output" >&2; _dump_logs; return 1; }
  grep -q "its scope exited" "$AGENT_LOG" || { echo "no teardown line in the agent log" >&2; _dump_logs; return 1; }
}

function the_sixteen_card_cap_is_its_own_refusal_and_a_retire_frees_a_slot { # @test
  _spawn_holder_fibby
  _spawn_holder_agent
  local i
  for i in $(seq 1 16); do
    run "$PIGGY_BIN" holder mint --scope piggy-mint-v1
    [[ $status -eq 0 ]] || { echo "mint $i failed ($status): $output" >&2; _dump_logs; return 1; }
    [[ $i -ne 16 ]] || printf '%s\n' "$output" >"$WORKDIR/last.pub"
  done
  run "$PIGGY_BIN" holder mint --scope piggy-mint-v1
  [[ $status -eq 1 && $output == *"cap-reached"* ]] || {
    echo "17th mint: want exit 1 cap-reached, got $status: $output" >&2; _dump_logs; return 1; }
  "$PIGGY_BIN" holder retire "$WORKDIR/last.pub"
  run "$PIGGY_BIN" holder mint --scope piggy-mint-v1
  [[ $status -eq 0 ]] || { echo "mint after a retire failed ($status): $output" >&2; _dump_logs; return 1; }
}

# Shape A (a holder per session): `--scope session=any` binds a key to no
# cgroup; the socket, in a private directory, is the whole boundary.

# The agent's socket in a private directory of its own, apart from fibby's
# (they share $WORKDIR): what an `any` holder requires of all three sockets.
_private_agent_socket() {
  mkdir -m 0700 "$WORKDIR/agent"
  AGENT_SOCK="$WORKDIR/agent/a.sock"
}

# The agent over a cgroup root with NO directory in it: a key bound to a
# cgroup would be torn down at the first sweep, an `any` key must not be.
_spawn_any_agent() {
  mkdir -p "$WORKDIR/emptyroot"
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" \
    --scope session=any \
    --cgroup-root "$WORKDIR/emptyroot" --scope-poll-interval 1 \
    -a "$AGENT_SOCK" "$@" >"$AGENT_LOG" 2>&1 3>&- &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do
    [[ -S $AGENT_SOCK ]] && { export SSH_AUTH_SOCK="$AGENT_SOCK"; return 0; }
    sleep 0.1
  done
  echo "agent socket never appeared at $AGENT_SOCK" >&2
  cat "$AGENT_LOG" "$FIBBY_LOG" >&2 || true
  return 1
}

function an_any_scope_key_signs_and_is_never_torn_down_for_want_of_a_cgroup { # @test
  _spawn_holder_fibby
  _private_agent_socket
  _spawn_any_agent
  # The socket file itself is 0600 whatever the umask (round 1, L2).
  [[ $(stat -c %a "$AGENT_SOCK") == 600 ]] || {
    echo "the agent socket is mode $(stat -c %a "$AGENT_SOCK"), want 600" >&2; return 1; }
  run "$PIGGY_BIN" holder mint --scope session
  [[ $status -eq 0 ]] || { echo "mint under an any scope failed ($status): $output" >&2; _dump_logs; return 1; }
  printf '%s\n' "$output" >"$WORKDIR/id.pub"
  local ktype kdata _c
  read -r ktype kdata _c <"$WORKDIR/id.pub"

  # Several sweep intervals pass over a cgroup root that holds nothing.
  sleep 3.5
  run ssh-add -L
  [[ $output == *"$kdata"* ]] || { echo "the any key was dropped: $output" >&2; _dump_logs; return 1; }
  run "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" list
  [[ $output == *"piggy-holder 1"* ]] || { echo "the card was destroyed: $output" >&2; _dump_logs; return 1; }
  if grep -q "its scope exited" "$AGENT_LOG"; then
    echo "the agent tore an any key down for a vanished scope" >&2; _dump_logs; return 1
  fi

  printf 'piggy-test@holder %s %s\n' "$ktype" "$kdata" >"$WORKDIR/allowed_signers"
  echo "piggy-test: signed under an any scope" >"$WORKDIR/data"
  run ssh-keygen -Y sign -f "$WORKDIR/id.pub" -U -n file "$WORKDIR/data"
  [[ $status -eq 0 && -f $WORKDIR/data.sig ]] || {
    echo "sign under an any scope failed ($status): $output" >&2; _dump_logs; return 1; }
  ssh-keygen -Y verify -f "$WORKDIR/allowed_signers" -I piggy-test@holder \
    -n file -s "$WORKDIR/data.sig" <"$WORKDIR/data" >/dev/null

  # A retire still destroys the card.
  run "$PIGGY_BIN" holder retire "$WORKDIR/id.pub"
  [[ $status -eq 0 ]] || { echo "retire failed ($status): $output" >&2; _dump_logs; return 1; }
  run "$FIBBY_BIN" ctl --socket "$FIBBY_CTL" list
  [[ $output == "ok" ]] || { echo "the card survived the retire: $output" >&2; return 1; }
}

function an_any_scope_agent_refuses_to_start_on_a_socket_others_can_reach { # @test
  _spawn_holder_fibby
  local shared="$WORKDIR/shared"
  mkdir -m 0755 "$shared"
  run timeout 20 env PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" --scope session=any -a "$shared/a.sock" 3>&-
  [[ $status -ne 0 && $status -ne 124 ]] || { echo "want a refusal, got $status: $output" >&2; return 1; }
  [[ $output == *"an \`any\` scope needs private sockets"* && $output == *"0700"* ]] || {
    echo "the refusal does not say why: $output" >&2; return 1; }
  [[ ! -e $shared/a.sock ]] || { echo "the socket was bound anyway" >&2; return 1; }
  # The same directory at 0700 is served.
  chmod 0700 "$shared"
  AGENT_SOCK="$shared/a.sock"
  _spawn_any_agent
}

# Round 1, M1: minted cards are PIN never and touch never, so fibby's own two
# sockets are as much the boundary as the agent's.
function an_any_scope_agent_refuses_a_socket_directory_shared_with_fibby_or_an_unnamed_pcsc_socket { # @test
  _spawn_holder_fibby
  # The agent's socket in $WORKDIR, where fibby's two sockets are.
  run timeout 20 env PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" --scope session=any -a "$WORKDIR/a2.sock" 3>&-
  [[ $status -ne 0 && $status -ne 124 && $output == *"own directory"* ]] || {
    echo "want a refusal naming the shared directory, got $status: $output" >&2; return 1; }
  [[ ! -e $WORKDIR/a2.sock ]]
  # No PC/SC socket named.
  _private_agent_socket
  run timeout 20 env -u PCSCLITE_CSOCK_NAME "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" --scope session=any -a "$AGENT_SOCK" 3>&-
  [[ $status -ne 0 && $status -ne 124 && $output == *"PCSCLITE_CSOCK_NAME"* ]] || {
    echo "want a refusal naming PCSCLITE_CSOCK_NAME, got $status: $output" >&2; return 1; }
  [[ ! -e $AGENT_SOCK ]]
}

function an_any_scope_cannot_share_an_agent_with_a_cgroup_scope { # @test
  _spawn_holder_fibby
  run timeout 20 env PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent --holder \
    --holder-fibby-ctl "$FIBBY_CTL" --scope session=any --scope piggy-mint-v1=caller \
    -a "$AGENT_SOCK" 3>&-
  [[ $status -ne 0 && $status -ne 124 ]] || { echo "want a refusal, got $status: $output" >&2; return 1; }
  [[ $output == *"every --scope must be"* ]] || { echo "the refusal does not say why: $output" >&2; return 1; }
  [[ ! -e $AGENT_SOCK ]]
}

function an_agent_that_is_not_a_holder_does_not_serve_the_extensions { # @test
  spawn_fibby --model yk5.7 --seed-rfc6979-slot-9a-cert 3>&-
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" "$PIGGY_BIN" agent -A -a "$AGENT_SOCK" >"$AGENT_LOG" 2>&1 3>&- &
  AGENT_PID=$!
  local _
  for _ in $(seq 1 50); do [[ -S $AGENT_SOCK ]] && break; sleep 0.1; done
  export SSH_AUTH_SOCK="$AGENT_SOCK"
  run "$PIGGY_BIN" holder mint --scope piggy-mint-v1
  [[ $status -eq 3 ]] || { echo "want exit 3 (not a holder), got $status: $output" >&2; return 1; }
}
