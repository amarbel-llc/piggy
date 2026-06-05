#! /usr/bin/env bats
#
# Fibby-backed proof that `piggy pass recipients sync` with NO file argument
# re-encrypts the existing store to the recipients already declared in the
# piggy-ids file(s), and that the result still decrypts through the card.
#
# This is the real-crypto counterpart to the mock-based guards in
# t0600-recipients.bats. The base64 mock round-trips bit-identically, so it
# can only prove the dispatch path; here, with fibby's virtual slot 9D, a
# re-encrypt produces fresh ciphertext that we then decrypt back through the
# agent <-> fibby ECDH path.
#
# Two scenarios:
#   - whole-store: bare `recipients sync` re-encrypts every ebox; a new
#     "Reencrypt password store." commit lands and both secrets still decrypt.
#   - `-p <subfolder>`: scopes the walk to that subtree; the sibling subtree's
#     ebox is left byte-identical.
#
# Single-card limitation: with one fibby card we verify the re-encrypt loop and
# that the card's recipient still decrypts. Independently verifying a *second,
# keyless* recipient (i.e. that the re-encrypted ebox is openable by another
# card too) would need a second card and is out of scope here.
#
# Required env (supplied by the
# `test-bats-conformance-recipients-sync-fibby` recipe):
#   PIVY_AGENT=/path/to/pivy-agent  (nix build .#pivy)
#   FIBBY_BIN=/path/to/fibby        (nix build .#fibby)
#   PIGGY_BIN=/path/to/piggy        (nix build .#default — real pivy-box +
#                                    piggy-ids, bypassing common.bash's mocks)
#
# When invoked via the conformance lane's glob without those env vars set, the
# suite gracefully skips — same convention as piggy_fibby_pivy_agent_smoke.bats.

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  export output

  if [[ -z ${PIVY_AGENT:-} ]] || [[ ! -x ${PIVY_AGENT:-/nonexistent} ]]; then
    skip "PIVY_AGENT unset or not executable; run via just test-bats-conformance-recipients-sync-fibby"
  fi
  if [[ -z ${FIBBY_BIN:-} ]] || [[ ! -x ${FIBBY_BIN:-/nonexistent} ]]; then
    skip "FIBBY_BIN unset or not executable"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable; run via just test-bats-conformance-recipients-sync-fibby"
  fi

  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""

  # Short-path workdir under /tmp because $BATS_TEST_TMPDIR can overrun
  # AF_UNIX sun_path's 108-byte limit when bats sits deep under nix sandbox
  # prefixes. Same trick as the smoke + hardware lanes.
  WORKDIR="$(mktemp -d -t rsync.XXXXXX)"
  FIBBY_SOCK="$WORKDIR/pcscd.comm"
  AGENT_SOCK="$WORKDIR/a.sock"
  FIBBY_LOG="$WORKDIR/fibby.log"
  AGENT_LOG="$WORKDIR/agent.log"
  FIBBY_PID=
  AGENT_PID=

  unset SSH_AUTH_SOCK
  # common.bash exports GIT_DIR/GIT_WORK_TREE pointed at *its* test-store, and
  # GIT_DIR env overrides `git -C`. This test drives a real git store under
  # $WORKDIR (unlike the gitless smoke tests), so the leaked env would send
  # piggy's commits — and our own rev-parse — to the wrong, empty repo. Clear
  # it so git resolves relative to the per-test store. (GIT_TEMPLATE_DIR stays:
  # it keeps `git init` from copying the nix-store template under the sandbox.)
  unset GIT_DIR GIT_WORK_TREE
  # In spinclass sessions $TMPDIR (hence $WORKDIR) lives under the outer
  # worktree, so with GIT_DIR cleared git's upward .git discovery could escape
  # the per-test store and reach the worktree repo — leaking commits into it.
  # Fence discovery at $WORKDIR so the only repo git can find is the
  # store-local one we create in _init_store_with_secrets.
  export GIT_CEILING_DIRECTORIES="$WORKDIR"
}

teardown() {
  [[ -n ${AGENT_PID:-} ]] && kill "$AGENT_PID" 2>/dev/null || true
  [[ -n ${FIBBY_PID:-} ]] && kill "$FIBBY_PID" 2>/dev/null || true
  if [[ -n ${AGENT_PID:-} ]]; then wait "$AGENT_PID" 2>/dev/null || true; fi
  if [[ -n ${FIBBY_PID:-} ]]; then wait "$FIBBY_PID" 2>/dev/null || true; fi
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

# Set up a git-backed store seeded from fibby's slot-9D recipient, with the
# named secrets inserted. Echoes nothing; leaves $store populated and committed.
# Args: <store-dir> <name>=<secret> ...
_init_store_with_secrets() {
  local store="$1"
  shift

  # Create the store's OWN git repo FIRST. In spinclass sessions $TMPDIR (and
  # thus this store) lives under the outer worktree, so if the store had no
  # `.git` yet, piggy's first commit would walk up and land in the *worktree*
  # repo. `git init "$store"` shadows that — every later commit resolves to the
  # store-local repo.
  mkdir -p "$store"
  PIGGY_STORE_DIR="$store" run "$PIGGY_BIN" pass git init
  [[ $status -eq 0 ]] || {
    echo "piggy pass git init exited $status" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # init auto-detects the single card's 9D recipient (offline pubkey read, no
  # PIN) and commits piggy-ids to the store-local repo.
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass init
  [[ $status -eq 0 ]] || {
    echo "piggy pass init exited $status" >&2
    printf '%s\n' "$output" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  local pair name secret
  for pair in "$@"; do
    name="${pair%%=*}"
    secret="${pair#*=}"
    printf '%s\n' "$secret" | PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" \
      PIGGY_STORE_DIR="$store" "$PIGGY_BIN" pass insert -e "$name"
    local ins=$?
    [[ $ins -eq 0 && -f "$store/$name.ebox" ]] || {
      echo "piggy pass insert $name exited $ins (ebox present: $([[ -f $store/$name.ebox ]] && echo yes || echo no))" >&2
      tail -40 "$FIBBY_LOG" >&2 || true
      return 1
    }
  done
}

_ebox_sha() { sha256sum "$1" | cut -d' ' -f1; }

# Assert a `pass show` of $name decrypts to $secret through the agent <-> fibby
# rebox path. `run` merges pivy-box's stderr into $output, so grep -Fxq the
# secret as its own line rather than equality.
_assert_decrypts() {
  local store="$1" name="$2" secret="$3"
  PIGGY_AUTH_SOCK="$AGENT_SOCK" PIGGY_STORE_DIR="$store" \
    run "$PIGGY_BIN" pass show "$name"
  [[ $status -eq 0 ]] || {
    echo "piggy pass show $name exited $status after re-encrypt" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }
  printf '%s\n' "$output" | grep -Fxq "$secret" || {
    echo "decrypt output for $name missing the secret line '$secret'" >&2
    printf 'got:\n%s\n' "$output" >&2
    return 1
  }
}

# Bare `recipients sync` (no file) re-encrypts the WHOLE store to the current
# piggy-ids recipients: a new commit lands (real crypto -> fresh ciphertext)
# and every secret still decrypts via fibby's slot 9D.
function recipients_sync_no_file_reencrypts_whole_store_via_fibby { # @test
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert
  spawn_agent

  local store="$WORKDIR/store"
  _init_store_with_secrets "$store" "foo/bar=secret-one" "baz=secret-two"

  local before
  before="$(git -C "$store" rev-parse HEAD)"

  # No file: re-encrypt the whole store to the current recipients. The decrypt
  # half routes through pivy-box stream decrypt -> agent rebox (slot 9D), so it
  # needs PIGGY_AUTH_SOCK + the PIN (supplied via the test askpass).
  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_AUTH_SOCK="$AGENT_SOCK" \
    PIGGY_STORE_DIR="$store" run "$PIGGY_BIN" pass recipients sync
  [[ $status -eq 0 ]] || {
    echo "piggy pass recipients sync (no file) exited $status" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # Real crypto re-encrypts to fresh ciphertext, so a commit must land.
  local after
  after="$(git -C "$store" rev-parse HEAD)"
  [[ "$before" != "$after" ]] || {
    echo "expected a new commit after whole-store re-encrypt" >&2
    git -C "$store" log --oneline -3 >&2 || true
    return 1
  }
  run git -C "$store" log -1 --pretty=%s
  assert_output --partial "Reencrypt password store."

  # Both secrets must still decrypt through the card.
  _assert_decrypts "$store" "foo/bar" "secret-one"
  _assert_decrypts "$store" "baz" "secret-two"

  # The re-encrypt's decrypt actually reached fibby's slot 9D, and the agent
  # neither died nor refused the askpass.
  grep -q "GA ECDH 9D -> 9000" "$FIBBY_LOG" || {
    echo "no successful slot-9D GA ECDH in fibby trace" >&2
    tail -80 "$FIBBY_LOG" >&2 || true
    return 1
  }
  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "pivy-agent died during the re-encrypt" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# `recipients sync -p <subfolder>` (no file) re-encrypts ONLY that subtree: the
# scoped ebox changes and still decrypts, while the sibling subtree's ebox is
# left byte-identical.
function recipients_sync_no_file_p_scopes_subtree_via_fibby { # @test
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert
  spawn_agent

  local store="$WORKDIR/store"
  _init_store_with_secrets "$store" "alpha/cred=in-scope" "beta/cred=untouched"

  local a_before b_before
  a_before="$(_ebox_sha "$store/alpha/cred.ebox")"
  b_before="$(_ebox_sha "$store/beta/cred.ebox")"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_AUTH_SOCK="$AGENT_SOCK" \
    PIGGY_STORE_DIR="$store" run "$PIGGY_BIN" pass recipients sync -p alpha
  [[ $status -eq 0 ]] || {
    echo "piggy pass recipients sync -p alpha exited $status" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }

  local a_after b_after
  a_after="$(_ebox_sha "$store/alpha/cred.ebox")"
  b_after="$(_ebox_sha "$store/beta/cred.ebox")"

  [[ "$a_before" != "$a_after" ]] || {
    echo "expected alpha/cred.ebox to be re-encrypted (sha unchanged: $a_after)" >&2
    return 1
  }
  [[ "$b_before" == "$b_after" ]] || {
    echo "beta/cred.ebox changed but was out of -p scope ($b_before -> $b_after)" >&2
    return 1
  }

  # The scoped secret still decrypts; the untouched one is unaffected.
  _assert_decrypts "$store" "alpha/cred" "in-scope"
  _assert_decrypts "$store" "beta/cred" "untouched"
}
