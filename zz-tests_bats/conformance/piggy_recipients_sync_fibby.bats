#! /usr/bin/env bats
#
# Fibby-backed proof that `piggy pass recipients sync` with NO file argument
# emits a TAP-14 stream and, on an already-current store, `# SKIP`s every ebox
# (the recipients-match optimization in
# crates/piggy/src/reencrypt.rs::reencrypt_unnecessary) without touching the
# card or landing a commit — while every secret still decrypts.
#
# This is the real-crypto counterpart to the mock-based guards in
# t0600-recipients.bats. The base64 mock can't carry recipient metadata, so the
# SKIP decision is invisible there; here, with fibby's virtual slot 9D, the
# eboxes are genuine ebox wire format, so `reencrypt_unnecessary` parses their
# recipient pubkeys and proves the SKIP path end-to-end.
#
# Two scenarios:
#   - whole-store: bare `recipients sync` on a just-initialised store emits a
#     `1..2` plan with both points `# SKIP`'d, lands NO new commit, never issues
#     a card GA ECDH, and both secrets still decrypt.
#   - `-p <subfolder>`: scopes the walk to that subtree (a `1..1` plan), SKIPs
#     the in-scope ebox, and leaves the sibling subtree's ebox byte-identical.
#
# Single-card limitation: with one fibby card every ebox is encrypted to exactly
# the one recipient piggy-ids declares, so `recipients sync` always SKIPs.
# Exercising the re-encrypt branch (recipients genuinely changed -> `ok` points
# + a fresh-ciphertext commit) needs a second, distinct recipient; the
# `reencrypt_unnecessary` false-cases are covered by Rust unit tests in
# reencrypt.rs instead. A multi-card/multi-instance fibby harness that would
# restore the real-crypto re-encrypt proof is tracked in amarbel-llc/piggy#147.
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

# Bare `recipients sync` (no file) on a just-initialised store: every ebox
# already encrypts to the one recipient in piggy-ids, so the TAP stream is a
# `1..2` plan with both points `# SKIP`'d, NO commit lands, the card is never
# touched, and both secrets still decrypt via fibby's slot 9D.
function recipients_sync_no_file_skips_already_current_via_fibby { # @test
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert
  spawn_agent

  local store="$WORKDIR/store"
  _init_store_with_secrets "$store" "foo/bar=secret-one" "baz=secret-two"

  local before fibby_lines_before
  before="$(git -C "$store" rev-parse HEAD)"
  fibby_lines_before="$(wc -l <"$FIBBY_LOG")"

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

  # TAP-14: a 1..2 plan with both points SKIP'd as recipients-already-current.
  printf '%s\n' "$output" | grep -qx "TAP version 14" || {
    echo "missing 'TAP version 14' header" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -qx "1..2" || {
    echo "expected a 1..2 plan" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  local skips
  skips="$(printf '%s\n' "$output" | grep -c '# SKIP recipients already current' || true)"
  [[ "$skips" -eq 2 ]] || {
    echo "expected 2 SKIP points, got $skips" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # SKIP short-circuits before any decrypt: no new commit, and the card is
  # never touched (no new slot-9D GA ECDH during the sync window).
  local after
  after="$(git -C "$store" rev-parse HEAD)"
  [[ "$before" == "$after" ]] || {
    echo "expected NO new commit (every ebox SKIP'd), but HEAD moved" >&2
    git -C "$store" log --oneline -3 >&2 || true
    return 1
  }
  local new_ga
  new_ga="$(tail -n "+$((fibby_lines_before + 1))" "$FIBBY_LOG" | grep -c 'GA ECDH 9D' || true)"
  [[ "$new_ga" -eq 0 ]] || {
    echo "SKIP path unexpectedly hit the card ($new_ga GA ECDH ops during sync)" >&2
    tail -40 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The eboxes are untouched and still decrypt through the card.
  _assert_decrypts "$store" "foo/bar" "secret-one"
  _assert_decrypts "$store" "baz" "secret-two"

  kill -0 "$AGENT_PID" 2>/dev/null || {
    echo "pivy-agent died during the sync" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    return 1
  }
  ! grep -q "REFUSING to prompt" "$AGENT_LOG" || {
    echo "unexpected askpass refusal in agent log" >&2
    cat "$AGENT_LOG" >&2
    return 1
  }
}

# `recipients sync -p <subfolder>` (no file) walks ONLY that subtree: a `1..1`
# plan (vs `1..2` for the whole store) proves the scoping, the in-scope ebox is
# SKIP'd (already current), and the sibling subtree's ebox is left untouched.
# Both still decrypt.
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

  # -p alpha walks ONLY the alpha subtree: a 1..1 plan, that one point SKIP'd.
  printf '%s\n' "$output" | grep -qx "1..1" || {
    echo "expected a 1..1 plan scoped to alpha" >&2
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output" | grep -q '# SKIP' || {
    echo "expected the alpha ebox to be SKIP'd" >&2
    printf '%s\n' "$output" >&2
    return 1
  }

  # Already-current store: alpha is SKIP'd (byte-identical) and beta is out of
  # scope (never walked), so both eboxes are unchanged.
  local a_after b_after
  a_after="$(_ebox_sha "$store/alpha/cred.ebox")"
  b_after="$(_ebox_sha "$store/beta/cred.ebox")"

  [[ "$a_before" == "$a_after" ]] || {
    echo "expected alpha/cred.ebox to be SKIP'd byte-identical (sha changed: $a_after)" >&2
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

# Real-crypto proof for the symlink-farm store (the rcm shape that broke
# `recipients sync` in practice): the store entry is a symlink pointing at an
# ebox that lives OUTSIDE the store. Bare `recipients sync` must follow the
# link, re-encrypt the EXTERNAL target to fresh ciphertext (sha changes),
# leave the link a link pointing at that same target, and the secret must
# still decrypt through the card via the link. The base64 mock in
# t0600-recipients.bats proves the plumbing but cannot prove the ciphertext is
# genuinely re-wrapped — that is this test's job.
function recipients_sync_follows_symlink_into_external_dir_via_fibby { # @test
  export PIGGY_TEST_FIB_PIN=123456
  spawn_fibby --seed-rfc5903-slot-9d-cert
  spawn_agent

  local store="$WORKDIR/store"
  _init_store_with_secrets "$store" "linked=linked-secret"

  # Relocate the real ebox outside the store and symlink it back in — the
  # exact shape of a store entry pointing into an rcm checkout.
  local ext="$WORKDIR/external"
  mkdir -p "$ext"
  mv "$store/linked.ebox" "$ext/linked.ebox"
  ln -s "$ext/linked.ebox" "$store/linked.ebox"
  [[ -L "$store/linked.ebox" ]] || {
    echo "setup: store entry is not a symlink" >&2
    return 1
  }

  local before
  before="$(_ebox_sha "$ext/linked.ebox")"

  PCSCLITE_CSOCK_NAME="$FIBBY_SOCK" PIGGY_AUTH_SOCK="$AGENT_SOCK" \
    PIGGY_STORE_DIR="$store" run "$PIGGY_BIN" pass recipients sync
  [[ $status -eq 0 ]] || {
    echo "piggy pass recipients sync (symlink-farm) exited $status" >&2
    printf '%s\n' "$output" >&2
    echo "--- agent log tail ---" >&2
    tail -60 "$AGENT_LOG" >&2 || true
    echo "--- fibby log tail ---" >&2
    tail -60 "$FIBBY_LOG" >&2 || true
    return 1
  }

  # The EXTERNAL target was re-encrypted (fresh ciphertext under real crypto).
  local after
  after="$(_ebox_sha "$ext/linked.ebox")"
  [[ "$before" != "$after" ]] || {
    echo "expected external target to be re-encrypted (sha unchanged: $after)" >&2
    return 1
  }

  # The store entry is STILL a symlink to the same external target — not
  # clobbered into a regular file.
  [[ -L "$store/linked.ebox" ]] || {
    echo "store entry stopped being a symlink after sync" >&2
    ls -la "$store" >&2 || true
    return 1
  }
  run readlink "$store/linked.ebox"
  assert_output "$ext/linked.ebox"

  # And the secret still decrypts through the card, reached via the link.
  _assert_decrypts "$store" "linked" "linked-secret"
}
