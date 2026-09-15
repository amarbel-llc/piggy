bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-island
bats_load_library bats-emo

# Isolate HOME and XDG dirs to test tmpdir
setup_test_home

# Unset config vars
unset PIGGY_STORE_DIR
unset PIGGY_GIT
unset PIGGY_X_SELECTION
unset PIGGY_CLIP_TIME
unset PIGGY_UMASK
unset PIGGY_GENERATED_LENGTH
unset PIGGY_CHARACTER_SET
unset PIGGY_CHARACTER_SET_NO_SYMBOLS
unset EDITOR

# Repo root is the working directory where bats is invoked.
#
# Two modes share this harness:
#   - Local `bats --no-sandbox` from the repo root: $PWD = repo root.
#   - Nix-sandboxed bats lane (`bats.lib.${system}.batsLane`): $PWD = stage/zz-tests_bats/
#     and the helpers live at $PWD/helpers/ (no extra zz-tests_bats/
#     prefix). The lane builder injects $PIGGY and $PIGGY_IDS_REAL via
#     extraEnv so we never need to resolve those out of $REPO_ROOT in
#     the sandbox path.
#
# Resolve the helpers dir from common.bash's own location so both modes
# pick up the same files without splitting paths on $PWD.
REPO_ROOT="$PWD"
PIGGY_BATS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGGY_BATS_HELPERS_DIR="$PIGGY_BATS_DIR/helpers"

# Password store in test tmpdir
export PIGGY_STORE_DIR="$BATS_TEST_TMPDIR/test-store"
mkdir -p "$PIGGY_STORE_DIR"

# Empty template dir so git init doesn't copy from nix store (sandbox-safe)
export GIT_TEMPLATE_DIR="$BATS_TEST_TMPDIR/git-templates"
mkdir -p "$GIT_TEMPLATE_DIR"

# Git identity for test commits
export GIT_DIR="$PIGGY_STORE_DIR/.git"
export GIT_WORK_TREE="$PIGGY_STORE_DIR"
git config --global user.email "Piggy-Automated-Testing-Suite@test.local"
git config --global user.name "Piggy Automated Testing Suite"

# Piggy under test:
#   - $PIGGY is the rust dispatcher binary (pure Rust post-#96; no bash
#     dispatch survives). Every pass-style subcommand runs through the
#     same binary so the integration layer is exercised on every test
#     run.
#
# Resolution order: $PIGGY env var → target/debug/piggy → target/release/piggy.
# The nix lane (`bats.lib.${system}.batsLane`) injects $PIGGY pre-set; the
# `target/debug` fallback is only reached for local `bats --no-sandbox`
# runs.
if [[ -z ${PIGGY:-} ]]; then
  if [[ -x $REPO_ROOT/target/debug/piggy ]]; then
    PIGGY="$REPO_ROOT/target/debug/piggy"
  elif [[ -x $REPO_ROOT/target/release/piggy ]]; then
    PIGGY="$REPO_ROOT/target/release/piggy"
  else
    echo "common.bash: piggy rust binary not found." >&2
    echo "             Run 'cargo build' first, or set \$PIGGY explicitly." >&2
    exit 1
  fi
fi
export PIGGY

# Pre-set SECURE_TMPDIR so piggy's `pass git` passthrough has a
# tmpdir to forward as $TMPDIR (sandbox-safe). The Rust `edit`
# handler's SecureTmpdir guard ignores this and allocates its own
# directory under $TMPDIR / /dev/shm; SECURE_TMPDIR survives only as
# the git-textconv carrier and as the legacy escape hatch for any
# consumer still poking at it.
export SECURE_TMPDIR="$BATS_TEST_TMPDIR/secure-tmp"
mkdir -p "$SECURE_TMPDIR"

# Mock pivy-tool (canned card discovery) and mock piggy-ids. We
# copy-with-shebang-rewrite rather than symlink so the staged scripts
# work inside the nix build sandbox (where /usr/bin/env doesn't exist,
# breaking the helpers' `#!/usr/bin/env bash` shebang). The rewrite uses
# whichever bash is currently on PATH, which is the sandbox's
# `${pkgs.bash}/bin/bash` or the local devshell's bash depending on
# context.
# Install a helper from zz-tests_bats/helpers/ into $BATS_TEST_TMPDIR
# with its shebang rewritten to whichever bash is on PATH. Exposed for
# tests that need to install additional helpers (e.g. the fake editor
# in t0200-edit.bats).
piggy_install_helper_as() {
  local helper="$1" name="$2"
  local dest="$BATS_TEST_TMPDIR/$name"
  sed "1s|^#!.*|#!$(command -v bash)|" "$PIGGY_BATS_HELPERS_DIR/$helper" >"$dest"
  chmod +x "$dest"
}
piggy_install_helper_as mock-pivy-tool.sh pivy-tool
# Mock piggy-ids: `encrypt` execs the real Rust binary ($PIGGY_IDS_REAL),
# so every ebox a test writes is genuine RFC 0002 wire format encrypted
# to the virtual card below; only card *discovery* (detect-pubkey /
# detect-all-pubkeys) is canned, driven by PIGGY_TEST_DETECT_* env vars.
# validate / canonicalize / diff delegate to the real binary too. The
# lane builder pins PIGGY_IDS_REAL to the wrapped
# $out/libexec/piggy/piggy-ids; local runs fall back to target/debug/.
: "${PIGGY_IDS_REAL:=$REPO_ROOT/target/debug/piggy-ids}"
export PIGGY_IDS_REAL
piggy_install_helper_as mock-piggy-ids.sh piggy-ids
export PATH="$BATS_TEST_TMPDIR:$PATH"

# The virtual card (piggy#164, piggy#281). Store decrypt runs in process
# — there is no `pivy-box` subprocess left to mock — so every test gets
# its own fibby on a private PC/SC socket: real encrypt through piggy-ids,
# real ECDH on decrypt, PIN 123456 supplied by the test askpass (an
# installed copy: the sandbox has no /usr/bin/env for the helper's
# shebang, and a failing askpass looks exactly like a card refusing the
# PIN). PIGGY_TEST_RECIPIENT is that card's slot-9D recipient, the RFC
# 5903 seed fibby loads by default; create_test_template writes it and
# t0980 pins it against `piggy-ids detect-pubkey`.
#
# PIGGY_TEST_CARD=none opts a harness out (conformance/common.bash does:
# those lanes spawn their own fibby or run against a recipe-provided
# PC/SC socket), and a preset PCSCLITE_CSOCK_NAME is left alone for the
# same reason.
export PIGGY_TEST_RECIPIENT="piggy-recipient-v1@pivy_ecdh_p256_pub-q0ddpdjnjs3pe7ds28slajjhslgf3hlxxl7fpw00j3wscdmjtqgcqqshc3f"
load "$PIGGY_BATS_DIR/lib/fibby.bash"
if [[ ${PIGGY_TEST_CARD:-auto} == auto && -z ${PCSCLITE_CSOCK_NAME:-} ]]; then
  # The helper narrates on stderr ("[piggy-test-askpass] supplying …"),
  # which `run` would fold into $output and break exact-match asserts;
  # a thin wrapper keeps that narration in a per-test log instead.
  piggy_install_helper_as piggy-test-askpass.sh piggy-test-askpass.real
  export PIGGY_TEST_ASKPASS_LOG="$BATS_TEST_TMPDIR/askpass.log"
  printf '#!%s\nexec "%s" "$@" 2>>"%s"\n' "$(command -v bash)" \
    "$BATS_TEST_TMPDIR/piggy-test-askpass.real" "$PIGGY_TEST_ASKPASS_LOG" \
    >"$BATS_TEST_TMPDIR/piggy-test-askpass"
  chmod +x "$BATS_TEST_TMPDIR/piggy-test-askpass"
  export SSH_ASKPASS="$BATS_TEST_TMPDIR/piggy-test-askpass" \
    SSH_ASKPASS_REQUIRE=force DISPLAY="" PIGGY_TEST_FIB_PIN=123456
  # bats predefines a no-op teardown() (lib/bats-core/test_functions.bash),
  # so "is one declared" cannot tell a file's own teardown from the
  # default. Chain whatever is there and append fibby_down: the file's
  # teardown runs first, and the card always comes down — a leaked fibby
  # keeps bats' fd 3 open and bats waits on it forever.
  eval "$(declare -f teardown | sed '1s/^teardown ()/piggy_harness_chained_teardown ()/')"
  teardown() {
    local rc=0
    piggy_harness_chained_teardown || rc=$?
    fibby_down
    return "$rc"
  }
  fibby_up
fi

# Pre-init git repo with --separate-git-dir so the actual git data lives
# outside .git/ (sandcastle blocks writes to .git directories).
init_test_git() {
  git init --separate-git-dir="$BATS_TEST_TMPDIR/git-dir" --template="" "$PIGGY_STORE_DIR"
}

# Skip the calling test unless an AF_UNIX socket can actually be bind(2)ed
# under $BATS_TEST_TMPDIR in this environment. Two known failure modes, both on
# darwin (macOS):
#   - the darwin nix build sandbox denies AF_UNIX bind with EPERM ("Operation
#     not permitted") — so tests that bind a real socket to fixture a Wayland
#     display pass in CI (Linux `nix build .#bats-default`) yet fail the local
#     darwin pre-merge hook;
#   - a deep $BATS_TEST_TMPDIR (e.g. a nested worktree/scratch path) overruns
#     macOS's ~104-byte sun_path limit → "AF_UNIX path too long".
# Probe under the test tmpdir (same root the tests bind in) and skip rather
# than fail on either. See piggy#208 for the platform-safe unskip (fixture the
# socket without a real bind, or run these in a non-sandboxed lane).
skip_unless_af_unix_bind() {
  local probe py
  py="$(command -v python3 || true)"
  [[ -n $py ]] || skip "python3 not on PATH (AF_UNIX bind probe unavailable)"
  probe="$BATS_TEST_TMPDIR/af-unix-bind-probe.$$.sock"
  if ! "$py" -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' \
    "$probe" 2>/dev/null; then
    skip "AF_UNIX bind unavailable here (darwin sandbox EPERM or sun_path too long; piggy#208)"
  fi
  rm -f "$probe"
}

# Create a test piggy-ids file naming the virtual card's slot-9D key, so
# an insert/generate in the test encrypts to a key the harness card can
# actually unwrap.
create_test_template() {
  local dir="${1:-$PIGGY_STORE_DIR}"
  mkdir -p "$dir"
  cat >"$dir/piggy-ids" <<-_EOF
		# test fixture — the harness fibby card (RFC 5903 slot-9D seed)
		$PIGGY_TEST_RECIPIENT
		_EOF
}
