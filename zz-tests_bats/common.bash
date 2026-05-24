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

# Use system getopt (nix provides gnu-getopt on PATH)
export PIGGY_GETOPT=getopt

# Repo root is the working directory where bats is invoked.
#
# Two modes share this harness:
#   - Local `bats --no-sandbox` from the repo root: $PWD = repo root.
#   - Nix-sandboxed bats lane (`bats.lib.${system}.batsLane`): $PWD = stage/zz-tests_bats/
#     and the helpers live at $PWD/helpers/ (no extra zz-tests_bats/
#     prefix). The lane builder injects $PIGGY, $PIGGY_SH_PATH, and
#     $PIGGY_IDS_REAL via extraEnv so we never need to resolve those
#     out of $REPO_ROOT in the sandbox path.
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
#   - $PIGGY is the rust dispatcher binary (NOT src/piggy.sh directly).
#     Every bash subcommand goes through the full rust → bash dispatch path
#     so the integration layer is exercised on every test run.
#   - $PIGGY_SH_PATH points the rust binary at the in-repo bash script.
#
# Resolution order: $PIGGY env var → target/debug/piggy → target/release/piggy.
# The nix lane (`bats.lib.${system}.batsLane`) injects $PIGGY pre-set; the
# `target/debug` fallback is only reached for local `bats --no-sandbox`
# runs. We deliberately do NOT fall back to src/piggy.sh — bypassing
# the rust dispatcher would hide regressions in the wrapper.
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
# `:=` so the lane builder's extraEnv (which points at the wrapped
# $out/libexec/piggy/piggy.sh) wins; local runs fall back to src/.
: "${PIGGY_SH_PATH:=$REPO_ROOT/src/piggy.sh}"
export PIGGY_SH_PATH

# Pre-set SECURE_TMPDIR so piggy skips ramdisk creation (sandbox-safe)
export SECURE_TMPDIR="$BATS_TEST_TMPDIR/secure-tmp"
mkdir -p "$SECURE_TMPDIR"

# Mock pivy-box and pivy-tool (base64 encode/decode instead of real crypto)
# and mock piggy-ids. We copy-with-shebang-rewrite rather than symlink so
# the staged scripts work inside the nix build sandbox (where
# /usr/bin/env doesn't exist, breaking the helpers' `#!/usr/bin/env bash`
# shebang). The rewrite uses whichever bash is currently on PATH, which
# is the sandbox's `${pkgs.bash}/bin/bash` or the local devshell's bash
# depending on context.
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
piggy_install_helper_as mock-pivy-box.sh pivy-box
piggy_install_helper_as mock-pivy-tool.sh pivy-tool
# Mock piggy-ids: encrypt → base64 (compatible with mock-pivy-box's
# decrypt). validate / canonicalize / diff delegate to the real Rust
# binary ($PIGGY_IDS_REAL). The lane builder pins this to the wrapped
# $out/libexec/piggy/piggy-ids; local runs fall back to target/debug/.
: "${PIGGY_IDS_REAL:=$REPO_ROOT/target/debug/piggy-ids}"
export PIGGY_IDS_REAL
piggy_install_helper_as mock-piggy-ids.sh piggy-ids
export PATH="$BATS_TEST_TMPDIR:$PATH"

# Pre-init git repo with --separate-git-dir so the actual git data lives
# outside .git/ (sandcastle blocks writes to .git directories).
init_test_git() {
  git init --separate-git-dir="$BATS_TEST_TMPDIR/git-dir" --template="" "$PIGGY_STORE_DIR"
}

# Create a test piggy-ids file with a canonical RFC 0002 recipient
# (the `pivy_ecdh_p256_pub` non-trivial vector at madder fd53684).
# The mock piggy-ids encrypt only checks file existence, so any valid
# piggy-ids works for tests that don't drive the recipients flow.
create_test_template() {
  local dir="${1:-$PIGGY_STORE_DIR}"
  mkdir -p "$dir"
  cat >"$dir/piggy-ids" <<-_EOF
		# test fixture — canonical RFC 0002 vector
		piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu
		_EOF
}
