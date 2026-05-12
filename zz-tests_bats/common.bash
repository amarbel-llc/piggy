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

# Repo root is the working directory where bats is invoked
REPO_ROOT="$PWD"

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
# We deliberately do NOT fall back to src/piggy.sh — bypassing the rust
# dispatcher would hide regressions in the wrapper.
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
export PIGGY_SH_PATH="$REPO_ROOT/src/piggy.sh"

# Pre-set SECURE_TMPDIR so piggy skips ramdisk creation (sandbox-safe)
export SECURE_TMPDIR="$BATS_TEST_TMPDIR/secure-tmp"
mkdir -p "$SECURE_TMPDIR"

# Mock pivy-box and pivy-tool (base64 encode/decode instead of real crypto)
ln -sf "$REPO_ROOT/zz-tests_bats/helpers/mock-pivy-box.sh" "$BATS_TEST_TMPDIR/pivy-box"
ln -sf "$REPO_ROOT/zz-tests_bats/helpers/mock-pivy-tool.sh" "$BATS_TEST_TMPDIR/pivy-tool"
# Mock piggy-ids: encrypt → base64 (compatible with mock-pivy-box's
# decrypt). validate / canonicalize / diff delegate to the real Rust
# binary (PIGGY_IDS_REAL set below).
export PIGGY_IDS_REAL="$REPO_ROOT/target/debug/piggy-ids"
ln -sf "$REPO_ROOT/zz-tests_bats/helpers/mock-piggy-ids.sh" "$BATS_TEST_TMPDIR/piggy-ids"
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
