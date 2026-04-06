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

# Git identity for test commits
export GIT_DIR="$PIGGY_STORE_DIR/.git"
export GIT_WORK_TREE="$PIGGY_STORE_DIR"
git config --global user.email "Piggy-Automated-Testing-Suite@test.local"
git config --global user.name "Piggy Automated Testing Suite"

# Piggy script under test
PIGGY="$REPO_ROOT/src/piggy.sh"

# Mock pivy-box and pivy-tool (base64 encode/decode instead of real crypto)
ln -sf "$REPO_ROOT/zz-tests_bats/helpers/mock-pivy-box.sh" "$BATS_TEST_TMPDIR/pivy-box"
ln -sf "$REPO_ROOT/zz-tests_bats/helpers/mock-pivy-tool.sh" "$BATS_TEST_TMPDIR/pivy-tool"
export PATH="$BATS_TEST_TMPDIR:$PATH"

# Create a test .pivy-id template (marker file for the mock)
create_test_template() {
  local dir="${1:-$PIGGY_STORE_DIR}"
  mkdir -p "$dir"
  echo "MOCK_PIVY_TEMPLATE_v1" >"$dir/.pivy-id"
}
