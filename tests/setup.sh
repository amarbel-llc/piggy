# This file should be sourced by all test-scripts
#
# This scripts sets the following:
#   $PIGGY      Full path to piggy script to test
#   $TEST_HOME  This folder

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

# Use system getopt (nix provides gnu-getopt on PATH), bypassing darwin.sh's
# homebrew resolution which may hang or point to a non-existent path.
export PIGGY_GETOPT=getopt

# We must be called from tests/
TEST_HOME="$(pwd)"

. ./sharness.sh

export PIGGY_STORE_DIR="$SHARNESS_TRASH_DIRECTORY/test-store/"
rm -rf "$PIGGY_STORE_DIR"
mkdir -p "$PIGGY_STORE_DIR"
if [[ ! -d $PIGGY_STORE_DIR ]]; then
  echo "Could not create $PIGGY_STORE_DIR"
  exit 1
fi

export GIT_DIR="$PIGGY_STORE_DIR/.git"
export GIT_WORK_TREE="$PIGGY_STORE_DIR"
git config --global user.email "Piggy-Automated-Testing-Suite@test.local"
git config --global user.name "Piggy Automated Testing Suite"

PIGGY="$TEST_HOME/../src/piggy.sh"
if [[ ! -e $PIGGY ]]; then
  echo "Could not find piggy.sh"
  exit 1
fi

# Use mock pivy-box and pivy-tool for testing without a real PIV card
ln -sf "$TEST_HOME/mock-pivy-box.sh" "$SHARNESS_TRASH_DIRECTORY/pivy-box"
ln -sf "$TEST_HOME/mock-pivy-tool.sh" "$SHARNESS_TRASH_DIRECTORY/pivy-tool"
export PATH="$SHARNESS_TRASH_DIRECTORY:$PATH"

# Create a test .pivy-id template (just a marker file for the mock)
create_test_template() {
  local dir="${1:-$PIGGY_STORE_DIR}"
  mkdir -p "$dir"
  echo "MOCK_PIVY_TEMPLATE_v1" >"$dir/.pivy-id"
}
