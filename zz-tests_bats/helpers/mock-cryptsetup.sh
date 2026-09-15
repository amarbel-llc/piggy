#!/usr/bin/env bash
# Test mock for cryptsetup, used by t0900-luks.bats.
#
# Records its argv (space-joined) and whatever arrived on stdin to
# sentinel paths from the environment, then exits with
# $CRYPTSETUP_MOCK_EXIT (default 0). It never touches a block device.
# `piggy luks` installs this on PATH (via piggy_install_helper_as) so the
# argv shape and the passphrase bytes can be asserted without root or a
# LUKS volume.
set -o pipefail

: "${CRYPTSETUP_ARGV_FILE:?mock-cryptsetup: CRYPTSETUP_ARGV_FILE unset}"
: "${CRYPTSETUP_STDIN_FILE:?mock-cryptsetup: CRYPTSETUP_STDIN_FILE unset}"

printf '%s\n' "$*" >"$CRYPTSETUP_ARGV_FILE"

# Only read stdin when piggy piped a key file; an inherited tty stdin
# would block.
if [[ ! -t 0 ]]; then
  cat >"$CRYPTSETUP_STDIN_FILE"
else
  : >"$CRYPTSETUP_STDIN_FILE"
fi

exit "${CRYPTSETUP_MOCK_EXIT:-0}"
