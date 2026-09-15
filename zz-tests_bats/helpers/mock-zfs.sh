#!/usr/bin/env bash
# Test mock for zfs, used by t0910-zfs.bats.
#
# Records its argv (space-joined) and whatever arrived on stdin to
# sentinel paths from the environment, then exits with $ZFS_MOCK_EXIT
# (default 0). It never touches a pool. `piggy zfs` installs this on PATH
# (via piggy_install_helper_as) so the argv shape and the passphrase
# bytes can be asserted without root or the zfs kernel module.
set -o pipefail

: "${ZFS_ARGV_FILE:?mock-zfs: ZFS_ARGV_FILE unset}"
: "${ZFS_STDIN_FILE:?mock-zfs: ZFS_STDIN_FILE unset}"

printf '%s\n' "$*" >"$ZFS_ARGV_FILE"
if [[ ! -t 0 ]]; then
  cat >"$ZFS_STDIN_FILE"
else
  : >"$ZFS_STDIN_FILE"
fi

exit "${ZFS_MOCK_EXIT:-0}"
