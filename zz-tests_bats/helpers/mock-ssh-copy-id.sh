#!/usr/bin/env bash
# Test mock for ssh-copy-id, used by t0800-ssh-copy-id.bats.
#
# Records its argv and the contents of the `-i <file>` it was handed to
# sentinel paths from the environment, then exits 0 — it never contacts a
# real host. `piggy ssh-copy-id` installs this on PATH (via
# piggy_install_helper_as) so the rendered authorized_keys lines can be
# asserted without SSH.
set -o pipefail

: "${SSH_COPY_ID_ARGV_FILE:?mock-ssh-copy-id: SSH_COPY_ID_ARGV_FILE unset}"
: "${SSH_COPY_ID_KEYS_FILE:?mock-ssh-copy-id: SSH_COPY_ID_KEYS_FILE unset}"

# Record the full argv (space-joined) for the caller to assert on.
printf '%s\n' "$*" >"$SSH_COPY_ID_ARGV_FILE"

# Dump the file passed to `-i` so the caller can inspect the rendered keys.
prev=""
for arg in "$@"; do
  if [[ $prev == "-i" ]]; then
    cat "$arg" >"$SSH_COPY_ID_KEYS_FILE" 2>/dev/null || true
  fi
  prev="$arg"
done

exit 0
