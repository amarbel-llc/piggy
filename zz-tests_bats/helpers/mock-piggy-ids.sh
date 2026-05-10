#!/usr/bin/env bash
# Mock piggy-ids for testing without real ECDH crypto.
#
# `encrypt` is mocked: stdin → base64 → stdout (so the mock pivy-box's
# `stream decrypt` can round-trip via `base64 -d`). The .piggy-ids
# file is only checked for existence; its contents are not parsed.
#
# `detect-pubkey` is mocked: tests don't have a real PIV card, so
# emit a fixed RFC 0002 vector. PIGGY_TEST_DETECT_FAIL flips the
# command to a failure (covers the no-card error path).
#
# `validate`, `canonicalize`, `diff` are delegated to the real
# piggy-ids Rust binary (PIGGY_IDS_REAL, set by common.bash) so the
# recipients-flow tests exercise real validation logic.

set -euo pipefail

case "${1:-}" in
encrypt)
  ids="${2:-}"
  [[ -f $ids ]] || {
    echo "mock-piggy-ids: .piggy-ids not found: $ids" >&2
    exit 1
  }
  base64
  ;;
detect-pubkey)
  if [[ -n ${PIGGY_TEST_DETECT_FAIL:-} ]]; then
    echo "mock-piggy-ids: $PIGGY_TEST_DETECT_FAIL" >&2
    exit 1
  fi
  echo "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
  ;;
validate | canonicalize | diff)
  exec "${PIGGY_IDS_REAL:-piggy-ids}" "$@"
  ;;
*)
  echo "mock-piggy-ids: unknown command: ${1:-}" >&2
  exit 1
  ;;
esac
