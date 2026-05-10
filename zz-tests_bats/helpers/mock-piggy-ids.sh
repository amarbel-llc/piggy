#!/usr/bin/env bash
# Mock piggy-ids for testing without real ECDH crypto.
#
# `encrypt` is mocked: stdin → base64 → stdout (so the mock pivy-box's
# `stream decrypt` can round-trip via `base64 -d`). The .piggy-ids
# file is only checked for existence; its contents are not parsed.
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
validate | canonicalize | diff)
  exec "${PIGGY_IDS_REAL:-piggy-ids}" "$@"
  ;;
*)
  echo "mock-piggy-ids: unknown command: ${1:-}" >&2
  exit 1
  ;;
esac
