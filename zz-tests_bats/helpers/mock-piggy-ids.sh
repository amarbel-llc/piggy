#!/usr/bin/env bash
# Mock piggy-ids for testing without real ECDH crypto.
#
# `encrypt` is mocked: stdin → base64 → stdout (so the mock pivy-box's
# `stream decrypt` can round-trip via `base64 -d`). The piggy-ids
# file is only checked for existence; its contents are not parsed.
#
# `detect-pubkey` is mocked: tests don't have a real PIV card, so
# emit a fixed RFC 0002 vector. PIGGY_TEST_DETECT_FAIL flips the
# command to a failure (covers the no-card error path).
#
# `detect-all-pubkeys` is mocked: canned tab-separated output driven
# by env vars (matches the real binary's TAB-delimited format).
#   PIGGY_TEST_DETECT_ALL_SUPPORTED   newline-separated lines of
#                                     "<markl-id>\t<guid-hex>"
#   PIGGY_TEST_DETECT_ALL_UNSUPPORTED newline-separated lines of
#                                     "<guid-hex>\t<reason>"
#   PIGGY_TEST_DETECT_ALL_FAIL        if set, command fails with this
#                                     stderr message (exit 1)
# Unset env vars → empty output (i.e. no cards attached).
#
# Note: the real piggy-ids detect-all-pubkeys subcommand sorts
# emitted lines by GUID. The mock emits lines in the order they
# appear in the env vars (supported first, then unsupported).
# Tests that assert output ORDER (not content) should pre-sort
# their env-var lines by GUID hex to match the real binary.
#
# `validate`, `canonicalize`, `diff` are delegated to the real
# piggy-ids Rust binary (PIGGY_IDS_REAL, set by common.bash) so the
# recipients-flow tests exercise real validation logic.

set -euo pipefail

case "${1:-}" in
encrypt)
  ids="${2:-}"
  [[ -f $ids ]] || {
    echo "mock-piggy-ids: piggy-ids not found: $ids" >&2
    exit 1
  }
  # Mirror the real binary's age-recipient rejection so bats tests
  # can exercise the bash-level error path. Real piggy-ids encrypt
  # surfaces BoxError::UnsupportedRecipientFormat for any
  # age_x25519_pub recipient until piggy RFC 0004 lands.
  if grep -q '@age_x25519_pub-\|^age_x25519_pub-' "$ids"; then
    echo "recipient format AgeX25519Pub not yet wired into the encrypt pipeline" >&2
    exit 1
  fi
  base64
  ;;
detect-pubkey)
  if [[ -n ${PIGGY_TEST_DETECT_FAIL:-} ]]; then
    echo "mock-piggy-ids: $PIGGY_TEST_DETECT_FAIL" >&2
    exit 1
  fi
  echo "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqr9fwqu"
  ;;
detect-all-pubkeys)
  # Canned output via env vars. Each var is newline-separated.
  # PIGGY_TEST_DETECT_ALL_SUPPORTED: lines of "<markl-id>\t<guid-hex>"
  # PIGGY_TEST_DETECT_ALL_UNSUPPORTED: lines of "<guid-hex>\t<reason>"
  # Unset → empty output (i.e. no cards attached).
  if [[ -n ${PIGGY_TEST_DETECT_ALL_FAIL:-} ]]; then
    echo "mock-piggy-ids: $PIGGY_TEST_DETECT_ALL_FAIL" >&2
    exit 1
  fi
  # Normalize GUID hex to uppercase to match the real piggy-ids binary's hex::encode_upper output.
  while IFS=$'\t' read -r id guid; do
    # Skip the trailing-newline noise from <<<""; fail loudly on partial lines.
    [[ -z $id && -z $guid ]] && continue
    [[ -z $id || -z $guid ]] && {
      echo "mock-piggy-ids: malformed PIGGY_TEST_DETECT_ALL_SUPPORTED line: id=[$id] guid=[$guid]" >&2
      exit 1
    }
    printf 'supported\t%s\t%s\n' "$id" "${guid^^}"
  done <<<"${PIGGY_TEST_DETECT_ALL_SUPPORTED:-}"
  while IFS=$'\t' read -r guid reason; do
    [[ -z $guid && -z $reason ]] && continue
    [[ -z $guid || -z $reason ]] && {
      echo "mock-piggy-ids: malformed PIGGY_TEST_DETECT_ALL_UNSUPPORTED line: guid=[$guid] reason=[$reason]" >&2
      exit 1
    }
    printf 'unsupported\t%s\t%s\n' "${guid^^}" "$reason"
  done <<<"${PIGGY_TEST_DETECT_ALL_UNSUPPORTED:-}"
  ;;
validate | canonicalize | diff)
  exec "${PIGGY_IDS_REAL:-piggy-ids}" "$@"
  ;;
*)
  echo "mock-piggy-ids: unknown command: ${1:-}" >&2
  exit 1
  ;;
esac
