#!/usr/bin/env bash
# Mock pivy-tool for testing without a real PIV card.
set -euo pipefail

case "${1:-}" in
  pubkey)
    # Usage: mock-pivy-tool pubkey <slot>
    echo "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFAKEKEYDATA= PIV_slot_${2:-9A}@TESTGUID"
    ;;
  list)
    cat <<'EOF'
      card: TESTGUID
    device: Test Virtual PIV
     chuid: ok
      guid: TESTGUID1234567890ABCDEF
     slots:
           ID   TYPE     BITS  CERTIFICATE
           9a   ECDSA    256   /CN=test
EOF
    ;;
  *)
    echo "error: unknown operation: ${1:-}" >&2
    exit 1
    ;;
esac
