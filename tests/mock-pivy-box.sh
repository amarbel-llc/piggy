#!/usr/bin/env bash
# Mock pivy-box for testing without a real PIV card.
# Encrypts with base64 (no real security), decrypts with base64 -d.
# Supports: stream encrypt/decrypt, tpl create/show

set -euo pipefail

case "${1:-}" in
stream)
  case "${2:-}" in
  encrypt)
    # Usage: mock-pivy-box stream encrypt <tpl-path>
    tpl="${3:-}"
    [[ -f $tpl ]] || {
      echo "error: template not found: $tpl" >&2
      exit 1
    }
    base64
    ;;
  decrypt)
    # Usage: mock-pivy-box stream decrypt < encrypted-data
    base64 -d
    ;;
  *)
    echo "error: unknown stream operation: ${2:-}" >&2
    exit 1
    ;;
  esac
  ;;
tpl)
  case "${2:-}" in
  create)
    # Usage: mock-pivy-box tpl create <name>
    # In tests, we pre-create .pivy-id files directly
    echo "error: use create_test_template instead" >&2
    exit 1
    ;;
  show)
    # Usage: mock-pivy-box tpl show [tpl-path]
    # or: mock-pivy-box tpl show < template-file
    if [[ -n ${3:-} && -f ${3:-} ]]; then
      cat "${3}"
    else
      cat
    fi
    ;;
  *)
    echo "error: unknown tpl operation: ${2:-}" >&2
    exit 1
    ;;
  esac
  ;;
*)
  echo "error: unknown command: ${1:-}" >&2
  exit 1
  ;;
esac
