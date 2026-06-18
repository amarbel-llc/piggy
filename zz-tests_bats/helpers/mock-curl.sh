#!/usr/bin/env bash
# Test mock for curl, used by t0900-papi.bats to drive `piggy papi verify`
# without network. Looks up a fixture file by the requested URL (the last
# argv) under $MOCK_CURL_DIR, sanitizing the URL to a filename. Prints the
# fixture body on stdout and exits 0; a missing fixture exits 22 (curl's
# HTTP-error code under -f), which `papi verify` renders as a fetch failure.
#
# `piggy papi verify` invokes `curl -fsS --proto =https … <url>` with the URL
# last, so $# (last arg) is the URL regardless of the bounded flags.
set -o pipefail

: "${MOCK_CURL_DIR:?mock-curl: MOCK_CURL_DIR unset}"

url="${!#}"
key="$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
fixture="$MOCK_CURL_DIR/$key"

if [[ -f $fixture ]]; then
  cat "$fixture"
  exit 0
fi

printf 'mock-curl: no fixture for %s (key %s)\n' "$url" "$key" >&2
exit 22
