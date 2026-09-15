#!/usr/bin/env bash
# Throwaway-card guard (piggy#286): exit 0 only if the identified card is
# on the operator's destructible allowlist, else print why and exit 1.
#
#   piggy-throwaway-guard.sh --guid HEX [--serial N]
#   piggy-throwaway-guard.sh --probe            # identify via pivy-tool list
#                                               # (+ ykman for a YK4's serial)
#
# Allowlists come from the ENVIRONMENT, never the repo:
#   PIGGY_TEST_THROWAWAY_SERIALS   space-separated YubiKey serials
#   PIGGY_TEST_THROWAWAY_GUIDS     space-separated CHUID GUIDs (hex)
#
# Rule: a card that reports a serial is judged by the serial alone (a
# re-provisioned card keeps its serial but gets a fresh GUID, so the
# stronger identifier wins). A card that reports no serial — the older
# YubiKey 4 case, piggy#256 — is judged by its GUID. With neither list
# set every card is refused. Matching is case-insensitive on hex.
#
# In the spirit of the askpass safety net: refusing must be loud and
# must happen before any APDU that writes.
set -uo pipefail

guid=""
serial=""
probe=0
while [[ $# -gt 0 ]]; do
  case $1 in
    --guid)
      guid="${2:-}"
      shift 2
      ;;
    --serial)
      serial="${2:-}"
      shift 2
      ;;
    --probe)
      probe=1
      shift
      ;;
    *)
      echo "piggy-throwaway-guard: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ $probe -eq 1 ]]; then
  pivy_tool="${PIVY_TOOL:-pivy-tool}"
  listing="$("$pivy_tool" list 2>/dev/null)" || {
    echo "piggy-throwaway-guard: REFUSING — '$pivy_tool list' failed (no pcscd / no card?)" >&2
    exit 1
  }
  guids="$(printf '%s\n' "$listing" | awk '/guid:/ {print $2}')"
  count="$(printf '%s\n' "$guids" | grep -c . || true)"
  if [[ $count -ne 1 ]]; then
    echo "piggy-throwaway-guard: REFUSING — expected exactly one card, pivy-tool sees $count; pass --guid to select" >&2
    exit 1
  fi
  guid="$guids"
  serial="$("$pivy_tool" -g "$guid" list 2>/dev/null | awk '/serial:/ {print $2; exit}')"
fi

if [[ -z $guid && -z $serial ]]; then
  echo "piggy-throwaway-guard: REFUSING — no card identity given (--guid/--serial/--probe)" >&2
  exit 1
fi

# Older YubiKey 4 firmware does not report the serial through the PIV
# applet (piggy#256) but ykman reads it over the management interface.
# Applies to every identification path (--probe and a caller-supplied
# --guid without --serial): with exactly one device attached the mapping
# to the one GUID is unambiguous; otherwise leave it to the GUID rule.
# YKMAN=/path overrides the PATH lookup (also how the bats test mocks it).
if [[ -z $serial ]] && command -v "${YKMAN:-ykman}" >/dev/null 2>&1; then
  yk_serials="$("${YKMAN:-ykman}" list --serials 2>/dev/null | grep -E '^[0-9]+$' || true)"
  if [[ "$(printf '%s\n' "$yk_serials" | grep -c . || true)" -eq 1 ]]; then
    serial="$yk_serials"
    echo "piggy-throwaway-guard: serial $serial via ykman (PIV applet reported none)" >&2
  fi
fi

serials="${PIGGY_TEST_THROWAWAY_SERIALS:-}"
guids="${PIGGY_TEST_THROWAWAY_GUIDS:-}"
if [[ -z $serials && -z $guids ]]; then
  echo "piggy-throwaway-guard: REFUSING — neither PIGGY_TEST_THROWAWAY_SERIALS nor PIGGY_TEST_THROWAWAY_GUIDS is set" >&2
  echo "  set them in your environment (never in the repo) to the serials / CHUID GUIDs of cards you are willing to wipe" >&2
  exit 1
fi

upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }
listed() {
  local needle want
  needle="$(upper "$1")"
  for want in $2; do
    [[ "$(upper "$want")" == "$needle" ]] && return 0
  done
  return 1
}

if [[ -n $serial ]]; then
  if listed "$serial" "$serials"; then
    echo "piggy-throwaway-guard: serial $serial is allowlisted as throwaway" >&2
    exit 0
  fi
  echo "piggy-throwaway-guard: REFUSING — card serial $serial (guid ${guid:-?}) is not in PIGGY_TEST_THROWAWAY_SERIALS" >&2
  exit 1
fi

if listed "$guid" "$guids"; then
  echo "piggy-throwaway-guard: guid $guid (no serial reported) is allowlisted as throwaway" >&2
  exit 0
fi
echo "piggy-throwaway-guard: REFUSING — card guid $guid reports no serial and is not in PIGGY_TEST_THROWAWAY_GUIDS" >&2
exit 1
