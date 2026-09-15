# Shared helpers for `hardware`-tagged bats lanes that touch a REAL card
# (piggy#286). Consumers `load` this from setup() after common.bash.
#
# require_throwaway_card GUID [SERIAL]
#   Fail the test — loudly, before any APDU that writes — unless the card
#   is on the operator's destructible allowlist (PIGGY_TEST_THROWAWAY_SERIALS
#   / PIGGY_TEST_THROWAWAY_GUIDS, environment only). Read-only lanes do not
#   need this; every lane that runs set-admin, import, factory-reset,
#   change-pin/puk or writes an object MUST call it.
require_throwaway_card() {
  local guid="${1:?require_throwaway_card: GUID required}" serial="${2:-}"
  local guard="$PIGGY_BATS_HELPERS_DIR/piggy-throwaway-guard.sh"
  local args=(--guid "$guid")
  [[ -n $serial ]] && args+=(--serial "$serial")
  if ! bash "$guard" "${args[@]}" 2>"$BATS_TEST_TMPDIR/throwaway-guard.err"; then
    cat "$BATS_TEST_TMPDIR/throwaway-guard.err" >&2
    fail "refusing to run a destructive step against card $guid: not allowlisted as throwaway (piggy#286)"
  fi
}
