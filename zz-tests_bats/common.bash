bats_load_library bats-support
bats_load_library bats-assert
bats_load_library bats-island
bats_load_library bats-emo

require_bin PIVY_BOX_BIN pivy-box
PIVY_BOX_BIN="${PIVY_BOX_BIN:-pivy-box}"

require_bin PIVY_TOOL_BIN pivy-tool
PIVY_TOOL_BIN="${PIVY_TOOL_BIN:-pivy-tool}"

# Isolate HOME and XDG dirs to test tmpdir
setup_test_home

# Detect a PIV device GUID, set DETECTED_GUID, or skip.
# Must be called at the top level of a test, not inside $().
detect_guid_or_skip() {
  DETECTED_GUID="$("$PIVY_TOOL_BIN" list 2>/dev/null | grep '^ *guid:' | head -1 | awk '{print $2}')" || true
  if [[ -z $DETECTED_GUID ]]; then
    skip "no PIV device found"
  fi
}
