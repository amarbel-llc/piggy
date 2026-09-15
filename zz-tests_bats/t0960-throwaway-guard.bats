#!/usr/bin/env bats
#
# The throwaway-card guard's decision rule (piggy#286), exercised without
# hardware: identity comes from --guid/--serial, the allowlists from the
# environment. The --probe path (pivy-tool list) is covered by the
# hardware lanes that use it.
bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  GUARD="$PIGGY_BATS_HELPERS_DIR/piggy-throwaway-guard.sh"
  unset PIGGY_TEST_THROWAWAY_SERIALS PIGGY_TEST_THROWAWAY_GUIDS
}

function guard_refuses_with_no_allowlists { # @test
  run -1 bash "$GUARD" --guid F55BF2A8AF0F95AF6F2FF417DACCA2B1
  assert_output --partial "REFUSING"
  assert_output --partial "PIGGY_TEST_THROWAWAY_SERIALS"
}

function guard_refuses_with_no_identity { # @test
  PIGGY_TEST_THROWAWAY_GUIDS=F55BF2A8AF0F95AF6F2FF417DACCA2B1 \
    run -1 bash "$GUARD"
  assert_output --partial "no card identity"
}

function guard_allows_listed_guid_when_no_serial { # @test
  PIGGY_TEST_THROWAWAY_GUIDS="0000 F55BF2A8AF0F95AF6F2FF417DACCA2B1" \
    run -0 bash "$GUARD" --guid f55bf2a8af0f95af6f2ff417dacca2b1
  assert_output --partial "allowlisted"
}

function guard_refuses_unlisted_guid { # @test
  PIGGY_TEST_THROWAWAY_GUIDS=F55BF2A8AF0F95AF6F2FF417DACCA2B1 \
    run -1 bash "$GUARD" --guid 5DA19C98257243EFCD29BE3AE91EA7F8
  assert_output --partial "REFUSING"
  assert_output --partial "not in PIGGY_TEST_THROWAWAY_GUIDS"
}

function guard_allows_listed_serial { # @test
  PIGGY_TEST_THROWAWAY_SERIALS="12345678 23456789" \
    run -0 bash "$GUARD" --guid 5DA19C98257243EFCD29BE3AE91EA7F8 --serial 23456789
  assert_output --partial "serial 23456789 is allowlisted"
}

function guard_serial_wins_over_listed_guid { # @test
  # A card that reports a serial is judged by the serial even when its
  # GUID is allowlisted: a re-provisioned throwaway keeps its serial but
  # a production card could inherit a stale GUID entry.
  PIGGY_TEST_THROWAWAY_GUIDS=5DA19C98257243EFCD29BE3AE91EA7F8 \
    PIGGY_TEST_THROWAWAY_SERIALS=12345678 \
    run -1 bash "$GUARD" --guid 5DA19C98257243EFCD29BE3AE91EA7F8 --serial 99999999
  assert_output --partial "serial 99999999"
  assert_output --partial "not in PIGGY_TEST_THROWAWAY_SERIALS"
}

function guard_serial_bearing_card_ignores_guid_list_only { # @test
  # Only a GUID list set, but the card reports a serial: refused — the
  # operator listed GUIDs for serial-less cards, not this one.
  PIGGY_TEST_THROWAWAY_GUIDS=5DA19C98257243EFCD29BE3AE91EA7F8 \
    run -1 bash "$GUARD" --guid 5DA19C98257243EFCD29BE3AE91EA7F8 --serial 12345678
  assert_output --partial "REFUSING"
}

function guard_rejects_unknown_flag { # @test
  run -2 bash "$GUARD" --bogus
  assert_output --partial "unknown argument"
}

function bats_library_helper_fails_loudly { # @test
  load "$PIGGY_BATS_DIR/lib/hardware.bash"
  PIGGY_TEST_THROWAWAY_GUIDS=F55BF2A8AF0F95AF6F2FF417DACCA2B1
  export PIGGY_TEST_THROWAWAY_GUIDS
  run require_throwaway_card 5DA19C98257243EFCD29BE3AE91EA7F8
  assert_failure
  assert_output --partial "refusing to run a destructive step"
  run require_throwaway_card F55BF2A8AF0F95AF6F2FF417DACCA2B1
  assert_success
}
