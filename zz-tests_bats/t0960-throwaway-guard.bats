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

# ykman fallback: a mock on YKMAN prints whatever YKMAN_MOCK_SERIALS holds,
# one per line, standing in for `ykman list --serials`.
mock_ykman() {
  local mock="$BATS_TEST_TMPDIR/ykman"
  printf '#!%s\nprintf "%%s\\n" $YKMAN_MOCK_SERIALS\n' "$(command -v bash)" >"$mock"
  chmod +x "$mock"
  export YKMAN="$mock"
}

function guard_guid_path_takes_serial_from_ykman_when_applet_has_none { # @test
  # The explore-rust-card-unlock-hw shape: caller passes --guid only (the
  # PIV applet reported no serial); with one device ykman supplies it and
  # the serial list decides, so a GUID allowlist is not needed.
  mock_ykman
  YKMAN_MOCK_SERIALS=87654321 PIGGY_TEST_THROWAWAY_SERIALS=87654321 \
    run -0 bash "$GUARD" --guid 0123456789ABCDEF0123456789ABCDEF
  assert_output --partial "serial 87654321 via ykman"
  assert_output --partial "allowlisted"
}

function guard_ykman_serial_refuses_when_not_listed_even_if_guid_is { # @test
  mock_ykman
  YKMAN_MOCK_SERIALS=87654321 PIGGY_TEST_THROWAWAY_GUIDS=0123456789ABCDEF0123456789ABCDEF \
    run -1 bash "$GUARD" --guid 0123456789ABCDEF0123456789ABCDEF
  assert_output --partial "not in PIGGY_TEST_THROWAWAY_SERIALS"
}

function guard_ignores_ykman_when_several_devices_are_attached { # @test
  # Two serials cannot be mapped to one GUID; fall back to the GUID rule.
  mock_ykman
  YKMAN_MOCK_SERIALS="87654321 11111111" PIGGY_TEST_THROWAWAY_GUIDS=0123456789ABCDEF0123456789ABCDEF \
    run -0 bash "$GUARD" --guid 0123456789ABCDEF0123456789ABCDEF
  refute_output --partial "via ykman"
  assert_output --partial "no serial reported"
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
