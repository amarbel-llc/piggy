#! /usr/bin/env bats
#
# `piggy ca root-cert --profile NAME` (FDR 0007 phase (ii), piggy#391) off
# the card: the profile is the only input, read from piggy's config home,
# and every refusal answers from the one exit table the `ca` verbs share.
# Exit 2 usage, 3 for a profile that is unknown, unreadable or not a root
# profile (naming the path tried), 6 for an issuer card that is not there;
# nothing on stdout and no PIN prompt on any refusal. The signature itself
# needs a card holding a key in slot 82, which fibby does not model yet
# (piggy#399); the unit tests sign with a software key.
#
# Required env (supplied by `just test-bats-conformance-ca-root-cert`):
#   PIGGY_BIN=/path/to/piggy   (nix build .#default)

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  export output

  if [[ -z ${PIGGY_BIN:-} && -x ${REPO_ROOT:-/nonexistent}/target/debug/piggy ]]; then
    PIGGY_BIN="$REPO_ROOT/target/debug/piggy"
  fi
  if [[ -z ${PIGGY_BIN:-} ]] || [[ ! -x ${PIGGY_BIN:-/nonexistent} ]]; then
    skip "PIGGY_BIN unset or not executable; run via just test-bats-conformance-ca-root-cert"
  fi

  # piggy-testing(7) PIN PROMPT SAFETY NET: no refusal here may reach a
  # prompt; the test askpass leaves a banner on stderr if one does, and
  # with no PIGGY_TEST_FIB_PIN it refuses.
  ASKPASS="$PIGGY_BATS_HELPERS_DIR/piggy-test-askpass.sh"
  [[ -x $ASKPASS ]] || skip "piggy-test-askpass.sh not found at $ASKPASS"
  export SSH_ASKPASS="$ASKPASS"
  export SSH_ASKPASS_REQUIRE=force
  export DISPLAY=""
  unset WAYLAND_DISPLAY SSH_AUTH_SOCK PIGGY_AUTH_SOCK PIGGY_TEST_FIB_PIN

  WORKDIR="$(mktemp -d -t rootcert.XXXXXX)"
  CONFIG="$WORKDIR/config"
  mkdir -p "$CONFIG/ca-profiles"
  export PIGGY_CONFIG_HOME="$CONFIG"
  # No PC/SC daemon answers here: a card the profile names is "not attached".
  export PCSCLITE_CSOCK_NAME="$WORKDIR/no-pcscd.comm"
}

teardown() {
  [[ -n ${WORKDIR:-} ]] && rm -rf "$WORKDIR" 2>/dev/null || true
  teardown_test_home 2>/dev/null || true
}

GUID=0123456789ABCDEF0123456789ABCDEF

_root_profile() {
  cat >"$CONFIG/ca-profiles/$1.toml" <<EOF
kind = "root"
common_name = "piggy-test root"
names = ["github.com", "api.github.com"]
lifetime_hours = 87600
$2
[issuer]
slot = "82"
guid = "$GUID"
EOF
}

_root_cert() {
  run "$PIGGY_BIN" ca root-cert "$@"
}

_assert_refusal() {
  local want="$1" why="$2"
  [[ $status -eq $want ]] || { echo "$why: want exit $want, got $status: $output" >&2; return 1; }
  [[ $output != *"BEGIN CERTIFICATE"* ]] || { echo "$why: a refusal printed a certificate" >&2; return 1; }
  [[ $output != *"piggy-test-askpass"* ]] || { echo "$why: a refusal reached the PIN prompt" >&2; return 1; }
}

function the_profile_is_required_and_the_only_issuer_source { # @test
  _root_cert
  _assert_refusal 2 "no --profile"
  _root_cert --profile x --slot 82
  _assert_refusal 2 "a slot flag"
}

function an_unknown_or_unreadable_profile_is_exit_3_naming_the_path { # @test
  _root_cert --profile missing
  _assert_refusal 3 "missing profile"
  [[ $output == *"$CONFIG/ca-profiles/missing.toml"* ]] || {
    echo "the path tried is not named: $output" >&2; return 1; }

  _root_cert --profile ../etc
  _assert_refusal 3 "a name that leaves the directory"

  _root_profile typo 'allow_wildcards = true'
  _root_cert --profile typo
  _assert_refusal 3 "an unknown field"
  [[ $output == *"typo.toml"* && $output == *"allow_wildcards"* ]] || {
    echo "the unknown field and the path are not named: $output" >&2; return 1; }
}

function only_a_root_profile_is_certified { # @test
  cat >"$CONFIG/ca-profiles/leaf.toml" <<EOF
kind = "leaf"
names = ["github.com"]
lifetime_hours = 720
[issuer]
slot = "82"
guid = "$GUID"
EOF
  _root_cert --profile leaf
  _assert_refusal 3 "a leaf profile"
  [[ $output == *"leaf profile"* ]] || { echo "the kind is not named: $output" >&2; return 1; }
}

function an_absent_issuer_card_is_exit_6_before_any_prompt { # @test
  _root_profile shithub ''
  _root_cert --profile shithub
  _assert_refusal 6 "no card"
  # PC/SC cannot be reached at all here; the message says so rather than
  # pretending a card was looked for.
  [[ $output == *"PC/SC"* || $output == *"$GUID"* ]] || {
    echo "the refusal names neither PC/SC nor the card: $output" >&2; return 1; }
}

function the_config_home_falls_back_to_xdg_then_home { # @test
  _root_profile shithub ''
  mkdir -p "$WORKDIR/xdg/piggy/ca-profiles" "$WORKDIR/home/.config/piggy/ca-profiles"
  cp "$CONFIG/ca-profiles/shithub.toml" "$WORKDIR/xdg/piggy/ca-profiles/viaxdg.toml"
  cp "$CONFIG/ca-profiles/shithub.toml" "$WORKDIR/home/.config/piggy/ca-profiles/viahome.toml"

  run env -u PIGGY_CONFIG_HOME XDG_CONFIG_HOME="$WORKDIR/xdg" HOME="$WORKDIR/home" \
    "$PIGGY_BIN" ca root-cert --profile viaxdg
  _assert_refusal 6 "read through XDG_CONFIG_HOME (past the profile, to the card)"
  run env -u PIGGY_CONFIG_HOME XDG_CONFIG_HOME="$WORKDIR/xdg" HOME="$WORKDIR/home" \
    "$PIGGY_BIN" ca root-cert --profile viahome
  _assert_refusal 3 "XDG_CONFIG_HOME set: HOME is not consulted"
  run env -u PIGGY_CONFIG_HOME -u XDG_CONFIG_HOME HOME="$WORKDIR/home" \
    "$PIGGY_BIN" ca root-cert --profile viahome
  _assert_refusal 6 "read through HOME"
  # PIGGY_CONFIG_HOME wins over both.
  run env XDG_CONFIG_HOME="$WORKDIR/xdg" HOME="$WORKDIR/home" \
    "$PIGGY_BIN" ca root-cert --profile viaxdg
  _assert_refusal 3 "PIGGY_CONFIG_HOME set: XDG_CONFIG_HOME is not consulted"
}
