#! /usr/bin/env bats
# bats file_tags=hardware
#
# RFC 0012 §2.5 — the text must be showable: valid UTF-8, 1 to 4096 bytes, no
# C0 or C1 control other than LF and TAB. Anything else is `refused-text`
# (status 4) before any prompt, because a terminal escape could reflow or
# hide what the operator reads before typing the PIN.
#
# Stack and required env: zz-tests_bats/lib/operator_act.bash.

bats_require_minimum_version 1.5.0

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/fibby.bash"
  load "$(dirname "$BATS_TEST_FILE")/../lib/operator_act.bash"
  operator_act_setup
}

teardown() {
  operator_act_teardown
}

# N bytes of 'a' in FILE.
_text_of_length() {
  head -c "$1" /dev/zero | tr '\0' 'a' >"$2"
}

_assert_refused_text() {
  local what="$1"
  shift
  operator_act_probe "$AGENT_SOCK" --slot 9C "$@"
  assert_probe_status 4 "refused-text: $what"
}

function undisplayable_texts_are_refused_without_a_prompt { # @test
  operator_act_stack_up
  _text_of_length 4097 "$WORKDIR/oversize"

  _assert_refused_text "empty" --text ""
  _assert_refused_text "4097 bytes" --text-file "$WORKDIR/oversize"
  _assert_refused_text "ESC (terminal escape)" --text-hex 611b5b324a62
  _assert_refused_text "NUL" --text-hex 610062
  _assert_refused_text "carriage return" --text-hex 610d62
  _assert_refused_text "DEL" --text-hex 617f62
  _assert_refused_text "C1 control U+009B (CSI)" --text-hex 61c29b62
  _assert_refused_text "invalid UTF-8" --text-hex fffe
  _assert_refused_text "truncated UTF-8 sequence" --text-hex 61c3

  [[ $(operator_act_prompt_count "$AGENT_LOG") -eq 0 ]] ||
    operator_act_fail "a text refusal raised a PIN prompt"
}

function newline_tab_and_non_ascii_text_is_signed { # @test
  operator_act_stack_up
  # "grant:\tcafé\nline two ✓"
  operator_act_probe "$AGENT_SOCK" --slot 9C \
    --text-hex 6772616e743a09636166c3a90a6c696e652074776f20e29c93
  assert_probe_status 0 signed
}

function text_of_exactly_4096_bytes_is_signed { # @test
  operator_act_stack_up
  _text_of_length 4096 "$WORKDIR/limit"
  operator_act_probe "$AGENT_SOCK" --slot 9C --text-file "$WORKDIR/limit"
  assert_probe_status 0 signed
}
