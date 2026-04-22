#! /usr/bin/env bats

setup() {
  load "$(dirname "$BATS_TEST_FILE")/common.bash"
  setup_test_home
  export output
}

teardown() {
  teardown_test_home
}

stub_service_commands() {
  # Stub out service management commands so tests don't escape the sandbox.
  # pivy-agent calls systemctl (Linux) or launchctl (macOS) which would
  # otherwise talk to the real service manager.
  local stub_dir="$BATS_TEST_TMPDIR/stub-bin"
  local exit_code="${1:-0}"
  mkdir -p "$stub_dir"
  printf '#!/bin/sh\nexit %s\n' "$exit_code" >"$stub_dir/systemctl"
  printf '#!/bin/sh\nexit %s\n' "$exit_code" >"$stub_dir/launchctl"
  chmod +x "$stub_dir/systemctl" "$stub_dir/launchctl"
  PATH="$stub_dir:$PATH"
}

install_service_setup() {
  if [[ "$(uname)" == "Darwin" ]]; then
    mkdir -p "$HOME/Library"
    SERVICE_FILE="$HOME/Library/LaunchAgents/net.cooperi.pivy-agent.plist"
  else
    local config_home="${XDG_CONFIG_HOME:-$HOME/.config}"
    mkdir -p "$config_home"
    SERVICE_FILE="$config_home/systemd/user/pivy-agent@.service"
  fi
  stub_service_commands
}

function no_args_prints_usage_and_fails { # @test
  run pivy-agent
  assert_failure
  assert_output --partial "usage: pivy-agent"
}

function bad_option_prints_usage_and_fails { # @test
  run pivy-agent -Q
  assert_failure
  assert_output --partial "usage: pivy-agent"
}

# --- install-service ---

function install_service_bad_option_fails { # @test
  run pivy-agent install-service -Z
  assert_failure
  assert_output --partial "usage: pivy-agent install-service"
}

function install_service_mutually_exclusive_A_and_g_fails { # @test
  run pivy-agent install-service -A -g 0000
  assert_failure
  assert_output --partial "-A and -g are mutually exclusive"
}

function install_service_writes_service_file_with_socket_path { # @test
  install_service_setup

  # service management commands fail in test sandbox, but files should be written
  run pivy-agent install-service -A -a /tmp/first.sock
  assert [ -f "$SERVICE_FILE" ]
  run grep '/tmp/first.sock' "$SERVICE_FILE"
  assert_success
}

function install_service_reinstall_updates_socket_path { # @test
  install_service_setup

  run pivy-agent install-service -A -a /tmp/first.sock
  assert [ -f "$SERVICE_FILE" ]

  run pivy-agent install-service -A -a /tmp/second.sock
  run grep '/tmp/second.sock' "$SERVICE_FILE"
  assert_success
  run grep '/tmp/first.sock' "$SERVICE_FILE"
  assert_failure
}

function install_service_contains_askpass_env { # @test
  install_service_setup

  run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$SERVICE_FILE" ]
  run grep 'SSH_ASKPASS' "$SERVICE_FILE"
  assert_success
  run grep 'SSH_ASKPASS_REQUIRE' "$SERVICE_FILE"
  assert_success
  run grep 'force' "$SERVICE_FILE"
  assert_success
}

function install_service_contains_notify_env { # @test
  install_service_setup

  run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$SERVICE_FILE" ]
  run grep 'SSH_NOTIFY_SEND' "$SERVICE_FILE"
  assert_success
}

function install_service_contains_confirm_env { # @test
  install_service_setup

  run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$SERVICE_FILE" ]
  run grep 'SSH_CONFIRM' "$SERVICE_FILE"
  assert_success
}

function install_service_no_askpass_omits_askpass_env { # @test
  install_service_setup

  run pivy-agent install-service -A -a /tmp/test.sock --no-askpass
  assert [ -f "$SERVICE_FILE" ]
  run grep 'SSH_ASKPASS' "$SERVICE_FILE"
  assert_failure
}

function install_service_no_notify_omits_notify_env { # @test
  install_service_setup

  run pivy-agent install-service -A -a /tmp/test.sock --no-notify
  assert [ -f "$SERVICE_FILE" ]
  run grep 'SSH_NOTIFY_SEND' "$SERVICE_FILE"
  assert_failure
}

# --- restart-service ---

function restart_service_fails_without_service_installed { # @test
  stub_service_commands 1
  run pivy-agent restart-service
  assert_failure
  assert_output --partial "restart failed"
}

# --- uninstall-service ---

function uninstall_service_recognized_as_subcommand { # @test
  stub_service_commands
  run pivy-agent uninstall-service
  assert_success
  assert_output --partial "Uninstalled"
}

# --- XDG path behavior ---

function install_service_uses_xdg_config_home_when_set { # @test
  local xdg_dir="$BATS_TEST_TMPDIR/xdg-config"
  export XDG_CONFIG_HOME="$xdg_dir"
  stub_service_commands

  if [[ "$(uname)" == "Darwin" ]]; then
    mkdir -p "$HOME/Library"
    run pivy-agent install-service -A -a /tmp/xdg-test.sock
    # macOS plist stays in ~/Library/LaunchAgents regardless of XDG
    assert [ -f "$HOME/Library/LaunchAgents/net.cooperi.pivy-agent.plist" ]
  else
    run pivy-agent install-service -A -a /tmp/xdg-test.sock
    assert [ -f "$xdg_dir/systemd/user/pivy-agent@.service" ]
    assert [ -f "$xdg_dir/pivy-agent/default" ]
    # Legacy path should NOT be created
    assert [ ! -f "$HOME/.config/systemd/user/pivy-agent@.service" ]
  fi
}

function install_service_xdg_log_home_used_on_macos { # @test
  if [[ "$(uname)" != "Darwin" ]]; then
    skip "macOS-only test"
  fi

  local log_dir="$BATS_TEST_TMPDIR/xdg-log"
  export XDG_LOG_HOME="$log_dir"
  mkdir -p "$HOME/Library"
  stub_service_commands

  run pivy-agent install-service -A -a /tmp/log-test.sock
  local plist="$HOME/Library/LaunchAgents/net.cooperi.pivy-agent.plist"
  assert [ -f "$plist" ]
  run grep "$log_dir/pivy/pivy-agent.log" "$plist"
  assert_success
  assert [ -d "$log_dir/pivy" ]
}

function uninstall_service_removes_xdg_and_legacy_paths { # @test
  if [[ "$(uname)" == "Darwin" ]]; then
    skip "Linux-only test"
  fi

  local xdg_dir="$BATS_TEST_TMPDIR/xdg-config"
  export XDG_CONFIG_HOME="$xdg_dir"
  stub_service_commands

  # Install to XDG path
  run pivy-agent install-service -A -a /tmp/test.sock
  assert [ -f "$xdg_dir/systemd/user/pivy-agent@.service" ]
  assert [ -f "$xdg_dir/pivy-agent/default" ]

  # Also create legacy files to simulate migration scenario
  mkdir -p "$HOME/.config/systemd/user"
  mkdir -p "$HOME/.config/pivy-agent"
  touch "$HOME/.config/systemd/user/pivy-agent@.service"
  touch "$HOME/.config/pivy-agent/default"

  run pivy-agent uninstall-service
  assert_success
  # Both XDG and legacy should be removed
  assert [ ! -f "$xdg_dir/systemd/user/pivy-agent@.service" ]
  assert [ ! -f "$xdg_dir/pivy-agent/default" ]
  assert [ ! -f "$HOME/.config/systemd/user/pivy-agent@.service" ]
  assert [ ! -f "$HOME/.config/pivy-agent/default" ]
}
