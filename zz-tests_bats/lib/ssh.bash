# Test SSH server (piggy-test-sshd) lifecycle for the SSH-over-fibby lane
# (piggy#135 Phase D). Mirrors madder's zz-tests_bats/lib/sftp.bash.
#
# Consumers `load` this from setup() after setting:
#   SSHD_BIN   — piggy-test-sshd binary (from the just recipe env)
#   WORKDIR    — short /tmp dir (the forwarded-agent socket the server arms
#                must fit AF_UNIX sun_path, so keep it short)
#
# start_test_sshd opens fd 9 to the server's stdin fifo (EOF = shutdown),
# parses the RFC-0001 handshake, and exports:
#   SSHD_PID, SSHD_PORT, SSHD_KNOWN_HOSTS, SSHD_CLIENT_HOME, SSHD_CLIENT_KEY,
#   SSHD_ERR
# stop_test_sshd kills the server and closes fd 9.

# Start piggy-test-sshd and block until its handshake line lands. Returns
# non-zero (with diagnostics on stderr) if the server never handshakes.
start_test_sshd() {
  local hs="$WORKDIR/sshd.handshake" fifo="$WORKDIR/sshd.fifo"
  SSHD_ERR="$WORKDIR/sshd.err"
  mkfifo "$fifo"
  local cookie
  cookie=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  # stdin from the fifo so we control EOF (the RFC-0001 shutdown signal);
  # fd 9 holds the write end open until stop_test_sshd.
  PIGGY_PLUGIN_COOKIE="$cookie" "$SSHD_BIN" <"$fifo" >"$hs" 2>"$SSHD_ERR" &
  SSHD_PID=$!
  exec 9>"$fifo"

  local _
  for _ in $(seq 1 50); do
    [[ -s $hs ]] && break
    sleep 0.1
  done
  [[ -s $hs ]] || {
    echo "piggy-test-sshd: no handshake line" >&2
    cat "$SSHD_ERR" >&2 || true
    return 1
  }

  local line got_cookie addr kh_field
  line=$(head -1 "$hs")
  IFS='|' read -r got_cookie _ _ addr kh_field _ <<<"$line"
  [[ $got_cookie == "$cookie" ]] || {
    echo "piggy-test-sshd: cookie mismatch (got '$got_cookie', want '$cookie')" >&2
    return 1
  }
  SSHD_PORT="${addr##*:}"
  SSHD_KNOWN_HOSTS="${kh_field#known_hosts=}"
  [[ -s $SSHD_KNOWN_HOSTS ]] || {
    echo "piggy-test-sshd: known_hosts missing at '$SSHD_KNOWN_HOSTS'" >&2
    return 1
  }

  # Ephemeral client key + pristine HOME so the env-isolated ssh below
  # neither inherits nor fights the operator's ssh config / agent / the
  # home-manager ssh wrapper. Same shape as `just debug-piggy-test-sshd`.
  SSHD_CLIENT_KEY="$WORKDIR/ssh_id"
  ssh-keygen -t ed25519 -N '' -f "$SSHD_CLIENT_KEY" -q
  SSHD_CLIENT_HOME="$WORKDIR/clienthome"
  mkdir -p "$SSHD_CLIENT_HOME/.ssh"
  chmod 700 "$SSHD_CLIENT_HOME/.ssh"
  cp "$SSHD_KNOWN_HOSTS" "$SSHD_CLIENT_HOME/.ssh/known_hosts"
  : >"$SSHD_CLIENT_HOME/.ssh/config"
}

# Run a remote command over `ssh -A`, forwarding the agent at $1. The rest
# of the args are the remote command (passed to the server's `sh -c`). Runs
# under `env -i` with a pristine HOME so the operator's ssh config can't
# bleed in (PATH is preserved so `ssh` resolves). Intended for bats `run`.
ssh_agent_exec() {
  local auth_sock="$1"
  shift
  # Point ssh explicitly at the copied known_hosts rather than relying on
  # HOME-based `~/.ssh/known_hosts` resolution (which proved fragile in CI:
  # the client reported "No ECDSA host key is known" despite the file being
  # in place). GlobalKnownHostsFile is silenced so a runner's /etc/ssh can't
  # interfere. StrictHostKeyChecking=accept-new still verifies against the
  # seeded entry on the happy path but won't abort the run if the ephemeral
  # localhost fixture's key isn't pre-trusted — host-key trust of a throwaway
  # test sshd is not what this lane exercises; the forwarded rebox decrypt is.
  # Pin the per-user config to the empty test file with -F. Per ssh(1), a
  # command-line config file makes ssh ignore the system-wide
  # /etc/ssh/ssh_config too — so the operator's eng-ssh setup can't leak in.
  # Without this the operator's system config injected a `RemoteForward` of
  # the piggy-agent socket (~/.local/state/ssh/piggy-agent.sock) that failed
  # against the throwaway sshd and left the remote pivy-box with no forwarded
  # agent, so the decrypt fell back to a (missing) local token (piggy#180).
  # -A (agent forwarding) and the explicit -o options below are command-line,
  # so they survive the config isolation.
  env -i \
    HOME="$SSHD_CLIENT_HOME" \
    SSH_HOME="$SSHD_CLIENT_HOME/.ssh" \
    SSH_AUTH_SOCK="$auth_sock" \
    PATH="$PATH" \
    ssh -A -F "$SSHD_CLIENT_HOME/.ssh/config" -i "$SSHD_CLIENT_KEY" \
    -o IdentitiesOnly=yes \
    -o UserKnownHostsFile="$SSHD_CLIENT_HOME/.ssh/known_hosts" \
    -o GlobalKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=accept-new \
    -o BatchMode=yes \
    -p "$SSHD_PORT" testuser@127.0.0.1 \
    "$@"
}

stop_test_sshd() {
  [[ -n ${SSHD_PID:-} ]] && kill "$SSHD_PID" 2>/dev/null || true
  exec 9>&- 2>/dev/null || true
}
