# Shared testScript prefix for the VM lane. Returns a Python string
# (the nixos-test-driver's testScript language), opening with igloo's
# vmTestPrelude (`wait_for_units`, `journal_count`), that leaves these
# names defined for the caller:
#
#   ENV          env prefix for every `piggy` invocation from the backdoor;
#                deliberately WITHOUT PCSCLITE_CSOCK_NAME, so a decrypt can
#                only go through the agent (the C pivy-box that
#                crypt::decrypt still execs falls back to a direct card
#                unlock whenever PC/SC is reachable, which would let a
#                broken agent path pass the "through the agent" asserts)
#   CARD_ENV     ENV plus PCSCLITE_CSOCK_NAME, for the one call that reads
#                the card directly (`pass init`)
#   show(name)   shell pipeline printing a store secret, newline-stripped
#   ecdh_count() number of successful slot-9D ECDH ops fibby has logged
#   expect_ecdh(n)  wait until fibby has logged exactly n of them (the
#                journal lags the daemon's stderr under TCG load)
#   secret       the generated secret's value
#
# and a store at /root/store holding `secretName` (64 alphanumeric
# chars), proven to decrypt through the agent. `nativeKeys` is how many
# keys the seeded card is expected to offer through `ssh-add -L`.
#
# The backdoor shell exports DISPLAY=:0.0 (nixos/modules/testing/
# test-instrumentation.nix), so DISPLAY is blanked explicitly: with
# SSH_ASKPASS_REQUIRE=force and the refusing askpass, a misrouted PIN
# prompt fails loudly instead of hanging on a GUI that does not exist.
{
  prelude,
  # `VAR=value ` words prepended to every piggy invocation: the test
  # askpass discipline and, in the coverage lanes, LLVM_PROFILE_FILE.
  extraEnv,
}:
{
  secretName,
  nativeKeys ? 1,
}:
prelude
+ ''
  ENV = (
      "${extraEnv}"
      "PIGGY_STORE_DIR=/root/store "
      "SSH_AUTH_SOCK=/run/piggy/agent.sock "
  )
  CARD_ENV = ENV + "PCSCLITE_CSOCK_NAME=/run/fibby/pcscd.comm "


  def show(name):
      # `pass show` writes the plaintext to stdout and nothing else there;
      # agent/pivy chatter is stderr. Strip the trailing newline so the
      # bytes fed to cryptsetup/zfs are identical on every call.
      return ENV + f"piggy pass show {name} | head -n1 | tr -d '\\n'"


  def expect_count(unit, needle, n):
      # journald ingests a daemon's stderr asynchronously (and mirrors it to
      # the serial console under the test driver), so a count taken right
      # after the command can be one short; wait for the exact value.
      machine.wait_until_succeeds(
          f"[ \"$(journalctl -u {unit} --no-pager -o cat | grep -c '{needle}' || true)\" -eq {n} ]",
          timeout=60,
      )


  def ecdh_count():
      return journal_count("fibby", "GA ECDH 9D -> 9000")


  def expect_ecdh(n):
      expect_count("fibby", "GA ECDH 9D -> 9000", n)


  def expect_present(unit, needle):
      # Like expect_count, but only waits for the line to appear (not an exact
      # count) — for the askpass-supply marker, which journald ingests
      # asynchronously just like the ECDH log. `grep -F` so a needle with
      # regex metacharacters (the bracketed tag) matches literally.
      machine.wait_until_succeeds(
          f"journalctl -u {unit} --no-pager -o cat | grep -qF '{needle}'",
          timeout=60,
      )


  wait_for_units(["multi-user.target", "fibby.service", "piggy-agent.service"])
  machine.wait_for_file("/run/fibby/pcscd.comm")
  machine.wait_for_file("/run/piggy/agent.sock")

  with subtest("agent serves exactly the seeded card keys"):
      keys = machine.wait_until_succeeds(
          "SSH_AUTH_SOCK=/run/piggy/agent.sock ssh-add -L", timeout=120
      )
      assert keys.count("ecdsa-sha2-nistp256 ") == ${toString nativeKeys}, keys

  with subtest("store init + generate + show decrypts through the agent"):
      # init reads the card's 9D pubkey directly (offline, PIN-free);
      # everything after it must reach the card through the agent only.
      machine.succeed(CARD_ENV + "piggy pass init")
      machine.succeed(ENV + "piggy pass generate -n ${secretName} 64")
      before = ecdh_count()
      secret = machine.succeed(show("${secretName}"))
      assert len(secret) == 64 and secret.isalnum(), repr(secret)
      expect_ecdh(before + 1)
      # The askpass-supply marker lands in journald asynchronously (like the
      # ECDH count above), so wait for it rather than reading the journal once
      # — a single read raced the ingest under the ZFS lane's TCG load.
      expect_present("piggy-agent", "[piggy-test-askpass] supplying PIGGY_TEST_FIB_PIN")
      agent_log = machine.succeed("journalctl -u piggy-agent --no-pager -o cat || true")
      assert "REFUSING to prompt" not in agent_log, agent_log
''
