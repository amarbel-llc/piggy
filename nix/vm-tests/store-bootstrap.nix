# Shared testScript prefix for the VM lane. Returns a Python string
# (the nixos-test-driver's testScript language), opening with igloo's
# vmTestPrelude (`wait_for_units`, `journal_count`), that leaves these
# names defined for the caller:
#
#   ENV          env prefix for every `piggy` invocation from the backdoor
#   show(name)   shell pipeline printing a store secret, newline-stripped
#   ecdh_count() number of successful slot-9D ECDH ops fibby has logged
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
  askpass,
  prelude,
  # Extra `VAR=value ` words prepended to every piggy invocation (the
  # coverage lanes pass LLVM_PROFILE_FILE).
  extraEnv ? "",
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
      "PCSCLITE_CSOCK_NAME=/run/fibby/pcscd.comm "
      "SSH_AUTH_SOCK=/run/piggy/agent.sock "
      "SSH_ASKPASS=${askpass} SSH_ASKPASS_REQUIRE=force DISPLAY= "
      "PIGGY_TEST_FIB_PIN=123456 "
  )


  def show(name):
      # `pass show` writes the plaintext to stdout and nothing else there;
      # agent/pivy chatter is stderr. Strip the trailing newline so the
      # bytes fed to cryptsetup/zfs are identical on every call.
      return ENV + f"piggy pass show {name} | head -n1 | tr -d '\\n'"


  def ecdh_count():
      return journal_count("fibby", "GA ECDH 9D -> 9000")


  wait_for_units(["multi-user.target", "fibby.service", "piggy-agent.service"])
  machine.wait_for_file("/run/fibby/pcscd.comm")
  machine.wait_for_file("/run/piggy/agent.sock")

  with subtest("agent serves exactly the seeded card keys"):
      keys = machine.wait_until_succeeds(
          "SSH_AUTH_SOCK=/run/piggy/agent.sock ssh-add -L", timeout=120
      )
      assert keys.count("ecdsa-sha2-nistp256 ") == ${toString nativeKeys}, keys

  with subtest("store init + generate + show decrypts through the agent"):
      machine.succeed(ENV + "piggy pass init")
      machine.succeed(ENV + "piggy pass generate -n ${secretName} 64")
      before = ecdh_count()
      secret = machine.succeed(show("${secretName}"))
      assert len(secret) == 64 and secret.isalnum(), repr(secret)
      assert ecdh_count() == before + 1, "decrypt did not perform exactly one slot-9D ECDH on fibby"
      agent_log = machine.succeed("journalctl -u piggy-agent --no-pager -o cat || true")
      assert "[piggy-test-askpass] supplying PIGGY_TEST_FIB_PIN" in agent_log, agent_log
      assert "REFUSING to prompt" not in agent_log, agent_log
''
