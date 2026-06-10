# age-plugin-piggy — design + usage

## Why

Piggy's native ciphertext is the pivy-box `.ebox` format, decrypted by piggy /
pivy-box. That's great for the password store, but it locks secrets into
piggy's own tooling. Many ecosystems (sops-nix, age-native workflows, CI) speak
**age** instead.

`age-plugin-piggy` bridges the two: it makes piggy's PIV slot-9D key an **age
identity**. Secrets become plain age files — encryptable/decryptable by `age`,
`rage`, `sops`/sops-nix, anything that speaks the age plugin protocol — while
the private key never leaves the card and decryption still happens over a
(forwardable) piggy-agent. The `.ebox` format is not involved on the per-secret
path; only the card/agent is shared.

This was chosen over a sops-nix-shaped "unseal the age key" module (which would
materialize a key at rest) precisely because the key never has to exist: the
card does the ECDH on demand.

## Architecture

- **Crate:** `crates/age-plugin-piggy` (binary `age-plugin-piggy`), installed to
  the `piggy` package's `$out/bin` so anything with `piggy` on PATH also exposes
  the plugin.
- **Stanza:** the `piv-p256` scheme, wire-shaped after str4d's
  `age-plugin-yubikey` (`src/p256_stanza.rs`): P-256 ECDH → HKDF-SHA256 (salt =
  `epk_compressed || pk_compressed`, info `b"piv-p256"`) → ChaCha20-Poly1305.
  - **Encrypt** (`recipient-v1`): pure software — a fresh ephemeral key, local
    ECDH against the recipient's public key. No card, no agent.
  - **Decrypt** (`identity-v1`): delegates the ECDH to piggy-agent via
    `piggy::agent_client::AgentEcdhOracle` (the `ecdh@joyent.com` extension).
    The card performs `card_secret · epk`; the plugin never sees a private
    scalar. The agent owns the PIN/touch prompt.
- **Recipient / identity:** Bech32 over the 33-byte compressed P-256 public key
  (`src/bech32id.rs`, byte-identical to `age_plugin::print_new_identity`):
  - recipient `age1piggy1…` (HRP `age1piggy`)
  - identity `AGE-PLUGIN-PIGGY-1…` (HRP `age-plugin-piggy-`, uppercased)
  - The identity carries **only the public key** — no private material.

## CLI

```text
age-plugin-piggy generate [--guid <GUID>]   # read a card's slot-9D key (PIN-free)
age-plugin-piggy convert <markl-id|hex>     # same, offline, from a known recipient
age-plugin-piggy --version
# age invokes: age-plugin-piggy --age-plugin=recipient-v1|identity-v1
```

`generate` enumerates the card via `piggy-piv` and reads slot 9D's certificate
(read-only, no PIN), then prints:

```text
# recipient: age1piggy1…
AGE-PLUGIN-PIGGY-1…
```

Save that to a file: the `AGE-PLUGIN-PIGGY-…` line is the identity (for
`age -i` / `sops.age.keyFile`); the `# recipient:` comment travels with it.
`convert` does the same from an existing piggy recipient (a markl ID such as
`piggy-recipient-v1@pivy_ecdh_p256_pub-…`, or raw compressed-pubkey hex) without
touching a card.

## Plain age usage

```sh
# one-time: derive your strings (needs the card present for `generate`)
age-plugin-piggy generate > ~/.config/age/piggy-identity.txt
recipient=$(sed -n 's/^# recipient: //p' ~/.config/age/piggy-identity.txt)

# encrypt (no card needed)
echo secret | age -r "$recipient" -o secret.age

# decrypt (card via piggy-agent; PIN/touch as the agent dictates)
PIGGY_AUTH_SOCK=$XDG_RUNTIME_DIR/piggy-agent.sock \
  age -d -i ~/.config/age/piggy-identity.txt secret.age
```

`age-plugin-piggy` must be on `PATH` (it is, if `piggy` is). Decryption resolves
the agent socket from `PIGGY_AUTH_SOCK`, falling back to `SSH_AUTH_SOCK`.

## sops-nix recipe

sops-nix exposes `sops.age.plugins` (a list of packages added to the
`sops-install-secrets` PATH) and `sops.age.keyFile` (an age identity file). Wire
piggy in:

```nix
{
  # piggy's $out/bin carries age-plugin-piggy; this puts it on the sops
  # decrypt PATH so age can invoke the plugin by name.
  sops.age.plugins = [ pkgs.piggy ];

  # An identity file whose contents are the AGE-PLUGIN-PIGGY-… line
  # (produced by `age-plugin-piggy generate`/`convert`). Comments are ignored.
  sops.age.keyFile = "${config.home.homeDirectory}/.config/sops/age/piggy-identity.txt";

  # Your secrets are encrypted to the age1piggy… recipient in .sops.yaml
  # (creation_rules → key_groups → age), the same way age1… recipients are.
  sops.secrets.example = { };
}
```

At activation/boot, `sops-install-secrets` runs age, which invokes
`age-plugin-piggy`, which reaches piggy-agent over `ecdh@joyent.com` to perform
the card-side ECDH and decrypt each secret.

**Interactivity caveat (important).** PIV decryption is interactive (card +
agent + possibly a PIN/touch). For the sops decrypt step to succeed, the agent
must be reachable and unlocked **at the moment sops runs**:

- The sops decrypt environment must carry `PIGGY_AUTH_SOCK` (or `SSH_AUTH_SOCK`)
  pointing at a live piggy-agent, and `SSH_ASKPASS` if a PIN prompt may be
  needed without a tty. sops-nix's home-manager module decrypts in a
  `sops-nix.service` user unit — thread these via its service environment.
- There is **no unattended boot-time decryption** without an already-unlocked
  forwarded agent: the card cannot decrypt on its own. After a reboot, secrets
  become available once the agent is up and (if required) the PIN supplied — the
  same constraint every PIV-interactive flow has.

This recipe is documented from the module option shapes; it has **not** been
exercised end-to-end against a live sops-nix here. A first fib-backed attempt
to drive `sops decrypt` through the plugin **hung** rather than completing
(cause not yet diagnosed — possibly an askpass/agent-prompt wiring difference
when `sops` rather than `age` spawns the plugin, or a sops-side plugin gap);
the equivalent `age -d` round-trip succeeds. So treat the sops path as
**unverified — known to stall** until that is resolved, and verify against your
own sops / sops-nix versions (age-plugin support on the encryption side also
requires a sufficiently recent `sops`).

## Tests

- **Unit (no hardware, CI):** `cargo test -p age-plugin-piggy` — wrap/unwrap
  round-trip, the oracle-X-coordinate vector, Bech32 round-trips, the
  recipient-string→decrypt interop chain, and `generate`'s point compression.
  The decrypt path runs against a software mock `EcdhOracle`.
- **Hardware (fibby, Linux):**
  `just test-bats-conformance-age-plugin-piggy`
  (`zz-tests_bats/conformance/age_plugin_piggy_fibby.bats`, tagged
  `file_tags=hardware`, also wired into `just test` via
  `_test-conformance-linux-only`). Derives the recipient from fib's slot-9D key,
  encrypts with `age`, and decrypts through piggy-agent against fib — the
  real-crypto confirmation that the agent's ECDH output is the X-coordinate the
  KDF consumes (the assumption the unit tests can only pin in software).

## Deferred / limitations

- Whole-file only (age files are whole-file; no structured per-key extraction).
- `generate` reads slot 9D specifically; other slots are not exposed.
- A man page and a version `build.rs` (today `--version` reports the crate
  version, not piggy's `version+commit`) are not yet wired.
- The sops-nix recipe above is documented but **unverified**: a fib-backed
  `sops decrypt`-through-the-plugin attempt hung (see the sops-nix section).
  Diagnosing that stall and landing a green sops bats lane is open work.
