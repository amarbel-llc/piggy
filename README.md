# piggy

**PIV-based encryption for daily use.**

piggy is a combo of pass, pivy, and age:

- **pass** ergonomics — the passwordstore.org command surface (`init`, `show`, `insert`, `edit`, `generate`, `rm`, `mv`, `cp`, `find`, `grep`, `git`), with the same filesystem layout and same git integration.
- **pivy** key material — passwords are encrypted to a YubiKey PIV slot (default `9D`, Key Management / ECDH) via `pivy-box`, so unlocking requires a physical touch rather than a passphrase. Decryption works transparently over SSH agent forwarding.
- **age** spirit — the `ebox` template format plays the role age's recipient syntax does: a small, explicit list of public keys that can unseal the payload, built on modern ECDH rather than legacy RSA/PGP. Encrypted files live alongside the plaintext command flow, not behind a separate keystore.

## Install

piggy ships as a Nix flake. With flakes enabled:

```sh
nix run github:amarbel-llc/piggy -- --help
nix profile install github:amarbel-llc/piggy
```

For development:

```sh
git clone https://github.com/amarbel-llc/piggy
cd piggy
nix develop
just build
```

Dependencies (pinned by the devshell): `bash`, `pivy` (vendored at `vendor/pivy/`), `git`, a clipboard helper (`xclip` / `wl-clipboard` / `pbcopy`), `tree`, GNU `getopt`, `qrencode`.

> **Note on the vendored pivy.** The standalone [`amarbel-llc/pivy`](https://github.com/amarbel-llc/pivy) fork (forked from [`arekinath/pivy`](https://github.com/arekinath/pivy)) is **archived**. All ongoing pivy work — bug fixes, new features, vendored patches — happens in this repository under `vendor/pivy/`. Do not open issues or send PRs against the archived fork; file them here against `vendor/pivy/...` instead. The vendored tree is the canonical source.

## Usage

The user-facing CLI is `piggy <subcommand>`. `piggy --help` prints the full subcommand list. There are three groups:

- **Pass-style** (`init`, `show`, `insert`, `edit`, `generate`, `rm`, `mv`, `cp`, `find`, `grep`, `git`) — same surface as passwordstore.org.
- **First-party Rust** (`agent`, `box`) — PIV-backed SSH agent and pivy-box reimplementation.
- **C `pivy-*` shortcuts** (`tool`, `ca`, `luks`, `zfs`) and the generic `piggy pivy <tool>` escape hatch — forwarded to the corresponding `pivy-*` C binary.

See the manpages in `doc/` for the full command reference and the `PIGGY_*` environment-variable knobs.

`src/piggy.sh` is the bash implementation behind the pass-style handlers. It is an internal detail of the installed binary (lives under `$out/libexec/piggy/`, not on `$PATH`) and is not a separately callable program.

A more complete walkthrough is tracked at [#25](https://github.com/amarbel-llc/piggy/issues/25).

## History

piggy started as a fork of [passwordstore.org](https://www.passwordstore.org/) and replaced the GPG encryption path with `pivy-box`. See `COPYING` for the original GPL-2.0+ license retained from pass.
