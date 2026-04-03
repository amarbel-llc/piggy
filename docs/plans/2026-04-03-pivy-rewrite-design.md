# piggy: pivy-tool/ebox rewrite design

## Summary

Rewrite piggy (a passwordstore.org fork) to use pivy-tool and eboxes instead of
GPG. In-place rewrite of the existing shell script, swapping the crypto layer
while preserving the directory tree structure, git integration, clipboard
handling, and platform-specific secure tmpdir logic.

## Decisions

- **Command name:** `piggy`
- **Store directory:** `~/.local/share/piggy` (env var: `PIGGY_STORE_DIR`)
- **File extension:** `.ebox` for encrypted secrets
- **Recipients file:** `.pivy-id` --- an ebox template file (base64-encoded,
  git-tracked), not a list of key IDs
- **Crypto API:** `pivy-box stream encrypt/decrypt` with templates (not
  low-level `pivy-tool box/unbox`)
- **Multi-recipient:** Native via ebox templates --- a PRIMARY config with
  multiple parts means any single key can decrypt
- **Emacs integration:** Updated now (renamed to `piggy.el`)
- **Extensions:** Stripped
- **Cygwin support:** Stripped
- **Rewrite approach:** In-place modification of `password-store.sh`

## Future: pivy merge

piggy may eventually merge into the pivy repo. The design keeps piggy as a
standalone shell script with no build-time dependency on pivy internals --- it
only shells out to `pivy-box` and `pivy-tool`. This makes a future merge
straightforward.

## Core crypto mapping

  ---------------------------------------------------------------------------------------------------------------
  pass (GPG)                                            piggy (pivy-box)
  ----------------------------------------------------- ---------------------------------------------------------
  `$GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$passfile"`   `pivy-box stream encrypt "$pivy_id_path" > "$passfile"`

  `$GPG -d "$passfile"`                                 `pivy-box stream decrypt < "$passfile"`

  `pass init <gpg-id>`                                  `piggy init` --- interactive `pivy-box tpl create`, saves
                                                        to `.pivy-id`

  Re-encryption on `.gpg-id` change                     Re-encryption on `.pivy-id` change
  ---------------------------------------------------------------------------------------------------------------

## `piggy init`

Three modes:

- **`piggy init [-p subfolder]`** --- Interactive. Runs `pivy-box tpl create`,
  saves template to `.pivy-id`. If `.pivy-id` already exists, re-encrypts all
  secrets under that path.
- **`piggy init -k <pubkey> [-p subfolder]`** --- Non-interactive. Creates a
  single-recipient PRIMARY template from an SSH-format public key.
- **`piggy init -e [-p subfolder]`** --- Edit existing `.pivy-id` via
  `pivy-box tpl edit`, then re-encrypt.

## Environment variables

  pass                                piggy
  ----------------------------------- -------------------------------------
  `PASSWORD_STORE_DIR`                `PIGGY_STORE_DIR`
  `PASSWORD_STORE_GIT`                `PIGGY_GIT`
  `PASSWORD_STORE_CLIP_TIME`          `PIGGY_CLIP_TIME`
  `PASSWORD_STORE_GENERATED_LENGTH`   `PIGGY_GENERATED_LENGTH`
  `PASSWORD_STORE_KEY`                removed (template is in `.pivy-id`)
  `PASSWORD_STORE_GPG_OPTS`           removed

## Commands

**Unchanged behavior** (swap `.gpg` → `.ebox`, GPG → pivy-box): `ls`, `show`,
`insert`, `edit`, `generate`, `rm`, `mv`, `cp`, `find`, `grep`, `git`

**Changed significantly:** `init` (see above)

**Removed:** Extension dispatch

## Platform support

Keep darwin and linux platform files. Remove cygwin and freebsd/openbsd.

Secure tmpdir (ramdisk on macOS, `/dev/shm` on Linux) unchanged.

Git textconv changes from GPG decrypt to `pivy-box stream decrypt`.

## Emacs integration

- Rename `password-store.el` → `piggy.el`
- All `password-store-` prefixes → `piggy-`
- Default executable: `"piggy"`, default dir: `"~/.local/share/piggy"`
- File extension matching: `.gpg` → `.ebox`
- Remove `auth-source-pass` dependency
- Parse fields directly from `piggy show` output
- Keep clipboard management, `with-editor`, `completing-read`

## Testing

Keep sharness framework. Two test strategies:

1.  **Shell logic tests:** Mock `pivy-box` with a wrapper that does base64
    encode/decode. Tests tree operations, git integration, clipboard, find, grep
    without card infrastructure.
2.  **Crypto round-trip tests:** Require either a real card or are skipped
    in CI. `pivy-box stream encrypt` works without a card (public key only), but
    `pivy-box stream decrypt` needs an agent with private key access.

All existing test files updated for piggy naming and `.ebox` extension.

## Rollback strategy

Not needed in the traditional sense --- `piggy` and `pass` are separate commands
with separate stores. Both coexist. To roll back: stop using `piggy`.

A future `piggy import` command could migrate a `.password-store` by decrypting
with GPG and re-encrypting with pivy-box. Not in scope for this rewrite.
