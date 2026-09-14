---
status: proposed
date: 2026-09-14
promotion-criteria: >
  One NixOS host (first candidate: circus's twerk reprovision) boots a
  LUKS2 root through systemd stage 1 with a FIDO2 keyslot per operator
  YubiKey plus a passphrase and a recovery key; each fallback (card absent
  -> passphrase after token-timeout, wrong FIDO2 PIN, recovery key) is
  exercised once on the real machine; one card rotation (enroll new card,
  wipe old card's slot by index) is performed without touching the other
  slots.
---

# Hardware-token LUKS2 unlock for operator YubiKeys

## Problem Statement

The operator wants an encrypted NixOS root (LUKS2, systemd stage 1) that
unlocks by plugging in one of their YubiKeys, with a passphrase kept as a
parallel keyslot. The cards are piggy cards: PIV slot 9D (ECDH) and 9A
(SSH auth) are provisioned by `piggy card init`, and 9D pubkeys are
published through `piggy-ids`/PAPI. The question is which unlock path to
use: the YubiKey's FIDO2 applet, its PIV applet over PKCS#11, or a
piggy-native path (`pivy-luks`, `age-plugin-piggy`). piggy owns the answer
because two of the three paths would run on piggy's slots and PIN.

## Recommendation

**Enroll each YubiKey's FIDO2 applet (`hmac-secret`) with
`systemd-cryptenroll --fido2-device`, one keyslot per card.** Alongside
those, keep a passphrase keyslot and a recovery-key keyslot. The recovery
key can be escrowed in the piggy store. This path is **piggy-unaware**:
piggy never touches the FIDO2 applet, and the enrollment runs in parallel
with piggy's own card conventions without conflicting with them.

Rejected alternatives, with evidence, are under *Alternatives assessed*.

## Interface

### What each YubiKey contributes

A YubiKey exposes FIDO2 and PIV as separate applets with separate PINs.
piggy uses only PIV (`piggy-piv-slots(7)`: 9D for ECDH, 9A for SSH
signing). The FIDO2 `hmac-secret` credential that systemd enrolls is a
different key on a different applet behind a different PIN, so:

- Unlock attempts at boot never touch the PIV PIN retry counter that
  piggy relies on. A PIV card locks after three wrong PINs (FDR 0002,
  piggy#245).
- `piggy card init` rotating or regenerating 9D/9A does **not** invalidate
  the LUKS keyslot, and re-enrolling LUKS does not disturb piggy.
- The LUKS keyslot is bound to the physical card's FIDO2 credential, not
  to anything published in `piggy-ids`/PAPI. PAPI identity does not help
  enroll a card that is not physically present (see Limitations).

### Keyslot layout (per LUKS2 device)

| Slot kind | Count | Enrolled with | Role |
|---|---|---|---|
| passphrase | 1 | `cryptsetup luksFormat` / `--password` | human fallback; required for re-enrollment when no card is present |
| recovery key | 1 | `systemd-cryptenroll --recovery-key` | high-entropy fallback, escrowed off-machine |
| FIDO2 | 1 per operator card | `systemd-cryptenroll --fido2-device=auto` | normal boot unlock |
| TPM2 **+ PIN** | 0 or 1 | `systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=yes` | optional "forgot the card" slot; never PCR-only (see *Combining with TPM2*) |

### Combining with TPM2

Circus measured a discrete TPM 2.0 on twerk (Nuvoton NTC0702, `/dev/tpmrm0`),
so a TPM2 slot is available. The rule that governs the combination: **LUKS
unlocks with any one keyslot, so the volume is only as strong as its weakest
slot.**

- **Do not add a PCR-only TPM2 slot** (`--tpm2-with-pin=no`, the default) if
  the point of the card is "possession required". A PCR-only slot unseals on
  any boot of the unmodified machine, so a stolen, powered-off laptop boots
  to its login screen with no card or passphrase. That makes the card slots
  a convenience, not a security property. Choose it only if unattended
  reboot matters more than theft resistance, and then say so explicitly.
- **TPM2 + PIN is worth it as the no-card path.** It binds the key to this
  machine's TPM *and* a PIN. Guessing the PIN runs into the TPM's global
  dictionary-attack lockout (systemd-cryptenroll(1) `--tpm2-with-pin`), which
  makes a short PIN far stronger offline than an equally short passphrase.
  A passphrase is brute-forceable against a copied header. crypttab
  `tpm2-pin=` exists since v251, within twerk's likely systemd.
- **Recommended role ordering:** card (FIDO2 PIN + touch) for daily boot →
  TPM2+PIN when the card is not at hand → long passphrase / recovery key as
  last resort (lost TPM state after firmware or Secure Boot changes, a
  different machine, header restore). PCR binding: circus's call. PCR 7
  is crypttab's default. Brittle PCRs strand the TPM slot after updates,
  which is acceptable only because the other slots remain.
- **Unverified: automatic ordering.** crypttab(5) as read does not say which
  enrolled token systemd-cryptsetup tries first when a volume carries both
  TPM2 and FIDO2 tokens, or whether one crypttab line can offer both. Verify
  on twerk before relying on "card first", for example by checking which
  prompt appears with both enrolled and the card unplugged. If it cannot
  offer both, prefer `fido2-device=auto` in crypttab. The TPM2+PIN slot is
  still usable manually from a live system via `systemd-cryptsetup attach`
  with `tpm2-device=auto`.

### NixOS side (systemd stage 1)

Verified against the nixpkgs `luksroot.nix` and `systemd/fido2.nix`
modules, NixOS 25.11:

- `boot.initrd.systemd.enable = true;` is required. The scripted-stage-1
  `boot.initrd.luks.fido2Support` (which uses `fido2luks`) fails an
  assertion under systemd stage 1 and is slated for removal in 26.11. The
  assertion text points users to `systemd-cryptenroll`.
- `boot.initrd.systemd.fido2.enable` defaults to
  `config.boot.initrd.systemd.package.withFido2`. When it is on, the
  initrd gains `libcryptsetup-token-systemd-fido2.so`, `libfido2`, the
  `fido_id` udev helper and its `60-fido-id.rules`.
- Per device, `boot.initrd.luks.devices.<name>.crypttabExtraOpts` carries
  the crypttab options, e.g. `[ "fido2-device=auto" "token-timeout=10s" ]`.
  With `fido2-device=auto` on a LUKS2 volume, the CID and salt come from
  the LUKS2 JSON token header (crypttab(5)).

### Boot-time behavior (crypttab(5))

- `fido2-device=auto` discovers the token as it is plugged in.
- `token-timeout=` (default 30s) bounds how long to wait for the token to
  appear. After it expires, **password authentication is attempted**,
  and any passphrase or recovery-key keyslot is accepted. The timeout does
  not cover the PIN prompt itself.
- With several FIDO2 tokens enrolled, systemd-cryptsetup sends pre-flight
  requests to find which enrolled token is plugged in. That identification
  is not possible for tokens enrolled with user verification (UV), which
  fall back to trying each token in turn with multiple prompts
  (systemd-cryptenroll(1) LIMITATIONS). Keep the default
  `--fido2-with-user-verification=no`.
- Enrollment defaults are client PIN **yes** and user presence (touch)
  **yes**, giving a two-factor unlock: the card plus its FIDO2 PIN plus a
  tap.

## Examples

Enrollment is run on the installed (or live-booted) system against the
LUKS2 partition. The partition path below is illustrative; circus owns
the real layout.

    # 0. Each card needs a FIDO2 PIN set first (distinct from its PIV PIN);
    #    systemd prompts for it at enroll and at unlock.

    # 1. Recovery key (prints it once; escrow it — see below)
    systemd-cryptenroll /dev/nvme0n1p2 --recovery-key

    # 2. One FIDO2 slot per card: plug in exactly ONE card per run
    systemd-cryptenroll /dev/nvme0n1p2 --fido2-device=auto
    #    (unlocks with the passphrase from stdin, then asks for the FIDO2 PIN + touch)

    # 3. Inspect: note which numeric keyslot each card got
    systemd-cryptenroll /dev/nvme0n1p2

NixOS config fragment (device name illustrative):

    boot.initrd.systemd.enable = true;
    boot.initrd.luks.devices.cryptroot = {
      device = "/dev/disk/by-uuid/…";
      crypttabExtraOpts = [ "fido2-device=auto" "token-timeout=10s" ];
    };

Escrowing the recovery key in the piggy store, encrypted to the store's
nearest `piggy-ids` like the #258 management-key seal:

    piggy pass insert -m luks/twerk/recovery-key

Card rotation (new card in, old card out). Unlock with the passphrase or
another enrolled card, then wipe **by numeric slot index**:

    systemd-cryptenroll /dev/nvme0n1p2 --fido2-device=auto              # new card
    systemd-cryptenroll /dev/nvme0n1p2 --wipe-slot=<old-card-slot-index>

Do **not** use `--wipe-slot=fido2` for a single-card rotation. It wipes
*every* FIDO2 slot (all cards) except one just enrolled in the same call.

## Alternatives assessed

### PIV over PKCS#11 (`--pkcs11-token-uri`) on slot 9D — viable, not recommended

- **Cryptographically compatible.** systemd-cryptenroll(1) supports EC key
  pairs via ECDH. It generates an ephemeral key in the token's EC group,
  derives the shared secret with the token's public key as the volume
  secret, and stores the ephemeral pubkey in the LUKS2 token header.
  Slot 9D is a P-256 ECDH key, the same operation `pivy-box` uses. 9A, 9C
  and 9E are signature-only and unusable (`piggy-piv-slots(7)`).
- **No NixOS support in the initrd.** nixpkgs' systemd stage 1 wires only
  the tpm2 token plugin (luksroot.nix) and the fido2 plugin (fido2.nix).
  No module adds `libcryptsetup-token-systemd-pkcs11.so`, a PKCS#11
  provider (opensc-pkcs11 / ykcs11 / p11-kit), or pcscd plus the CCID
  driver to the initrd. `services.hardware.pcscd` has no initrd hook. All
  of that would be hand-built and then maintained in circus.
- **It shares piggy's PIV PIN.** Wrong PINs typed at the boot prompt spend
  the same three-try retry counter that locks the card for `piggy pass`,
  `piggy agent` and SSH. A boot-time lockout bricks the operator's daily
  identity until PUK recovery.
- **Enrollment constraint.** The man page says unlocking with a PKCS#11
  key cannot be used to enroll a new PKCS#11 key, so a passphrase or other
  non-PKCS#11 slot is mandatory for rotation.
- **No conflict with piggy-agent at boot**, since the agent does not run
  in the initrd. At runtime pcscd shares readers, but that is moot for
  unlock.
- **The one real advantage (theory, not verified):** the ECDH enrollment
  needs only the token's *public* key. In principle a spare card's
  published 9D pubkey (piggy-ids/PAPI) could be enrolled without the card
  present. `systemd-cryptenroll` itself resolves the key through the token
  URI on a *present* token, so this would require a custom tool writing
  systemd's `systemd-pkcs11` token JSON. That is not proposed here and
  would need verification.

### piggy-native: `pivy-luks` (`piggy luks`) — reject

- piggy vendors `vendor/pivy/src/pivy-luks.c` and exposes `piggy luks` as
  an exec-to-C passthrough. **However, `nix/pivy.nix` does not build it**:
  it installs only `pivy-tool`, `pivy-agent`, `pivy-box` and
  `pivy-wire-test`, and the pivy Makefile gates `pivy-luks` behind
  `USE_LUKS` plus libcryptsetup/json-c. In the nix build, `piggy luks` has
  no binary to exec.
- Its design conflicts with the requirement. `pivy-luks format` calls
  `crypt_format` with the ebox holding the raw volume key and **no
  keyslot** ("there is no passphrase that will unlock the volume key",
  vendor/pivy/README.adoc). Unlock uses `crypt_activate_by_volume_key` from
  an `ebox`-typed LUKS2 token.
- systemd-cryptsetup does not understand an `ebox` token (only its own
  tpm2/pkcs11/fido2 plugins exist), so boot would need a bespoke initrd
  unit with pcscd, the C binary and an interactive PIN/recovery TTY flow.
  It would have the same PIV-PIN-sharing hazard as PKCS#11.
- exec.rs documents the C luks path as having no planned Rust port.

### piggy-native: `age-plugin-piggy` / `piggy pass` key file — reject

- age-plugin-piggy decrypt delegates the ECDH to a running piggy-agent
  (`ecdh@joyent.com`). No agent exists in the initrd, so it would have to
  be booted there along with pcscd, a PIN prompt and a key file handoff.
  That is strictly more moving parts than PKCS#11 for the same slot-9D
  operation, with the same PIN hazard.
- The piggy store's legitimate role here is **escrow** of the recovery key
  and passphrase (see Examples), not boot-time unlock.

## Limitations

- **Each card must be physically present to enroll.** A FIDO2
  `hmac-secret` credential is created on the card, so spare cards in a
  safe cannot be enrolled from their PAPI/piggy-ids data. Plan a
  provisioning session with every card, or accept re-enrolling later via
  the passphrase.
- **FIDO2 PIN lockout is separate from piggy's.** Exhausting the FIDO2 PIN
  retries blocks the card's FIDO2 applet (and its LUKS slot), not PIV.
  The exact YubiKey FIDO2 retry count and reset semantics were **not
  verified** here; check Yubico docs before relying on a number. Recovery
  is to boot with another card, the passphrase or the recovery key.
- **Card absent at boot:** after `token-timeout`, systemd falls back to
  password entry, where the passphrase or recovery key is accepted.
- **Version skew:** crypttab/cryptenroll text was read from the man7.org
  render of systemd 262~devel. The dev host runs systemd 258.3.
  Enrollments made with a newer cryptenroll are not guaranteed to unlock
  with an older systemd-cryptsetup (COMPATIBILITY section), so enroll with
  the target system's own systemd, from the installed system or a live
  environment with a matching or older version. Options cited above that
  matter here all date from v248–v257. The v262-only ones (`--firstboot`,
  `--unlock-headless`) are not used.
- **TPM2 interaction:** covered in *Combining with TPM2*. `token-timeout`
  covers TPM2 as well as FIDO2/PKCS#11. The multi-token try order is
  unverified.
- The nixpkgs module source cited was a local nixos-25.11-era store copy.
  It was not confirmed to be byte-identical to twerk's eventual pin.
- piggy adds no code or commands for this feature. The FDR records a
  deliberate decision that the operator's cards unlock disks through
  FIDO2, outside piggy.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| `token-timeout` | 10s (default 30s) | a laptop user plugs the card in before boot or not at all | card routinely missed on cold boot (USB enumeration slower) |
| FIDO2 client PIN | yes | card theft alone must not unlock | operator decides touch-only is acceptable for this host |
| FIDO2 user presence | yes | proves a human at the machine | unattended reboot needed (then TPM2, not a card) |
| FIDO2 user verification | no | UV defeats multi-token pre-flight identification | operator's cards are biometric-only |

## More Information

- `piggy-piv-slots(7)`: PIV slot roles; 9D is the only ECDH slot.
- FDR 0002: the PIV three-try PIN lockout hazard (piggy#245).
- systemd-cryptenroll(1), crypttab(5): FIDO2/PKCS#11 enrollment and boot
  semantics.
- `vendor/pivy/src/pivy-luks.c`, `vendor/pivy/README.adoc` "LUKS/cryptsetup",
  and `nix/pivy.nix` (pivy-luks not built).
- Consumer: circus's twerk NixOS reprovision design
  (circus/keen-aspen/clarabell).
