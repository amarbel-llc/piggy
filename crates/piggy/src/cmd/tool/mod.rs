//! `piggy tool` — the Rust re-implementation of `pivy-tool` (piggy#289
//! Phase 3). Milestone 3.1a covers the read-only, no-PIN slot readers:
//!
//! - `piggy tool pubkey <slot>` — the slot's public key in OpenSSH format
//!   (matches C `pivy-tool`'s `sshkey_write`).
//! - `piggy tool cert <slot>` — the slot's X.509 certificate as PEM
//!   (matches C `PEM_write_X509`).
//! - `piggy tool attest <slot>` — the slot's YubiKey attestation cert
//!   followed by the device attestation cert, both PEM (matches C's two
//!   `PEM_write_X509` calls). On a card whose slot key was imported (so
//!   attestation is unavailable — every fibby key, and a real YubiKey's
//!   imported keys) this fails exactly as C does; the two-PEM happy path
//!   is exercised only by the hardware lane.
//! - `piggy tool sign <slot>` — hash stdin (SHA-256 for P-256, SHA-384
//!   for P-384) and ECDSA-sign the digest, writing the card's raw
//!   signature bytes (DER) to stdout (matches C `piv_sign` + `fwrite`).
//! - `piggy tool ecdh <slot>` — read an OpenSSH public key from stdin and
//!   write the raw ECDH shared secret to stdout (matches C `piv_ecdh` +
//!   `fwrite`). Both are PIN-gated; the PIN comes from `-P` or the same
//!   `SSH_ASKPASS` prompt C uses.
//! - `piggy tool change-pin` / `change-puk` — rotate the PIV PIN / PUK
//!   (CHANGE REFERENCE DATA, matches C `piv_change_pin`). The current and
//!   new values come from two repeated `-P` options, as C consumes them;
//!   piggy prompts via `SSH_ASKPASS` when either is absent.
//! - `piggy tool reset-pin` — unblock a PIN whose retry counter hit zero,
//!   installing a new PIN under PUK authority (RESET RETRY COUNTER, INS
//!   0x2C, matches C `piv_reset_pin`). The two repeated `-P` options are
//!   the PUK then the new PIN, as C consumes them; piggy prompts via
//!   `SSH_ASKPASS` when either is absent.
//! - `piggy tool set-admin <newkey>` — rotate the PIV management (admin)
//!   key (mgmt-key mutual auth with the current key, then SET MANAGEMENT
//!   KEY; matches C `cmd_set_admin`). The current key comes from `-K`
//!   (`default` or hex; default: the factory 3DES key), the new key from
//!   the positional (`default` or hex). 3DES-only: AES admin keys,
//!   `random`, `@file`, and `-R` PINFO-save fall through to C.
//! - `piggy tool delete-cert <slot>` — clear a slot's certificate object
//!   (mgmt-key mutual auth, then PUT DATA at the slot's cert tag with an
//!   empty body; matches C `cmd_delete_cert`). The current key comes from
//!   `-K` (`default` or hex). Takes the key slots 9A/9C/9D/9E and the
//!   retired slots 82..95 (as do `write-cert`, `generate`, `import` and
//!   `req-cert`); F9 and other ids are a usage error.
//! - `piggy tool update-keyhist` — rescan the retired key slots and rewrite
//!   the PIV Key History object (mgmt-key mutual auth, then PUT DATA at
//!   `5FC10C`; matches C `cmd_update_keyhist`). `oncard` is recomputed from
//!   the retired slots, `offcard`/URL preserved from the existing object.
//!   The current key comes from `-K` (`default` or hex).
//! - `piggy tool write-cert <slot>` — read an X.509 cert (DER or PEM) from
//!   stdin and write it to the slot's cert object (mgmt-key mutual auth,
//!   then PUT DATA; matches C `cmd_write_cert`). The current key comes from
//!   `-K` (`default` or hex). Slots 9A/9C/9D/9E and 82..95.
//! - `piggy tool generate <slot> -a <alg> [-i <pin-policy>] [-t <touch-policy>]`
//!   — generate a new key pair (GENERATE ASYMMETRIC under mgmt auth),
//!   self-sign a minimal cert for it (PIN-gated), and print the new public
//!   key (matches C `cmd_generate`). `-i`/`-t` set the YubicoPIV PIN and touch
//!   policy; without them no policy tag is sent.
//!   Modeled for the EC algorithms `eccp256`/`eccp384` on slots 9A/9C/9D/9E
//!   and 82..95; RSA/Ed25519 is a usage error. Needs `-K` (mgmt) and a
//!   PIN (`-P` or askpass, for the self-sign).
//! - `piggy tool import <slot>` — read an OpenSSH private key from stdin,
//!   import it (YubicoPIV IMPORT ASYMMETRIC), self-sign a minimal cert
//!   (PIN-gated), and write it (matches C `cmd_import`). EC P-256/P-384 only
//!   (piggy is EC-only); an RSA/Ed25519 key errors, pointing to `piggy pivy
//!   tool import`. Needs `-K` (mgmt) and a PIN. Slots 9A/9C/9D/9E and 82..95.
//! - `piggy tool pinfo` — read and print the PIV Printed Information object
//!   (`name`/`affiliation`/`expiry`/`serial`/`issuer`, optional
//!   `organization`, `yubico`; matches C `cmd_pinfo`). The card models the
//!   object PIN-free; a real card's PIN-gated read is a tracked follow-up.
//! - `piggy tool [-j|-p] list` — the card listing in C `cmd_list`'s human,
//!   `-p` parseable or `-j` JSON form, byte-for-byte for what piggy reads
//!   (piggy#345). The mode flag must precede `list` (options-first, like
//!   piggy's other `tool` ops).
//! - `piggy tool version` — piggy's bare version on one line, the shape of C
//!   `pivy-tool version` (which prints pivy's own version; piggy#348).
//! - `piggy tool factory-reset` — wipe the PIV applet via YubicoPIV RESET
//!   (INS 0xFB; the card requires the PIN and PUK both blocked first, else
//!   SW 6985). Gated by a confirmation: a typed `YES` on the controlling tty,
//!   or `--yes`/`--force` to skip it non-interactively (a piggy-native gate —
//!   pivy-tool's tty-only prompt isn't scriptable — outside the differential).
//! - `piggy tool req-cert <slot>` — build a minimal PKCS#10 CSR for the slot's
//!   EC key, signed by that key on the card (PIN-gated). EC-only; a non-EC slot
//!   errors → `piggy pivy tool req-cert`. The CSR is minimal (no template
//!   extensions), a valid/equivalent CSR rather than a byte clone of C's
//!   cert-template output — mirroring `cert_builder`'s self-signed minimalism.
//!   Subject CN from `-n`, else `<slot-name>@<short-guid>`.
//!
//! As of the 3.6 cutover (piggy#289, mirroring the `box` cutover in #165)
//! `piggy tool` is Rust — NOT a superset that falls back to C. [`run`]
//! returns the exit code directly; an unported op (`init`) or an unmodeled
//! option
//! (whatever [`parse`] rejects — e.g. an RSA/Ed25519 `-a`, a pivy debug
//! flag) is a usage error (exit 2), not a silent hop to `pivy-tool`. The
//! full C `pivy-tool` surface stays reachable via `piggy pivy tool` while
//! C is shipped.

use std::io::{Read, Write};

use piggy_piv::{PinPolicy, PivAlgorithm, PivContext, PivToken, TouchPolicy};

/// One parsed `piggy tool` invocation: the general options piggy models,
/// the operation, and its positional arguments.
struct Invocation {
    /// `-g <hex>`: GUID (or prefix) selecting a token among several.
    guid: Option<String>,
    /// Repeated `-P <code>` values, in order. pivy-tool consumes the first
    /// as the current PIN/PUK and the second as the new one (change-pin,
    /// change-puk); the single-secret ops (sign, ecdh) use only the first.
    pins: Vec<String>,
    /// `-K <key>`: the CURRENT management (admin) key used to authenticate a
    /// write op, as `default` or a hex string. pivy-tool's general admin-key
    /// option; `set-admin` reads it as the old key to auth with.
    admin_key: Option<String>,
    /// `-a <alg>`: pivy-tool's algorithm option (e.g. `eccp256`). Required by
    /// `generate`; this port models the EC algorithms only.
    alg: Option<String>,
    /// `--yes`/`--force`: piggy-native skip of the `factory-reset` confirmation
    /// prompt (pivy-tool has no scriptable equivalent). Only `factory-reset`
    /// reads it.
    force: bool,
    /// `-n <cn>`: the CSR subject common name for `req-cert`. Only `req-cert`
    /// reads it; when absent it defaults to `<slot-name>@<short-guid>`.
    cn: Option<String>,
    /// `-i <policy>`: pivy-tool's PIN policy for a key `generate` creates.
    /// Absent means the card's default for the slot (no policy tag sent).
    pin_policy: PinPolicy,
    /// `-t <policy>`: pivy-tool's touch policy for a key `generate` creates.
    touch_policy: TouchPolicy,
    /// `list`'s output mode: human (default), `-p` parseable, or `-j` JSON.
    list_mode: ListMode,
    /// `attest-verify` only (piggy#397): `--root FILE`, the PEM the card's
    /// F9 certificate must chain to; `--saved FILE`, an earlier attestation
    /// to compare with; `--expect-pin` / `--expect-touch`, the policy the
    /// attestation must state.
    root: Option<String>,
    saved: Option<String>,
    expect_pin: Option<PinPolicy>,
    expect_touch: Option<TouchPolicy>,
    op: String,
    positionals: Vec<String>,
}

/// `piggy tool list` output modes, as C `cmd_list` picks them: `-j` wins over
/// `-p`, and neither is the human table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ListMode {
    Human,
    Parseable,
    Json,
}

use crate::card::seal::{ManagementKeySealer, default_pass_name};
use zeroize::Zeroizing;

/// Parse `piggy tool <args>` into an [`Invocation`], or `None` if the op is
/// unrecognized OR an unmodeled option is present. Since the 3.6 cutover
/// [`run`] maps `None` to a usage error (exit 2) — no C fallback — so `None`
/// means "not part of the Rust port; direct the user to `piggy pivy tool`".
fn parse(args: &[String]) -> Option<Invocation> {
    let mut guid = None;
    let mut pins = Vec::new();
    let mut admin_key = None;
    let mut alg = None;
    let mut json = false;
    let mut parseable = false;
    let mut force = false;
    let mut cn = None;
    let mut pin_policy = PinPolicy::Default;
    let mut touch_policy = TouchPolicy::Default;
    let mut policy_given = false;
    let mut root = None;
    let mut saved = None;
    let mut expect_pin = None;
    let mut expect_touch = None;
    let mut i = 0;
    // Leading options (pivy-tool style: options precede the operation).
    while i < args.len() {
        let a = &args[i];
        if !a.starts_with('-') {
            break;
        }
        match a.as_str() {
            "-g" => {
                guid = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            "-P" => {
                pins.push(args.get(i + 1)?.clone());
                i += 2;
            }
            "-K" => {
                admin_key = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            "-a" => {
                alg = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            // pivy-tool's global JSON flag. Only `list` consumes it; other ops
            // ignore it (as C does), so accepting it here is never an error.
            "-j" | "--json" => {
                json = true;
                i += 1;
            }
            // pivy-tool's global parseable flag; like `-j`, only `list` reads it.
            "-p" => {
                parseable = true;
                i += 1;
            }
            // piggy-native: skip the `factory-reset` confirmation. Only
            // `factory-reset` consumes it; accepting it here is never an error.
            "--yes" | "--force" => {
                force = true;
                i += 1;
            }
            // pivy-tool's subject option; only `req-cert` consumes it (sets the
            // CSR subject CN). Ignored by other ops.
            "-n" => {
                cn = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            // pivy-tool's key policy options; only `generate` consumes them.
            // An unknown policy name is a usage error, like any unmodeled
            // option.
            "-i" => {
                pin_policy = args.get(i + 1)?.parse().ok()?;
                policy_given = true;
                i += 2;
            }
            "-t" => {
                touch_policy = args.get(i + 1)?.parse().ok()?;
                policy_given = true;
                i += 2;
            }
            // piggy-native (piggy#397): `attest-verify`'s inputs.
            "--root" => {
                root = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            "--saved" => {
                saved = Some(args.get(i + 1)?.clone());
                i += 2;
            }
            "--expect-pin" => {
                expect_pin = Some(args.get(i + 1)?.parse().ok()?);
                i += 2;
            }
            "--expect-touch" => {
                expect_touch = Some(args.get(i + 1)?.parse().ok()?);
                i += 2;
            }
            // Any other flag is not modeled here — `None` becomes a usage
            // error in `run` (the 3.6 cutover; no C fallback).
            _ => return None,
        }
    }
    let op = args.get(i)?.clone();
    // Only claim the ops this milestone implements; everything else falls
    // through to C.
    if !matches!(
        op.as_str(),
        "pubkey"
            | "cert"
            | "attest"
            | "sign"
            | "ecdh"
            | "change-pin"
            | "change-puk"
            | "reset-pin"
            | "set-admin"
            | "delete-cert"
            | "update-keyhist"
            | "write-cert"
            | "generate"
            | "import"
            | "pinfo"
            | "list"
            | "factory-reset"
            | "req-cert"
            | "version"
            | "auth-test"
            | "attest-verify"
    ) {
        return None;
    }
    // `attest-verify`'s options belong to it alone: given to another op they
    // would be silently ignored, which is a usage error here.
    let verify_option_given =
        root.is_some() || saved.is_some() || expect_pin.is_some() || expect_touch.is_some();
    if verify_option_given && op != "attest-verify" {
        return None;
    }
    let list_mode = if json {
        ListMode::Json
    } else if parseable {
        ListMode::Parseable
    } else {
        ListMode::Human
    };
    // Only `generate` applies a key policy. Accepting `-i`/`-t` elsewhere
    // (e.g. on `import`) would leave the operator believing a policy was set
    // on a key that got the card default.
    if policy_given && op != "generate" {
        return None;
    }
    let positionals = args[i + 1..].to_vec();
    // The admin-key–gated ops authenticate with `-K`; validate the modeled
    // key forms (`default`, hex, `@store[:<pass-name>]`, piggy#396) so
    // `random`/`@file` stay usage errors.
    if matches!(
        op.as_str(),
        "set-admin"
            | "delete-cert"
            | "update-keyhist"
            | "write-cert"
            | "generate"
            | "import"
            | "auth-test"
    ) {
        if let Some(k) = &admin_key {
            if !is_admin_key_arg(k) {
                return None;
            }
        }
    }
    // `generate` requires `-a <alg>` and this port models only the EC
    // algorithms (eccp256/eccp384); a missing or RSA/Ed25519 `-a` is a usage
    // error, as is a slot outside 9A/9C/9D/9E and 82..95.
    if op == "generate" {
        let slot = positionals.first()?;
        if positionals.len() != 1
            || !is_supported_cert_slot(slot)
            || alg.as_deref().and_then(parse_ec_alg).is_none()
        {
            return None;
        }
    }
    // `update-keyhist`, `pinfo`, `list`, `factory-reset` and `auth-test` take
    // no positionals (C errors "too many arguments").
    if matches!(
        op.as_str(),
        "update-keyhist" | "pinfo" | "list" | "factory-reset" | "version" | "auth-test"
    ) && !positionals.is_empty()
    {
        return None;
    }
    // `set-admin` is 3DES-only in this port: the new key positional must be
    // `default`, a hex string, or `-` (one hex line on stdin, piggy#396); not
    // `random`, `@file`, `@store`, an AES `-N`, or `-R`.
    if op == "set-admin" {
        let new_key = positionals.first()?;
        if positionals.len() != 1 || !(new_key == "-" || is_key_literal(new_key)) {
            return None;
        }
    }
    // `delete-cert`, `write-cert`, `import`, and `req-cert` claim the key slots
    // (9A/9C/9D/9E and retired 82..95); F9 and anything else is a usage
    // error. (import's key TYPE is unknown until stdin is read, so a
    // non-EC key is handled in cmd_import, not here; req-cert's non-EC rejection
    // is likewise in cmd_req_cert once the slot key is read.)
    if matches!(
        op.as_str(),
        "delete-cert" | "write-cert" | "import" | "req-cert" | "attest-verify"
    ) {
        let slot = positionals.first()?;
        if positionals.len() != 1 || !is_supported_cert_slot(slot) {
            return None;
        }
    }
    Some(Invocation {
        guid,
        pins,
        admin_key,
        alg,
        force,
        cn,
        pin_policy,
        touch_policy,
        list_mode,
        root,
        saved,
        expect_pin,
        expect_touch,
        op,
        positionals,
    })
}

/// Map a pivy-tool `-a` algorithm name to the EC algorithms this port
/// models: `eccp256` → P-256, `eccp384` → P-384. Everything else (RSA,
/// Ed25519, X25519) returns `None` and falls through to C.
fn parse_ec_alg(s: &str) -> Option<(PivAlgorithm, u8)> {
    match s {
        "eccp256" => Some((PivAlgorithm::EcP256, piggy_piv::apdu::alg::ECCP256)),
        "eccp384" => Some((PivAlgorithm::EcP384, piggy_piv::apdu::alg::ECCP384)),
        _ => None,
    }
}

/// A management key written out: the literal `default` (the factory 3DES
/// key) or a plain hex string.
fn is_key_literal(s: &str) -> bool {
    s == "default"
        || (!s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit()))
}

/// `-K @store` or `-K @store:<pass-name>` (piggy#396): the current key is
/// read from the password store instead of argv. `Some(None)` is the bare
/// form (the entry `card init` seals, `piv/<GUID>/management-key` of the
/// selected card); `Some(Some(name))` names the entry.
fn store_ref(s: &str) -> Option<Option<&str>> {
    if s == "@store" {
        return Some(None);
    }
    s.strip_prefix("@store:")
        .filter(|n| !n.is_empty())
        .map(Some)
}

/// Whether a `-K` argument is one this port models: a key literal or a
/// store reference. `random`, an `@file` reference, and anything else are
/// usage errors (C `pivy-tool` forms this port does not carry).
fn is_admin_key_arg(s: &str) -> bool {
    is_key_literal(s) || store_ref(s).is_some()
}

/// The current management key an admin op authenticates with (piggy#396):
/// `-K default` or hex as before, or `-K @store[:<pass-name>]`, read from the
/// password store, the entry `card init` sealed (`piv/<GUID>/management-key`
/// of the selected card) unless named. The store read is a decrypt, through
/// the agent or a card over PC/SC, so it happens BEFORE the card session
/// opens (as `card add-key --management-key-from-store` does); the key is
/// never in argv. `Err` carries the exit code and the message.
fn current_admin_key(
    inv: &Invocation,
    sealer: &dyn ManagementKeySealer,
    guid_hex: &str,
) -> Result<Zeroizing<Vec<u8>>, (i32, String)> {
    let arg = inv.admin_key.as_deref().unwrap_or("default");
    match store_ref(arg) {
        None => resolve_admin_key(arg)
            .map(Zeroizing::new)
            .map_err(|e| (2, format!("current admin key: {e}"))),
        Some(name) => {
            let pass_name = name
                .map(str::to_string)
                .unwrap_or_else(|| default_pass_name(guid_hex));
            // A card with no sealed entry (a holder-minted virtual card, a card
            // never sealed) is a plain failure here, never a fall back to the
            // factory key: `@store` means the store or nothing.
            let hex = sealer.recover(&pass_name).map_err(|e| {
                let what = match name {
                    Some(_) => format!("current admin key from {pass_name}"),
                    None => format!("no sealed management key for this card ({pass_name})"),
                };
                (1, format!("{what}: {e}"))
            })?;
            // The entry's content is never quoted back: a wrong entry is some
            // other secret.
            let key = hex.trim();
            if key.len() != 48 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err((
                    1,
                    format!(
                        "current admin key from {pass_name}: the entry does not hold a 48-hex-digit key ({} characters)",
                        key.len()
                    ),
                ));
            }
            resolve_admin_key(key).map(Zeroizing::new).map_err(|_| {
                (
                    1,
                    format!("current admin key from {pass_name}: not a 3DES key"),
                )
            })
        }
    }
}

/// `set-admin -`: the NEW key as one hex line on stdin (piggy#396), so it
/// is never in argv. Trailing whitespace is dropped; nothing of the line is
/// echoed in an error.
fn read_new_admin_key(input: &mut dyn std::io::BufRead) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(String::new());
    let n = input
        .read_line(&mut line)
        .map_err(|e| format!("stdin: {e}"))?;
    if n == 0 {
        return Err("stdin held no key line (expected 48 hex digits on one line)".into());
    }
    let key = line.trim();
    if key.len() != 48 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "the new key must be 48 hex digits on one line ({} characters read)",
            key.len()
        ));
    }
    resolve_admin_key(key).map(Zeroizing::new)
}

/// Whether a slot argument names a key slot the write ops (`generate`,
/// `write-cert`, `req-cert`, `import`, `delete-cert`) may target: the named
/// key slots 9A/9C/9D/9E and the retired key-management slots 82..95. The
/// attestation slot F9 and anything else is refused.
fn is_supported_cert_slot(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    u8::from_str_radix(hex, 16).is_ok_and(is_key_slot)
}

/// The key slots: 9A/9C/9D/9E and the retired key-management slots 82..95.
fn is_key_slot(slot_id: u8) -> bool {
    matches!(slot_id, 0x9A | 0x9C | 0x9D | 0x9E | 0x82..=0x95)
}

/// Dispatch `piggy tool <args>`, returning the process exit code. As of the
/// 3.6 cutover (piggy#289, mirroring the `box` cutover in #165) this is NOT a
/// superset that falls back to C: an unported op or an unmodeled option
/// (whatever [`parse`] rejects) is a usage error (exit 2), not a silent hop to
/// `pivy-tool`. The full C surface stays reachable via `piggy pivy tool`.
///
/// `sealer` is the password store the admin ops read a `-K @store` key from
/// (piggy#396); the binary passes its store-backed one.
pub fn run(args: &[String], sealer: &dyn ManagementKeySealer) -> i32 {
    let Some(inv) = parse(args) else {
        return usage();
    };
    match inv.op.as_str() {
        "pubkey" => cmd_pubkey(&inv),
        "cert" => cmd_cert(&inv),
        "attest" => cmd_attest(&inv),
        "sign" => cmd_sign(&inv),
        "ecdh" => cmd_ecdh(&inv),
        "change-pin" => cmd_change_secret(&inv, Secret::Pin),
        "change-puk" => cmd_change_secret(&inv, Secret::Puk),
        "reset-pin" => cmd_reset_pin(&inv),
        "set-admin" => cmd_set_admin(&inv, sealer),
        "delete-cert" => cmd_delete_cert(&inv, sealer),
        "update-keyhist" => cmd_update_keyhist(&inv, sealer),
        "write-cert" => cmd_write_cert(&inv, sealer),
        "generate" => cmd_generate(&inv, sealer),
        "import" => cmd_import(&inv, sealer),
        "pinfo" => cmd_pinfo(&inv),
        "list" => cmd_list(&inv),
        "factory-reset" => cmd_factory_reset(&inv),
        "req-cert" => cmd_req_cert(&inv),
        "version" => cmd_version(),
        "auth-test" => cmd_auth_test(&inv, sealer),
        "attest-verify" => cmd_attest_verify(&inv),
        // parse() only returns these ops.
        _ => unreachable!(),
    }
}

/// What `attest-verify` checks (piggy#397), over bytes only, so the checks
/// are unit-tested with generated chains and the card path only supplies
/// the bytes: the fresh slot attestation, the card's F9 certificate, the
/// slot's public key point as the card reports it, and the operator's
/// inputs.
pub struct AttestInputs<'a> {
    pub attestation_der: &'a [u8],
    pub f9_der: &'a [u8],
    /// The slot's key, SEC1 uncompressed, from the slot certificate the card
    /// serves; `None` when the slot key is not an EC key.
    pub slot_point: Option<&'a [u8]>,
    /// `--root FILE`: the PEM the F9 certificate must chain to; `None` is
    /// the embedded [`YUBICO_PIV_ROOT_CA_PEM`], checked against its pin.
    pub root_pem: Option<&'a [u8]>,
    /// `--saved FILE`: an earlier `piggy tool attest` output to compare with
    /// (its first PEM block): same key, same policy, same issuer.
    pub saved_pem: Option<&'a [u8]>,
    pub expect_pin: Option<PinPolicy>,
    pub expect_touch: Option<TouchPolicy>,
}

pub enum PointStatus {
    Pass,
    Fail,
    Skip(String),
}

/// Yubico's published PIV attestation root, "Yubico PIV Root CA Serial
/// 263751", the default root `attest-verify` chains a card's F9 certificate
/// to (piggy#397). PROVENANCE: fetched 2026-11-19T11:26:54Z by the
/// coordinator session (circus/eager-holly) with an anonymous GET of
/// https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem,
/// which answered 301 (through a plain-http hop) to
/// https://developers.yubico.com/PKI/yubico-piv-ca-1.pem, HTTP 200; the
/// served file's sha256 was
/// 6234f33d5f652109d265b391f2898b8ba92f62df406b684db18363f50d7c9129. The
/// certificate's SHA-256 fingerprint, [`YUBICO_PIV_ROOT_CA_SHA256`], is
/// identical to the reading FDR 0007 recorded from the operator's card host
/// on 2026-11-18. Both readings come from Yubico's own server over TLS: a
/// consistency check between two downloads, not an independent anchor. A
/// verifier with its own copy passes `--root FILE` instead. The pin is
/// checked every time the embedded root is used, and by a unit test.
pub const YUBICO_PIV_ROOT_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----
";

/// The pinned SHA-256 fingerprint of [`YUBICO_PIV_ROOT_CA_PEM`]'s DER.
pub const YUBICO_PIV_ROOT_CA_SHA256: &str = "63:EC:E9:14:E5:4D:D8:79:15:F3:40:33:C8:5A:F4:C0:69:6B:A1:51:2F:8A:DD:66:CE:D7:38:33:12:07:B5:46";

/// The embedded Yubico root, parsed and checked against its pin; an
/// embedded PEM that does not match the pin is refused, never used.
pub fn embedded_yubico_root() -> Result<openssl::x509::X509, String> {
    let root = openssl::x509::X509::from_pem(YUBICO_PIV_ROOT_CA_PEM.as_bytes())
        .map_err(|e| format!("the embedded Yubico root does not parse: {e}"))?;
    let fingerprint = x509_fingerprint(&root);
    if fingerprint != YUBICO_PIV_ROOT_CA_SHA256 {
        return Err(format!(
            "the embedded Yubico root's fingerprint {fingerprint} is not the pinned {YUBICO_PIV_ROOT_CA_SHA256}"
        ));
    }
    Ok(root)
}

/// One TAP point of the verdict.
pub struct AttestPoint {
    pub name: String,
    pub status: PointStatus,
    pub diags: Vec<(String, String)>,
}

fn point(
    name: impl Into<String>,
    status: PointStatus,
    diags: Vec<(String, String)>,
) -> AttestPoint {
    AttestPoint {
        name: name.into(),
        status,
        diags,
    }
}

/// The EC public key of a certificate as a SEC1 uncompressed point.
fn x509_ec_point(cert: &openssl::x509::X509) -> Result<Vec<u8>, String> {
    let pkey = cert
        .public_key()
        .map_err(|e| format!("certificate public key: {e}"))?;
    let ec = pkey
        .ec_key()
        .map_err(|_| "the certificate's key is not an EC key".to_string())?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| e.to_string())?;
    ec.public_key()
        .to_bytes(
            ec.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|e| e.to_string())
}

fn x509_fingerprint(cert: &openssl::x509::X509) -> String {
    match cert.digest(openssl::hash::MessageDigest::sha256()) {
        Ok(d) => d
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
        Err(e) => format!("(digest failed: {e})"),
    }
}

fn x509_name_oneline(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object().nid().short_name().unwrap_or("?"),
                e.data()
                    .as_utf8()
                    .map(|s| s.to_string())
                    .unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The checks, in the order a reader wants them: the signature chain, then
/// the key, then what the attestation states, then the comparison with a
/// saved one. A certificate that does not parse fails its point and the
/// points that need it SKIP naming the cause.
pub fn verify_attestation(inputs: &AttestInputs) -> Vec<AttestPoint> {
    use openssl::x509::X509;
    let mut out = Vec::new();
    let attestation = X509::from_der(inputs.attestation_der);
    let f9 = X509::from_der(inputs.f9_der);

    // 1. the attestation is signed by the card's F9 certificate
    out.push(
        match piggy_piv::attest::attestation_signed_by(inputs.attestation_der, inputs.f9_der) {
            Ok(true) => point(
                "attestation signed by the card's F9 certificate",
                PointStatus::Pass,
                f9.as_ref()
                    .map(|c| {
                        vec![(
                            "f9_subject".to_string(),
                            x509_name_oneline(c.subject_name()),
                        )]
                    })
                    .unwrap_or_default(),
            ),
            Ok(false) => point(
                "attestation signed by the card's F9 certificate",
                PointStatus::Fail,
                vec![(
                    "error".to_string(),
                    "the signature does not verify under F9's key".to_string(),
                )],
            ),
            Err(e) => point(
                "attestation signed by the card's F9 certificate",
                PointStatus::Fail,
                vec![("error".to_string(), e)],
            ),
        },
    );

    // 2. F9 chains to the root: the given one, else the embedded Yubico root
    let root = match inputs.root_pem {
        Some(pem) => X509::from_pem(pem)
            .map(|r| (r, "--root FILE"))
            .map_err(|e| format!("--root is not a PEM certificate: {e}")),
        None => embedded_yubico_root().map(|r| (r, "embedded Yubico PIV Root CA Serial 263751")),
    };
    out.push(match (root, &f9) {
        (Err(e), _) => point(
            "F9 certificate chains to the root",
            PointStatus::Fail,
            vec![("error".to_string(), e)],
        ),
        (Ok(_), Err(e)) => point(
            "F9 certificate chains to the root",
            PointStatus::Fail,
            vec![(
                "error".to_string(),
                format!("the F9 certificate does not parse: {e}"),
            )],
        ),
        (Ok((root, source)), Ok(f9)) => {
            let signed = root
                .public_key()
                .and_then(|k| f9.verify(&k))
                .map_err(|e| e.to_string());
            let names_agree = match (f9.issuer_name().to_der(), root.subject_name().to_der()) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            };
            let mut diags = vec![
                ("root_source".to_string(), source.to_string()),
                (
                    "root_subject".to_string(),
                    x509_name_oneline(root.subject_name()),
                ),
                ("root_sha256".to_string(), x509_fingerprint(&root)),
            ];
            let status = match signed {
                Ok(true) if names_agree => PointStatus::Pass,
                Ok(true) => {
                    diags.push((
                        "error".to_string(),
                        format!(
                            "F9's issuer is {} but the root's subject is {}",
                            x509_name_oneline(f9.issuer_name()),
                            x509_name_oneline(root.subject_name())
                        ),
                    ));
                    PointStatus::Fail
                }
                Ok(false) => {
                    diags.push((
                        "error".to_string(),
                        "F9's signature does not verify under the root's key".to_string(),
                    ));
                    PointStatus::Fail
                }
                Err(e) => {
                    diags.push(("error".to_string(), e));
                    PointStatus::Fail
                }
            };
            point("F9 certificate chains to the root", status, diags)
        }
    });

    // 3. the attested key is the slot's key
    out.push(match (&attestation, inputs.slot_point) {
        (Err(e), _) => point(
            "attested key is the slot's key",
            PointStatus::Fail,
            vec![(
                "error".to_string(),
                format!("the attestation does not parse: {e}"),
            )],
        ),
        (Ok(_), None) => point(
            "attested key is the slot's key",
            PointStatus::Fail,
            vec![(
                "error".to_string(),
                "the slot's key is not an EC key".to_string(),
            )],
        ),
        (Ok(att), Some(slot_point)) => match x509_ec_point(att) {
            Ok(p) if p == slot_point => {
                point("attested key is the slot's key", PointStatus::Pass, vec![])
            }
            Ok(_) => point(
                "attested key is the slot's key",
                PointStatus::Fail,
                vec![(
                    "error".to_string(),
                    "the attestation is for a different key".to_string(),
                )],
            ),
            Err(e) => point(
                "attested key is the slot's key",
                PointStatus::Fail,
                vec![("error".to_string(), e)],
            ),
        },
    });

    // 4. the policy the attestation states
    out.push(
        match piggy_piv::attest::parse_policy(inputs.attestation_der) {
            Ok((pin, touch)) => {
                let stated = piggy_piv::KeyPolicy { pin, touch };
                let mut diags = vec![("policy".to_string(), stated.to_string())];
                let pin_ok = inputs.expect_pin.is_none_or(|e| e == pin);
                let touch_ok = inputs.expect_touch.is_none_or(|e| e == touch);
                let status = if pin_ok && touch_ok {
                    PointStatus::Pass
                } else {
                    diags.push((
                        "expected".to_string(),
                        format!(
                            "PIN {}, touch {}",
                            inputs
                                .expect_pin
                                .map_or("any".to_string(), |p| p.to_string()),
                            inputs
                                .expect_touch
                                .map_or("any".to_string(), |t| t.to_string())
                        ),
                    ));
                    PointStatus::Fail
                };
                point(format!("attested policy: {stated}"), status, diags)
            }
            Err(e) => point(
                "attested policy",
                PointStatus::Fail,
                vec![("error".to_string(), e.to_string())],
            ),
        },
    );

    // 5. firmware and serial, as stated
    out.push({
        let firmware = piggy_piv::attest::firmware_version(inputs.attestation_der);
        let serial = piggy_piv::attest::serial_number(inputs.attestation_der);
        match (firmware, serial) {
            (Ok(Some((a, b, c))), Ok(Some(serial))) => point(
                format!("attestation names firmware {a}.{b}.{c}, serial {serial}"),
                PointStatus::Pass,
                vec![
                    ("firmware".to_string(), format!("{a}.{b}.{c}")),
                    ("serial".to_string(), serial.to_string()),
                ],
            ),
            (Ok(None), Ok(None)) => point(
                "attestation names firmware and serial",
                PointStatus::Skip("no YubicoPIV firmware or serial extension".to_string()),
                vec![],
            ),
            // One of the two: informational, so stated rather than failed.
            (Ok(f), Ok(s)) => point(
                format!(
                    "attestation names firmware {}, serial {}",
                    f.map_or("absent".to_string(), |(a, b, c)| format!("{a}.{b}.{c}")),
                    s.map_or("absent".to_string(), |n| n.to_string())
                ),
                PointStatus::Pass,
                vec![
                    (
                        "firmware".to_string(),
                        f.map_or("absent".to_string(), |(a, b, c)| format!("{a}.{b}.{c}")),
                    ),
                    (
                        "serial".to_string(),
                        s.map_or("absent".to_string(), |n| n.to_string()),
                    ),
                ],
            ),
            (Err(e), _) | (_, Err(e)) => point(
                "attestation names firmware and serial",
                PointStatus::Fail,
                vec![("error".to_string(), e.to_string())],
            ),
        }
    });

    // 6. a saved attestation agrees
    if let Some(saved_pem) = inputs.saved_pem {
        out.push(match (X509::from_pem(saved_pem), &attestation) {
            (Err(e), _) => point(
                "saved attestation agrees (key, policy, issuer)",
                PointStatus::Fail,
                vec![(
                    "error".to_string(),
                    format!("--saved is not a PEM certificate: {e}"),
                )],
            ),
            (_, Err(e)) => point(
                "saved attestation agrees (key, policy, issuer)",
                PointStatus::Fail,
                vec![(
                    "error".to_string(),
                    format!("the attestation does not parse: {e}"),
                )],
            ),
            (Ok(saved), Ok(att)) => {
                let mut differ = Vec::new();
                match (x509_ec_point(&saved), x509_ec_point(att)) {
                    (Ok(a), Ok(b)) if a == b => {}
                    _ => differ.push("key"),
                }
                let saved_der = saved.to_der().unwrap_or_default();
                match (
                    piggy_piv::attest::parse_policy(&saved_der),
                    piggy_piv::attest::parse_policy(inputs.attestation_der),
                ) {
                    (Ok(a), Ok(b)) if a == b => {}
                    _ => differ.push("policy"),
                }
                match (saved.issuer_name().to_der(), att.issuer_name().to_der()) {
                    (Ok(a), Ok(b)) if a == b => {}
                    _ => differ.push("issuer"),
                }
                if differ.is_empty() {
                    point(
                        "saved attestation agrees (key, policy, issuer)",
                        PointStatus::Pass,
                        vec![],
                    )
                } else {
                    point(
                        "saved attestation agrees (key, policy, issuer)",
                        PointStatus::Fail,
                        vec![("differs".to_string(), differ.join(", "))],
                    )
                }
            }
        });
    }
    out
}

/// Render the verdict as TAP 14 (or, with `-j`, one JSON object per point).
fn render_attest_points(
    points: &[AttestPoint],
    json: bool,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if json {
        for (i, p) in points.iter().enumerate() {
            let (ok, skip) = match &p.status {
                PointStatus::Pass => (true, None),
                PointStatus::Fail => (false, None),
                PointStatus::Skip(why) => (true, Some(why.as_str())),
            };
            let diags: serde_json::Map<String, serde_json::Value> = p
                .diags
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect();
            let line = serde_json::json!({
                "n": i + 1,
                "name": p.name,
                "ok": ok,
                "skip": skip,
                "diags": diags,
            });
            writeln!(out, "{line}")?;
        }
        return Ok(());
    }
    writeln!(out, "TAP version 14")?;
    writeln!(out, "1..{}", points.len())?;
    for (i, p) in points.iter().enumerate() {
        let n = i + 1;
        match &p.status {
            PointStatus::Pass => writeln!(out, "ok {n} - {}", p.name)?,
            PointStatus::Fail => writeln!(out, "not ok {n} - {}", p.name)?,
            PointStatus::Skip(why) => writeln!(out, "ok {n} - {} # SKIP {why}", p.name)?,
        }
        if !p.diags.is_empty() {
            writeln!(out, "  ---")?;
            for (k, v) in &p.diags {
                writeln!(out, "  {k}: {}", serde_json::Value::String(v.clone()))?;
            }
            writeln!(out, "  ...")?;
        }
    }
    Ok(())
}

/// `piggy tool attest-verify <slot>` (piggy#397): the slot's attestation
/// checked, not just printed: signed by the card's F9, F9 chained to the
/// given root, the attested key equal to the slot's key, the PIN and touch
/// policy decoded (and asserted with `--expect-*`), firmware and serial
/// read, and, with `--saved`, an earlier attestation compared by what it
/// states. Read-only, no PIN, any key slot 9A/9C/9D/9E and 82..95. TAP on
/// stdout (`-j` for JSON lines); exit 0 when no point fails, 1 when one
/// does, 2 for a usage error or an unreadable --root/--saved file.
fn cmd_attest_verify(inv: &Invocation) -> i32 {
    let op = "attest-verify";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let read_file = |what: &str, path: &Option<String>| -> Result<Option<Vec<u8>>, i32> {
        match path {
            None => Ok(None),
            Some(p) => std::fs::read(p).map(Some).map_err(|e| {
                eprintln!("piggy tool {op}: {what} {p}: {e}");
                2
            }),
        }
    };
    let root_pem = match read_file("--root", &inv.root) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let saved_pem = match read_file("--saved", &inv.saved) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: slot {slot_id:02X}: {e}");
            return 1;
        }
    };
    let slot_point: Option<Vec<u8>> = match slot.public_key().key_data() {
        ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP256(p)) => {
            Some(p.as_bytes().to_vec())
        }
        ssh_key::public::KeyData::Ecdsa(ssh_key::public::EcdsaPublicKey::NistP384(p)) => {
            Some(p.as_bytes().to_vec())
        }
        _ => None,
    };
    let attestation_der = match token.yk_attest(slot_id) {
        Ok(der) => der,
        Err(e) => {
            eprintln!(
                "piggy tool {op}: the card will not attest slot {slot_id:02X} ({e}): only a key generated on a YubiKey can be attested, not an imported one"
            );
            return 1;
        }
    };
    let f9_der = match token.read_slot(0xF9) {
        Ok(s) => s.cert_der().to_vec(),
        Err(e) => {
            eprintln!(
                "piggy tool {op}: cannot read the card's attestation certificate (slot F9): {e}"
            );
            return 1;
        }
    };
    let points = verify_attestation(&AttestInputs {
        attestation_der: &attestation_der,
        f9_der: &f9_der,
        slot_point: slot_point.as_deref(),
        root_pem: root_pem.as_deref(),
        saved_pem: saved_pem.as_deref(),
        expect_pin: inv.expect_pin,
        expect_touch: inv.expect_touch,
    });
    let stdout = std::io::stdout();
    if let Err(e) =
        render_attest_points(&points, inv.list_mode == ListMode::Json, &mut stdout.lock())
    {
        eprintln!("piggy tool {op}: write the report: {e}");
        return 2;
    }
    if points.iter().any(|p| matches!(p.status, PointStatus::Fail)) {
        1
    } else {
        0
    }
}

/// `piggy tool auth-test`: the management-key mutual authentication and
/// nothing else (piggy#396): no PUT DATA, no PIN, nothing printed on success.
/// Exit 0 when the current key (`-K`) authenticates, 1 with "failed to
/// authenticate with current admin key" when it does not (and the usual 1
/// for no card). A failed try costs nothing: PIV keeps no retry counter on
/// the management key. The read-only proof a rotation ends with.
fn cmd_auth_test(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "auth-test";
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let admin_key = match current_admin_key(inv, sealer, &token.guid().to_hex()) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    0
}

/// `piggy tool version`: piggy's bare version, the value `piggy version`'s
/// self-line carries (wrapper-injected `PIGGY_VERSION`, else this crate's),
/// in C `pivy-tool version`'s one-line shape (piggy#348).
fn cmd_version() -> i32 {
    let version = std::env::var("PIGGY_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("{version}");
    0
}

/// Print the `piggy tool` usage banner and return exit code 2, for an
/// operation or option the Rust port does not implement (piggy#289 3.6
/// cutover). The full C `pivy-tool` surface is reachable via `piggy pivy
/// tool` while C is shipped.
fn usage() -> i32 {
    eprintln!("piggy tool: unsupported operation or option");
    eprintln!(
        "supported: pubkey, cert, attest, sign, ecdh, change-pin, change-puk, \
         reset-pin, set-admin, delete-cert, update-keyhist, write-cert, generate, import, \
         pinfo, list, factory-reset, req-cert, version, auth-test, attest-verify"
    );
    eprintln!(
        "for the rest of the pivy-tool surface (init, RSA/Ed25519, …) \
         use: piggy pivy tool <args>"
    );
    2
}

/// `piggy tool pubkey <slot>`: print the slot's public key in OpenSSH
/// wire form (`<type> <base64>`), matching C `pivy-tool`'s `sshkey_write`.
fn cmd_pubkey(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "pubkey") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool pubkey: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool pubkey: slot {slot_id:02x}: {e}");
            return 1;
        }
    };
    // Match C `pivy-tool` exactly: after the OpenSSH `<type> <base64>` it
    // appends ` PIV_slot_<SLOT>@<GUID> "<cert-subject>"` as the key
    // comment (pivy-tool.c:1762). Setting that as the ssh comment yields
    // the same single-space-joined line.
    let subject = subject_oneline(slot.cert_der());
    let comment = format!(
        "PIV_slot_{slot_id:02X}@{} \"{subject}\"",
        token.guid().to_hex()
    );
    let mut pubkey = slot.public_key().clone();
    pubkey.set_comment(comment);
    match pubkey.to_openssh() {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(e) => {
            eprintln!("piggy tool pubkey: render OpenSSH: {e}");
            1
        }
    }
}

/// The certificate's subject DN as OpenSSL's `X509_NAME_oneline` renders
/// it (`/CN=foo`), which is what pivy's `piv_slot_subject` returns and
/// bakes into the pubkey comment. Best-effort: an unreadable cert yields
/// an empty string (the C side would have failed to read the slot at all).
fn subject_oneline(cert_der: &[u8]) -> String {
    let Ok(x509) = openssl::x509::X509::from_der(cert_der) else {
        return String::new();
    };
    let mut out = String::new();
    for entry in x509.subject_name().entries() {
        let key = entry
            .object()
            .nid()
            .short_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| entry.object().to_string());
        let val = entry
            .data()
            .as_utf8()
            .map(|s| s.to_string())
            .unwrap_or_default();
        out.push('/');
        out.push_str(&key);
        out.push('=');
        out.push_str(&val);
    }
    out
}

/// `piggy tool cert <slot>`: print the slot's X.509 certificate as PEM,
/// matching C `pivy-tool`'s `PEM_write_X509`.
fn cmd_cert(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "cert") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool cert: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool cert: slot {slot_id:02x}: {e}");
            return 1;
        }
    };
    match print_cert_pem(slot.cert_der()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("piggy tool cert: {e}");
            1
        }
    }
}

/// `piggy tool attest <slot>`: print the slot's YubiKey attestation cert
/// and then the device attestation cert, both PEM — matching C's two
/// `PEM_write_X509` calls (pivy-tool.c:1699,1719). Attestation is
/// unavailable for an imported key (INS_ATTEST returns 6A80), so on fibby
/// and on a real YubiKey's imported keys this fails just as C does; the
/// happy path is validated by the hardware lane.
fn cmd_attest(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "attest") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool attest: {msg}");
            return 1;
        }
    };
    // 1. The per-slot attestation cert (INS_ATTEST / 0xF9 signing key).
    let att = match token.yk_attest(slot_id) {
        Ok(der) => der,
        Err(e) => {
            eprintln!("piggy tool attest: attestation failed: {e}");
            return 1;
        }
    };
    if let Err(e) = print_cert_pem(&att) {
        eprintln!("piggy tool attest: slot attestation cert: {e}");
        return 1;
    }
    // 2. The device attestation cert (the F9 slot's own cert object).
    let dev = match token.read_slot(0xF9) {
        Ok(slot) => slot.cert_der().to_vec(),
        Err(e) => {
            eprintln!("piggy tool attest: read device attestation cert: {e}");
            return 1;
        }
    };
    if let Err(e) = print_cert_pem(&dev) {
        eprintln!("piggy tool attest: device attestation cert: {e}");
        return 1;
    }
    0
}

/// Re-encode a DER X.509 certificate as PEM and write it to stdout,
/// matching OpenSSL's `PEM_write_X509` (the PEM already ends in a
/// newline). Shared by `cert` and `attest`.
fn print_cert_pem(cert_der: &[u8]) -> Result<(), String> {
    let pem = openssl::x509::X509::from_der(cert_der)
        .and_then(|x509| x509.to_pem())
        .map_err(|e| format!("encode PEM: {e}"))?;
    print!("{}", String::from_utf8_lossy(&pem));
    Ok(())
}

/// `piggy tool sign <slot>`: hash stdin with the key's matching digest
/// (SHA-256 for P-256, SHA-384 for P-384) and ECDSA-sign it, writing the
/// card's raw signature bytes to stdout — matching C `pivy-tool`'s
/// `piv_sign` (which auto-selects the hash) + `fwrite`. PIN-gated.
fn cmd_sign(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "sign") {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool sign: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "piggy tool sign: failed to read cert for signing key in slot {slot_id:02X}: {e}"
            );
            return 1;
        }
    };
    let algorithm = slot.algorithm();
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("piggy tool sign: stdin: {e}");
        return 1;
    }
    // RFC 0012 §2.7: no surface that reaches a card signs an operator act
    // unseen. (C pivy-tool has no such rule; this is piggy's.)
    if let Err(refusal) = crate::operator_act::refuse_operator_act_signed_data(&input) {
        eprintln!("piggy tool sign: {refusal}");
        return 1;
    }
    // FDR 0007 phase (ii): nor does it sign a certificate with a CA key, and
    // the SSH CA slot (83) signs nothing here: its certificates go through
    // the agent, whose PIN dialog says what they certify.
    if let Err(refusal) = crate::operator_act::refuse_data_for_slot(&input, slot_id) {
        eprintln!("piggy tool sign: {refusal}");
        return 1;
    }
    let digest: Vec<u8> = match algorithm {
        PivAlgorithm::EcP256 => openssl::sha::sha256(&input).to_vec(),
        PivAlgorithm::EcP384 => openssl::sha::sha384(&input).to_vec(),
        other => {
            eprintln!(
                "piggy tool sign: slot {slot_id:02X} key algorithm {other:?} is not supported for signing"
            );
            return 1;
        }
    };
    let pin = match get_pin(inv, "sign") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool sign: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool sign: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool sign: PIN verification failed: {e}");
        return 1;
    }
    let sig = match session.sign_prehash(&slot, &digest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool sign: failed to sign data: {e}");
            return 1;
        }
    };
    if let Err(e) = std::io::stdout().write_all(&sig) {
        eprintln!("piggy tool sign: write: {e}");
        return 1;
    }
    0
}

/// `piggy tool req-cert <slot>`: build a minimal PKCS#10 CSR for the slot's EC
/// key, sign it with that key on the card (PIN-gated), and print it as PEM.
///
/// EC-only (piggy is EC): a non-EC slot key errors, pointing at `piggy pivy
/// tool req-cert`. The CSR is minimal (subject + SPKI + signature, no requested
/// extensions) — a valid, equivalent CSR carrying the slot key, NOT a byte-for-
/// byte clone of C's cert-template output (piggy#289 milestone 3.10; mirrors
/// `cert_builder`'s self-signed-cert minimalism). The subject CN comes from
/// `-n`, else defaults to `<slot-name>@<short-guid>`.
fn cmd_req_cert(inv: &Invocation) -> i32 {
    let op = "req-cert";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // The SSH certificate authority signs OpenSSH certificates and nothing
    // else; a certificate request is not one.
    if piggy_piv::slot::ca_kind(slot_id) == Some(piggy_piv::slot::CaKind::SshCertificate) {
        eprintln!(
            "piggy tool {op}: slot {slot_id:02X} is the SSH certificate authority: it signs \
             OpenSSH certificates (ssh-keygen -U -s) and nothing else, not a certificate request"
        );
        return 1;
    }
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let slot = match token.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: failed to read the key in slot {slot_id:02X}: {e}");
            return 1;
        }
    };
    let algorithm = slot.algorithm();
    if !matches!(algorithm, PivAlgorithm::EcP256 | PivAlgorithm::EcP384) {
        eprintln!(
            "piggy tool {op}: slot {slot_id:02X} key algorithm {algorithm:?} is not EC; \
             piggy req-cert is EC-only — use: piggy pivy tool req-cert {slot_id:02x}"
        );
        return 1;
    }
    let point = match slot.ec_sec1_point() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let cn = inv.cn.clone().unwrap_or_else(|| {
        let guid = token.guid().to_hex();
        format!("{}@{}", slot.slot_name(), &guid[..guid.len().min(8)])
    });
    let pin = match get_pin(inv, op) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool {op}: PIN verification failed: {e}");
        return 1;
    }
    let csr_der = match piggy_piv::cert_builder::build_csr(&point, algorithm, &cn, |digest| {
        session.sign_prehash(&slot, digest)
    }) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("piggy tool {op}: failed to build CSR: {e}");
            return 1;
        }
    };
    // DER -> PEM ("CERTIFICATE REQUEST"), via openssl for the standard framing.
    let pem = match openssl::x509::X509Req::from_der(&csr_der).and_then(|r| r.to_pem()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: PEM encode: {e}");
            return 1;
        }
    };
    if let Err(e) = std::io::stdout().write_all(&pem) {
        eprintln!("piggy tool {op}: write: {e}");
        return 1;
    }
    0
}

/// `piggy tool ecdh <slot>`: read an OpenSSH public key from stdin and
/// write the raw ECDH shared secret (the card's GENERAL AUTHENTICATE
/// output) to stdout — matching C `pivy-tool`'s `piv_ecdh` + `fwrite`.
/// PIN-gated; the key slots 9A/9C/9D/9E and the retired key-management slots
/// 82..95 can do ECDH (not the attestation slot F9).
fn cmd_ecdh(inv: &Invocation) -> i32 {
    let slot_id = match slot_arg(inv, "ecdh") {
        Ok(s) => s,
        Err(code) => return code,
    };
    if !is_key_slot(slot_id) {
        eprintln!("piggy tool ecdh: PIV slot {slot_id:02X} cannot be used for ECDH");
        return 1;
    }
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool ecdh: {msg}");
            return 1;
        }
    };
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("piggy tool ecdh: stdin: {e}");
        return 1;
    }
    let peer_point = match parse_openssh_ec_point(&input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool ecdh: {e}");
            return 1;
        }
    };
    let pin = match get_pin(inv, "ecdh") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool ecdh: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool ecdh: begin session: {e}");
            return 1;
        }
    };
    // Read before the VERIFY, so nothing sits between the VERIFY and the
    // ECDH (piggy#325).
    let slot = match session.read_slot(slot_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool ecdh: failed to read the key in slot {slot_id:02X}: {e}");
            return 1;
        }
    };
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool ecdh: PIN verification failed: {e}");
        return 1;
    }
    let secret = match session.ecdh_derive(&slot, &peer_point) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool ecdh: failed to compute ECDH: {e}");
            return 1;
        }
    };
    if let Err(e) = std::io::stdout().write_all(&secret) {
        eprintln!("piggy tool ecdh: write: {e}");
        return 1;
    }
    0
}

/// Parse an OpenSSH public-key line into its uncompressed SEC1 EC point,
/// the peer input `ecdh` feeds to the card (matches C's `sshkey_read` +
/// `piv_ecdh`).
fn parse_openssh_ec_point(input: &str) -> Result<Vec<u8>, String> {
    let pk = ssh_key::PublicKey::from_openssh(input.trim())
        .map_err(|e| format!("failed to parse public key input: {e}"))?;
    match pk.key_data() {
        ssh_key::public::KeyData::Ecdsa(ec) => Ok(ec.as_sec1_bytes().to_vec()),
        _ => Err("public key input is not an EC key".into()),
    }
}

/// The PIV PIN for a PIN-gated op: from `-P` if given, otherwise the same
/// `SSH_ASKPASS` prompt C `pivy-tool` uses (via `card_oracle::run_askpass`),
/// tagged with a `piggy-tool:<op>` context.
fn get_pin(inv: &Invocation, op: &str) -> Result<zeroize::Zeroizing<String>, String> {
    if let Some(p) = inv.pins.first() {
        return Ok(zeroize::Zeroizing::new(p.clone()));
    }
    crate::card_oracle::run_askpass(
        &format!("Enter PIV PIN for {op}: "),
        Some(&format!("piggy-tool:{op}")),
    )
    .map_err(|e| format!("PIN prompt failed: {e}"))
}

/// Which credential `change-pin`/`change-puk` rotates.
#[derive(Clone, Copy)]
enum Secret {
    Pin,
    Puk,
}

impl Secret {
    fn label(self) -> &'static str {
        match self {
            Secret::Pin => "PIN",
            Secret::Puk => "PUK",
        }
    }
    fn op(self) -> &'static str {
        match self {
            Secret::Pin => "change-pin",
            Secret::Puk => "change-puk",
        }
    }
}

/// Prompt for one credential value with `SSH_ASKPASS`, tagged so an
/// escaped prompt is identifiable.
fn prompt_secret(op: &str, which: &str, label: &str) -> Result<zeroize::Zeroizing<String>, String> {
    crate::card_oracle::run_askpass(
        &format!("Enter {which} {label}: "),
        Some(&format!("piggy-tool:{op}:{which}")),
    )
    .map_err(|e| format!("{which} {label} prompt failed: {e}"))
}

/// `piggy tool change-pin` / `change-puk`: rotate the PIV PIN or PUK
/// (CHANGE REFERENCE DATA, INS 0x24) — matching C `pivy-tool`'s
/// `piv_change_pin`. The current and new values come from two repeated
/// `-P` options (exactly as C consumes them); when either is absent piggy
/// prompts via `SSH_ASKPASS` (C requires a tty for that path). No stdout
/// on success, matching C.
fn cmd_change_secret(inv: &Invocation, secret: Secret) -> i32 {
    let label = secret.label();
    let op = secret.op();
    let old = match inv.pins.first() {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "current", label) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let new = match inv.pins.get(1) {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "new", label) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    let result = match secret {
        Secret::Pin => session.change_pin(&old, &new),
        Secret::Puk => session.change_puk(&old, &new),
    };
    match result {
        Ok(()) => 0,
        Err(piggy_piv::PivError::PinIncorrect { retries }) => {
            eprintln!(
                "piggy tool {op}: current {label} was incorrect ({retries} attempt(s) remaining); {label} change failed"
            );
            1
        }
        Err(e) => {
            eprintln!("piggy tool {op}: failed to set new {label}: {e}");
            1
        }
    }
}

/// `piggy tool reset-pin`: unblock the PIV PIN using the PUK and install a
/// new PIN (RESET RETRY COUNTER, INS 0x2C) — matching C `pivy-tool`'s
/// `piv_reset_pin`. The two repeated `-P` options are the PUK then the new
/// PIN (exactly as C consumes them); when either is absent piggy prompts
/// via `SSH_ASKPASS` (C requires a tty for that path). No stdout on
/// success, matching C.
fn cmd_reset_pin(inv: &Invocation) -> i32 {
    let op = "reset-pin";
    let puk = match inv.pins.first() {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "current", "PUK") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let new_pin = match inv.pins.get(1) {
        Some(p) => zeroize::Zeroizing::new(p.clone()),
        None => match prompt_secret(op, "new", "PIN") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        },
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    match session.reset_pin(&puk, &new_pin) {
        Ok(()) => 0,
        Err(piggy_piv::PivError::PinIncorrect { retries }) => {
            eprintln!(
                "piggy tool {op}: PUK was incorrect ({retries} attempt(s) remaining); PIN reset failed"
            );
            1
        }
        Err(e) => {
            eprintln!("piggy tool {op}: failed to reset PIN: {e}");
            1
        }
    }
}

/// `piggy tool set-admin <newkey>`: rotate the PIV management (admin) key —
/// matching C `pivy-tool`'s `cmd_set_admin` (mgmt-key mutual authentication
/// with the current key, then YubicoPIV SET MANAGEMENT KEY). The current key
/// comes from `-K` (`default` or hex; default: the factory 3DES key); the new
/// key is the positional (`default` or hex). 3DES-only in this port — AES
/// admin keys, `random`, `@file`, and `-R` PINFO-save fall through to C
/// (rejected in `parse`). No stdout on success, matching C.
fn cmd_set_admin(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "set-admin";
    // parse() guaranteed exactly one positional: `-` (one hex line on stdin,
    // piggy#396) or a modeled key form.
    let new_key = if inv.positionals[0] == "-" {
        match read_new_admin_key(&mut std::io::stdin().lock()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("piggy tool {op}: new admin key: {e}");
                return 2;
            }
        }
    } else {
        match resolve_admin_key(&inv.positionals[0]) {
            Ok(k) => Zeroizing::new(k),
            Err(e) => {
                eprintln!("piggy tool {op}: new admin key: {e}");
                return 2;
            }
        }
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let old_key = match current_admin_key(inv, sealer, &token.guid().to_hex()) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&old_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.set_management_key_3des(&new_key) {
        eprintln!("piggy tool {op}: failed to set new admin key: {e}");
        return 1;
    }
    0
}

/// Resolve an admin-key argument to its 24-byte 3DES value: `default` → the
/// factory key, else a hex string decoded to bytes. Errors (like C's
/// EXIT_BAD_ARGS) when the hex is malformed or not 24 bytes.
fn resolve_admin_key(arg: &str) -> Result<Vec<u8>, String> {
    if arg == "default" {
        return Ok(piggy_piv::DEFAULT_ADMIN_KEY.to_vec());
    }
    if arg.is_empty() || !arg.len().is_multiple_of(2) || !arg.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(format!("{arg:?} is not a hex admin key"));
    }
    let bytes: Vec<u8> = (0..arg.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&arg[i..i + 2], 16).expect("validated hex"))
        .collect();
    if bytes.len() != 24 {
        return Err(format!(
            "admin key must be 24 bytes for 3DES ({} given)",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// `piggy tool delete-cert <slot>`: clear a slot's certificate object —
/// matching C `pivy-tool`'s `cmd_delete_cert` (mgmt-key mutual auth with the
/// current key, then PUT DATA at the slot's cert tag with an empty body). The
/// current key comes from `-K` (`default` or hex; default: the factory 3DES
/// key). Slots 9A/9C/9D/9E and the retired 82..95. On a YubiKey <5.7 (fibby's model) this clears only
/// the cert, not the private key, exactly as C does. No stdout on success.
fn cmd_delete_cert(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "delete-cert";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let admin_key = match current_admin_key(inv, sealer, &token.guid().to_hex()) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.clear_cert(slot_id) {
        eprintln!("piggy tool {op}: failed to clear the certificate for slot {slot_id:02X}: {e}");
        return 1;
    }
    0
}

/// `piggy tool update-keyhist`: rescan the retired key slots and rewrite the
/// PIV Key History object — matching C `pivy-tool`'s `cmd_update_keyhist`.
/// The `oncard` count is recomputed from the retired slots (82..95); the
/// `offcard` count and off-card URL are preserved from the existing object;
/// then mgmt-key mutual auth (current key from `-K`, default factory 3DES)
/// gates the PUT DATA at `5FC10C`. No stdout on success, matching C.
fn cmd_update_keyhist(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "update-keyhist";
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let admin_key = match current_admin_key(inv, sealer, &token.guid().to_hex()) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    // Recompute oncard from the retired slots; preserve offcard/url from the
    // existing Key History object (exactly what pivy's update-keyhist does).
    let oncard = token.count_oncard_retired();
    let existing = match token.read_keyhistory() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("piggy tool {op}: failed to read the existing key history: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.write_keyhistory(oncard, existing.offcard, existing.url.as_deref()) {
        eprintln!("piggy tool {op}: failed to write the key history object: {e}");
        return 1;
    }
    0
}

/// `piggy tool write-cert <slot>`: read an X.509 certificate (DER or PEM)
/// from stdin and write it to the slot's cert object — matching C
/// `pivy-tool`'s `cmd_write_cert` (mgmt-key mutual auth, then PUT DATA at the
/// slot's cert tag wrapping the DER as `70 <cert> 71 00`). The current key
/// comes from `-K` (`default` or hex). Slots 9A/9C/9D/9E and the retired
/// 82..95. No stdout on success, matching C.
fn cmd_write_cert(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "write-cert";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("piggy tool {op}: stdin: {e}");
        return 1;
    }
    let cert_der = match parse_cert_input(&input) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let admin_key = match current_admin_key(inv, sealer, &token.guid().to_hex()) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.put_cert(slot_id, &cert_der) {
        eprintln!("piggy tool {op}: failed to write the certificate to slot {slot_id:02X}: {e}");
        return 1;
    }
    0
}

/// Parse an X.509 certificate from stdin bytes, accepting DER or PEM (C
/// `pivy-tool`'s `cmd_write_cert` tries DER first, then PEM). Returns the
/// canonical DER the card stores.
fn parse_cert_input(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if let Ok(x509) = openssl::x509::X509::from_der(bytes) {
        return x509
            .to_der()
            .map_err(|e| format!("re-encode cert DER: {e}"));
    }
    let x509 = openssl::x509::X509::from_pem(bytes)
        .map_err(|_| "invalid certificate input (expected DER or PEM on stdin)".to_string())?;
    x509.to_der()
        .map_err(|e| format!("re-encode cert DER: {e}"))
}

/// `piggy tool generate <slot> -a <alg>`: generate a new key pair on the
/// card, self-sign a minimal cert for it, and print the new public key —
/// matching C `pivy-tool`'s `cmd_generate` (GENERATE ASYMMETRIC under mgmt
/// auth, then a PIN-gated self-signed cert). Modeled for the EC algorithms
/// (`eccp256`, `eccp384`) on slots 9A/9C/9D/9E and the retired 82..95; other
/// algorithms are a usage error. The generated key is random on real
/// hardware (so the printed pubkey differs per run); the self-signed cert C
/// writes carries a random serial (a side effect that legitimately differs).
/// Prints `<openssh-pubkey> PIV_slot_XX@<GUID>`, matching C's format (a bare
/// slot/GUID comment — no cert subject, unlike `pubkey`).
fn cmd_generate(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "generate";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // parse() validated the algorithm and slot.
    let (algorithm, alg_byte) = inv
        .alg
        .as_deref()
        .and_then(parse_ec_alg)
        .expect("parse() validated -a");
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let guid = token.guid().to_hex();
    let admin_key = match current_admin_key(inv, sealer, &guid) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    let pin = match get_pin(inv, op) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    let point = match session.generate_key(
        slot_id,
        alg_byte,
        inv.pin_policy.generate_tag_byte(),
        inv.touch_policy.generate_tag_byte(),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: key generation failed: {e}");
            return 1;
        }
    };
    // The self-signed cert is signed by the freshly-generated slot key, which
    // is PIN-gated — C's selfsign_slot does the same via assert_pin.
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool {op}: PIN verification failed: {e}");
        return 1;
    }
    let cert_der = match piggy_piv::cert_builder::build_self_signed_cert(
        &point,
        algorithm,
        &format!("PIV slot {slot_id:02X}"),
        // The slot has no certificate yet, so the algorithm cannot be read
        // back from one: pass the one the key was just generated with.
        |digest| session.sign_prehash_with_alg(slot_id, alg_byte, digest),
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("piggy tool {op}: self-signing the new cert failed: {e}");
            return 1;
        }
    };
    if let Err(e) = session.put_cert(slot_id, &cert_der) {
        eprintln!("piggy tool {op}: failed to write the new cert to slot {slot_id:02X}: {e}");
        return 1;
    }
    match generated_key_openssh_line(&point, slot_id, &guid) {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            1
        }
    }
}

/// A key just generated in `slot` as an OpenSSH public-key line, from its
/// uncompressed EC point, commented `PIV_slot_<SLOT>@<GUID>` (`guid` as
/// given, uppercase hex). The line `piggy tool generate` and `piggy card
/// add-key` both print.
pub fn generated_key_openssh_line(point: &[u8], slot: u8, guid: &str) -> Result<String, String> {
    let ecdsa = ssh_key::public::EcdsaPublicKey::from_sec1_bytes(point)
        .map_err(|e| format!("parse generated public key: {e}"))?;
    let mut pubkey = ssh_key::PublicKey::from(ssh_key::public::KeyData::Ecdsa(ecdsa));
    pubkey.set_comment(format!("PIV_slot_{slot:02X}@{guid}"));
    pubkey
        .to_openssh()
        .map_err(|e| format!("render OpenSSH: {e}"))
}

/// The message directing an unsupported `import` key type to the C path.
const IMPORT_UNSUPPORTED: &str =
    "piggy tool import supports EC P-256/P-384 keys; use `piggy pivy tool import` for RSA/Ed25519";

/// `piggy tool import <slot>`: read an OpenSSH private key from stdin, import
/// it into the slot (YubicoPIV IMPORT ASYMMETRIC, INS 0xFE), self-sign a
/// minimal cert for it (PIN-gated), and write it — matching C `cmd_import`.
/// Modeled for EC P-256/P-384 keys (piggy is EC-only); an RSA/Ed25519 key
/// errors and points at `piggy pivy tool import` for the C path. Needs `-K`
/// (mgmt) and a PIN (`-P`/askpass, for the self-sign). Silent on success.
fn cmd_import(inv: &Invocation, sealer: &dyn ManagementKeySealer) -> i32 {
    let op = "import";
    let slot_id = match slot_arg(inv, op) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let pin = match get_pin(inv, op) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("piggy tool {op}: stdin: {e}");
        return 1;
    }
    let (algorithm, alg_byte, scalar, point) = match parse_openssh_ec_private(&input) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("piggy tool {op}: {e}");
            return 1;
        }
    };
    let mut token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let admin_key = match current_admin_key(inv, sealer, &token.guid().to_hex()) {
        Ok(k) => k,
        Err((code, msg)) => {
            eprintln!("piggy tool {op}: {msg}");
            return code;
        }
    };
    let mut session = match token.begin_pin_session() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("piggy tool {op}: begin session: {e}");
            return 1;
        }
    };
    if let Err(e) = session.authenticate_admin(&admin_key, piggy_piv::apdu::alg::TDEA_3KEY) {
        eprintln!("piggy tool {op}: failed to authenticate with current admin key: {e}");
        return 1;
    }
    if let Err(e) = session.import_ec_key(slot_id, alg_byte, &scalar) {
        eprintln!("piggy tool {op}: failed to import the key into slot {slot_id:02X}: {e}");
        return 1;
    }
    // The self-signed cert is signed by the freshly-imported slot key, which
    // is PIN-gated — C's selfsign_slot does the same via assert_pin.
    if let Err(e) = session.verify_pin(&pin) {
        eprintln!("piggy tool {op}: PIN verification failed: {e}");
        return 1;
    }
    let cert_der = match piggy_piv::cert_builder::build_self_signed_cert(
        &point,
        algorithm,
        &format!("PIV slot {slot_id:02X}"),
        // The key was just imported and has no cert yet, so its algorithm
        // is the one imported; reading the slot would find the old cert.
        |digest| session.sign_prehash_with_alg(slot_id, alg_byte, digest),
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("piggy tool {op}: self-signing the imported cert failed: {e}");
            return 1;
        }
    };
    if let Err(e) = session.put_cert(slot_id, &cert_der) {
        eprintln!("piggy tool {op}: failed to write the cert to slot {slot_id:02X}: {e}");
        return 1;
    }
    0
}

/// Parse an OpenSSH private key into `(algorithm, alg-byte, private scalar,
/// SEC1 uncompressed public point)` for the EC curves this port imports
/// (P-256/P-384). A non-EC key (RSA/Ed25519) is an error directing to the C
/// path.
#[allow(clippy::type_complexity)]
fn parse_openssh_ec_private(input: &str) -> Result<(PivAlgorithm, u8, Vec<u8>, Vec<u8>), String> {
    let key = ssh_key::private::PrivateKey::from_openssh(input.trim())
        .map_err(|e| format!("failed to parse OpenSSH private key: {e}"))?;
    // Public point (SEC1 uncompressed) from the key's public half.
    let point = match key.public_key().key_data() {
        ssh_key::public::KeyData::Ecdsa(ec) => ec.as_sec1_bytes().to_vec(),
        _ => return Err(IMPORT_UNSUPPORTED.into()),
    };
    let (algorithm, alg_byte, scalar) = match key.key_data() {
        ssh_key::private::KeypairData::Ecdsa(ec) => match ec {
            ssh_key::private::EcdsaKeypair::NistP256 { private, .. } => (
                PivAlgorithm::EcP256,
                piggy_piv::apdu::alg::ECCP256,
                private.as_slice().to_vec(),
            ),
            ssh_key::private::EcdsaKeypair::NistP384 { private, .. } => (
                PivAlgorithm::EcP384,
                piggy_piv::apdu::alg::ECCP384,
                private.as_slice().to_vec(),
            ),
            _ => return Err(IMPORT_UNSUPPORTED.into()),
        },
        _ => return Err(IMPORT_UNSUPPORTED.into()),
    };
    Ok((algorithm, alg_byte, scalar, point))
}

/// `piggy tool pinfo`: read and print the PIV Printed Information object —
/// matching C `pivy-tool`'s `cmd_pinfo` (`%12s: %s` per field, an optional
/// two-line `organization`, and a `yubico: contains admin key` line). Absent
/// fields render as `(null)`, matching C's `printf("%s", NULL)`. The card
/// models the object PIN-free; a real card's PIN-gated PINFO read (C's
/// `assert_pin` retry) is a tracked follow-up.
fn cmd_pinfo(inv: &Invocation) -> i32 {
    let op = "pinfo";
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    let pi = match token.read_pinfo() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("piggy tool {op}: failed to read printed info: {e}");
            return 1;
        }
    };
    let field = |v: &Option<String>| v.clone().unwrap_or_else(|| "(null)".to_string());
    println!("{:>12}: {}", "name", field(&pi.name));
    println!("{:>12}: {}", "affiliation", field(&pi.affiliation));
    println!("{:>12}: {}", "expiry", field(&pi.expiry));
    println!("{:>12}: {}", "serial", field(&pi.serial));
    println!("{:>12}: {}", "issuer", field(&pi.issuer));
    if pi.org_1.is_some() || pi.org_2.is_some() {
        println!(
            "{:>12}: {}",
            "organization",
            pi.org_1.as_deref().unwrap_or("")
        );
        println!("{:>12}  {}", "", pi.org_2.as_deref().unwrap_or(""));
    }
    if pi.has_admin_key {
        println!("{:>12}: contains admin key", "yubico");
    }
    0
}

/// pivy-tool's `escape_qstr` (`vendor/pivy/src/pivy-tool.c`): backslash-escape
/// `"`, `\`, and `'`, and render a newline as `\n`. Applied to the cert
/// subject/issuer before they go inside a JSON string, matching C's `-j list`
/// (whose output is therefore not strict JSON — a `'` in a DN becomes `\'`).
fn escape_qstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' {
            out.push_str("\\n");
            continue;
        }
        if c == '"' || c == '\\' || c == '\'' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Lowercase hex of a byte slice (C's `buf_to_hex(_, _, B_FALSE)`), used for the
/// CHUID cardholder UUID. Note: the case is not verified against C here — the
/// fibby differential card carries no cardholder UUID, so this path is
/// exercised only on real cards that populate CHUID tag `0x36`.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `piggy tool [-j|-p] list`: describe every PIV token, byte-for-byte like C
/// `pivy-tool list` in the same mode (`cmd_list`). Read-only and PIN-free.
///
/// The token-capability fields
/// (`auth`, `vci_supported`, `algorithms`) use the no-Discovery-object defaults,
/// which are what a YubiKey reports (its SELECT FCI is AID-only and it publishes
/// no Discovery object); a non-YubiKey PIV card that publishes a Discovery
/// object or advertises an algorithm list is a documented follow-up.
fn cmd_list(inv: &Invocation) -> i32 {
    let op = "list";
    let ctx = match PivContext::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("piggy tool {op}: PC/SC: {e}");
            return 1;
        }
    };
    let tokens = match ctx.enumerate_tokens() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("piggy tool {op}: enumerate tokens: {e}");
            return 1;
        }
    };
    // `-g <hex>` filters to tokens whose GUID starts with the (uppercase) prefix,
    // like C. An invalid hex prefix is a clear error rather than a silent no-match.
    let prefix = match inv.guid.as_deref() {
        Some(p) => {
            let p = p.to_ascii_uppercase();
            if !p.chars().all(|c| c.is_ascii_hexdigit()) {
                eprintln!("piggy tool {op}: -g {p:?}: not a hex GUID prefix");
                return 1;
            }
            Some(p)
        }
        None => None,
    };
    let mut out = String::new();
    for token in &tokens {
        if let Some(p) = &prefix {
            if !token.guid().to_hex().starts_with(p) {
                continue;
            }
        }
        let rendered = match inv.list_mode {
            ListMode::Json => list_json_for_token(token).map(|line| line + "\n"),
            ListMode::Parseable => list_parseable_for_token(token),
            ListMode::Human => list_human_for_token(token),
        };
        match rendered {
            Ok(text) => out.push_str(&text),
            Err(e) => {
                eprintln!("piggy tool {op}: {e}");
                return 1;
            }
        }
    }
    print!("{out}");
    0
}

/// Build one token's `-j list` JSON object, matching C's `cmd_list` field order
/// and conditional fields exactly.
fn list_json_for_token(token: &PivToken) -> Result<String, piggy_piv::PivError> {
    let guid_hex = token.guid().to_hex();
    let short_id = &guid_hex[..guid_hex.len().min(8)];

    let mut s = String::new();
    s.push('{');
    s.push_str(&format!("\"short_id\":\"{short_id}\""));
    s.push_str(&format!(",\"guid\":\"{guid_hex}\""));
    s.push_str(&format!(",\"reader\":\"{}\"", token.reader_name()));

    // chuid (piggy's enumerate_tokens only returns initialized tokens, so the
    // object is always present — never the JSON `null` C emits for a blank card).
    let chuid = token.chuid();
    s.push_str(",\"chuid\":{");
    s.push_str(&format!("\"signed\":{}", chuid.signed));
    if let Some(ch) = &chuid.cardholder {
        s.push_str(&format!(",\"cardholder\":\"{}\"", hex_lower(ch)));
    }
    let fascn = chuid
        .fascn
        .as_ref()
        .map(|f| f.to_pivy_string())
        .unwrap_or_default();
    s.push_str(&format!(",\"fasc-n\":\"{fascn}\""));
    s.push_str(&format!(
        ",\"expiry\":\"{}\"",
        chuid.expiry.as_deref().unwrap_or("")
    ));
    // C's piv_chuid_is_expired is a stub returning B_FALSE — always false.
    s.push_str(",\"expired\":false");
    s.push('}');

    // ykpiv: a GET VERSION that answers marks a YubicoPIV token. When it is one,
    // the PIV-applet serial (if the applet exposes it) and the version follow.
    let version = token.read_ykpiv_version();
    let is_ykpiv = version.is_some();
    s.push_str(&format!(",\"ykpiv\":{is_ykpiv}"));
    if let Some(v) = version {
        if let Some(serial) = token.read_ykpiv_piv_serial() {
            s.push_str(&format!(",\"serial\":{serial}"));
        }
        s.push_str(&format!(
            ",\"ykpiv_version\":\"{}.{}.{}\"",
            v[0], v[1], v[2]
        ));
    }

    // applet_uri/applet: omitted (piggy does not parse the SELECT FCI's optional
    // label/uri tags; a YubiKey advertises neither, and C omits an absent field).
    // auth/vci_supported/algorithms: the no-Discovery-object defaults a YubiKey
    // reports (see cmd_list docs).
    s.push_str(
        ",\"auth\":{\"pin\":{\"supported\":true,\"default\":true},\
         \"global_pin\":{\"supported\":false,\"default\":false},\
         \"biometrics\":{\"supported\":false,\"default\":false}}",
    );
    s.push_str(",\"vci_supported\":false");
    s.push_str(",\"algorithms\":[]");

    // slots: keyed by lowercase `%02x` slot id, over the standard slots only
    // (9A, 9C, 9D, 9E) — matching C's default `list`, which reads the standard
    // certs and enumerates retired slots 82..95 ONLY under an explicit flag
    // (`enum_all_retired`). Empty slots are skipped, like C's piv_slot_next.
    s.push_str(",\"slots\":{");
    let mut first = true;
    for &slot_id in piggy_piv::slot::STANDARD_SLOTS {
        let slot = match token.read_slot(slot_id) {
            Ok(slot) => slot,
            Err(_) => continue,
        };
        if !first {
            s.push(',');
        }
        first = false;
        let (subject, issuer, serial) = slot.cert_display_fields()?;
        s.push_str(&format!("\"{:02x}\":{{", slot.id()));
        s.push_str(&format!("\"name\":\"{}\"", slot.slot_name()));
        s.push_str(&format!(",\"algorithm\":\"{}\"", slot.algorithm_label()));
        s.push_str(&format!(",\"key_type\":\"{}\"", slot.key_type()));
        s.push_str(&format!(",\"key_size\":{}", slot.key_bits()));
        s.push_str(&format!(",\"subject\":\"{}\"", escape_qstr(&subject)));
        s.push_str(&format!(",\"issuer\":\"{}\"", escape_qstr(&issuer)));
        s.push_str(&format!(",\"cert_serial\":\"{serial}\""));
        s.push_str(&format!(
            ",\"pubkey\":\"{}\"",
            slot.ssh_public_key_string()?
        ));
        s.push('}');
    }
    s.push('}');

    s.push('}');
    Ok(s)
}

/// The standard-slot keys `list` reports, in C's `piv_slot_next` order; empty
/// slots are absent.
fn listed_slots(token: &PivToken) -> Vec<piggy_piv::slot::PivSlot> {
    piggy_piv::slot::STANDARD_SLOTS
        .iter()
        .filter_map(|&id| token.read_slot(id).ok())
        .collect()
}

/// Build one token's `-p list` line, matching C `cmd_list`'s parseable branch:
/// `reader:guid:chuid:ykpiv:version:serial:algs` then one `:<ID>[;subject;type;bits]`
/// field per slot id 9A..9E (9B included, so always bare).
fn list_parseable_for_token(token: &PivToken) -> Result<String, piggy_piv::PivError> {
    let version = token.read_ykpiv_version();
    let [major, minor, patch] = version.unwrap_or([0, 0, 0]);
    let serial = version
        .and_then(|_| token.read_ykpiv_piv_serial())
        .unwrap_or(0);
    let mut s = format!(
        "{}:{}:true:{}:{major}.{minor}.{patch}:{serial}:",
        token.reader_name(),
        token.guid().to_hex(),
        version.is_some(),
    );
    // No algorithm list: the no-Discovery-object default (see cmd_list docs).
    let slots = listed_slots(token);
    for id in 0x9Au8..0x9F {
        match slots.iter().find(|slot| slot.id() == id) {
            None => s.push_str(&format!(":{id:02X}")),
            Some(slot) => {
                let (subject, _, _) = slot.cert_display_fields()?;
                s.push_str(&format!(
                    ":{id:02X};{subject};{};{}",
                    slot.key_type(),
                    slot.key_bits()
                ));
            }
        }
    }
    s.push('\n');
    Ok(s)
}

/// Build one token's human `list` block, matching C `cmd_list`'s default
/// branch for what piggy reads: the fields piggy does not parse (cardcap, the
/// SELECT FCI's applet label/uri, extended-length APDU support, a Discovery
/// object's auth/VCI/algorithms) take the defaults the JSON mode uses.
fn list_human_for_token(token: &PivToken) -> Result<String, piggy_piv::PivError> {
    let guid_hex = token.guid().to_hex();
    let chuid = token.chuid();
    let mut s = String::new();
    let mut field = |name: &str, value: &str| s.push_str(&format!("{name:>10}: {value}\n"));
    field("card", &guid_hex[..guid_hex.len().min(8)]);
    field("device", token.reader_name());
    field("chuid", if chuid.signed { "ok, signed" } else { "ok" });
    field("guid", &guid_hex);
    if let Some(ch) = &chuid.cardholder {
        field("owner", &hex_lower(ch));
    }
    if let Some(fascn) = &chuid.fascn {
        field("fasc-n", &fascn.to_pivy_string());
    }
    if let Some(e) = chuid.expiry.as_deref() {
        let b = e.as_bytes();
        if b.len() == 8 && b[0].is_ascii_digit() {
            field("expiry", &format!("{}-{}-{}", &e[..4], &e[4..6], &e[6..]));
        }
    }
    if let Some(v) = token.read_ykpiv_version() {
        field(
            "yubico",
            &format!(
                "implements YubicoPIV extensions (v{}.{}.{})",
                v[0], v[1], v[2]
            ),
        );
        if let Some(serial) = token.read_ykpiv_piv_serial() {
            field("serial", &serial.to_string());
        }
    }
    field("auth", "PIN*");
    s.push_str(&format!("{:>10}:\n", "slots"));
    s.push_str(&format!(
        "{:>10} {:<3}  {:<7}  {:<4}  {:<30}\n",
        "", "ID", "TYPE", "BITS", "CERTIFICATE"
    ));
    for slot in listed_slots(token) {
        let (subject, _, _) = slot.cert_display_fields()?;
        s.push_str(&format!(
            "{:>10} {:<3x}  {:<7}  {:<4}  {:<30}\n",
            "",
            slot.id(),
            slot.key_type(),
            slot.key_bits(),
            subject
        ));
    }
    s.push('\n');
    Ok(s)
}

/// Confirm a destructive `factory-reset`. `--yes`/`--force` skips the prompt.
/// Otherwise require the operator to type `YES` on the controlling tty — like C
/// `pivy-tool`'s `RPP_REQUIRE_TTY` prompt. There is deliberately NO stdin
/// fallback: a reset that erases every key needs either a real tty or the
/// explicit `--yes` flag, so a stray piped `YES` cannot trigger it. This is a
/// piggy-native gate (pivy-tool has no scriptable confirmation), documented in
/// piggy(1) / #291 and outside the differential contract.
fn confirm_factory_reset(force: bool) -> bool {
    if force {
        return true;
    }
    eprintln!("WARNING: factory-reset erases ALL keys and certificates on this card.");
    let mut tty = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    {
        Ok(t) => t,
        Err(_) => {
            eprintln!(
                "piggy tool factory-reset: no controlling tty for confirmation; \
                 pass --yes to confirm non-interactively."
            );
            return false;
        }
    };
    if write!(tty, "Type 'YES' to continue: ")
        .and_then(|()| tty.flush())
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    let n = match tty.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    String::from_utf8_lossy(&buf[..n]).trim() == "YES"
}

/// `piggy tool factory-reset`: wipe the PIV applet to factory state via
/// YubicoPIV RESET (INS 0xFB), after a confirmation gate. The card only permits
/// the reset once BOTH the PIN and the PUK are blocked (else SW 6985). Ports C
/// `pivy-tool`'s `cmd_factory_reset` wire, with a scriptable confirmation gate
/// in place of C's tty-only `YES` prompt (piggy#291).
fn cmd_factory_reset(inv: &Invocation) -> i32 {
    let op = "factory-reset";
    if !confirm_factory_reset(inv.force) {
        eprintln!("piggy tool {op}: aborted (confirmation not given)");
        return 1;
    }
    let token = match select_token(inv.guid.as_deref()) {
        Ok(t) => t,
        Err(msg) => {
            eprintln!("piggy tool {op}: {msg}");
            return 1;
        }
    };
    match token.factory_reset() {
        Ok(()) => {
            eprintln!("piggy tool {op}: PIV applet reset to factory state.");
            0
        }
        Err(piggy_piv::PivError::Apdu { sw: 0x6985 }) => {
            eprintln!(
                "piggy tool {op}: the card refused the reset — both the PIN and the PUK \
                 must be blocked first (SW 6985)."
            );
            1
        }
        Err(e) => {
            eprintln!("piggy tool {op}: reset failed: {e}");
            1
        }
    }
}

/// The slot positional (`9a`, `9d`, `9e`, `9c`, `82`..`95`, `f9`),
/// parsed as a hex byte and validated as a PIV slot that can hold a cert.
fn slot_arg(inv: &Invocation, op: &str) -> Result<u8, i32> {
    let Some(raw) = inv.positionals.first() else {
        eprintln!("piggy tool {op}: missing slot (e.g. 9d)");
        return Err(2);
    };
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    let slot_id = u8::from_str_radix(hex, 16).map_err(|_| {
        eprintln!("piggy tool {op}: invalid slot {raw:?} (want a hex slot id like 9d)");
        2
    })?;
    if !piggy_piv::slot::is_valid_piv_slot(slot_id) {
        eprintln!("piggy tool {op}: {raw:?} is not a PIV slot that holds a certificate");
        return Err(2);
    }
    Ok(slot_id)
}

/// Select the PIV token to operate on. With `-g`, the token whose GUID
/// starts with that hex prefix (case-insensitive); without it, the sole
/// present token, mirroring `pivy-tool`'s "required if more than one
/// token is present" rule.
fn select_token(guid_prefix: Option<&str>) -> Result<PivToken, String> {
    let ctx = PivContext::new().map_err(|e| format!("PC/SC: {e}"))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| format!("enumerate tokens: {e}"))?;
    if tokens.is_empty() {
        return Err("no PIV tokens present".into());
    }
    match guid_prefix {
        Some(prefix) => {
            // Validate the prefix is hex so a typo is a clear error, not a
            // silent no-match (Guid::to_hex is uppercase).
            let prefix = prefix.to_ascii_uppercase();
            if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("-g {prefix:?}: not a hex GUID prefix"));
            }
            let mut matches: Vec<PivToken> = tokens
                .into_iter()
                .filter(|t| t.guid().to_hex().starts_with(&prefix))
                .collect();
            match matches.len() {
                0 => Err(format!("no PIV token matches GUID prefix {prefix}")),
                1 => Ok(matches.remove(0)),
                n => Err(format!("{n} PIV tokens match GUID prefix {prefix}")),
            }
        }
        None => {
            let mut tokens = tokens;
            if tokens.len() > 1 {
                return Err("more than one PIV token present; select one with -g <guid>".into());
            }
            Ok(tokens.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ListMode, current_admin_key, generated_key_openssh_line, is_admin_key_arg, is_key_slot,
        is_supported_cert_slot, parse, read_new_admin_key, store_ref,
    };

    // -------- piggy#396: the management key off argv --------

    /// A store holding one sealed key, or none.
    struct FakeStore(Option<(&'static str, &'static str)>);

    impl crate::card::seal::ManagementKeySealer for FakeStore {
        fn prepare(&self, _: &str) -> Result<Box<dyn crate::card::seal::KeyEscrow>, String> {
            Err("not a sealing store".into())
        }
        fn recover(&self, pass_name: &str) -> Result<zeroize::Zeroizing<String>, String> {
            match self.0 {
                Some((name, hex)) if name == pass_name => {
                    Ok(zeroize::Zeroizing::new(format!("{hex}\n")))
                }
                _ => Err(format!("{pass_name} is not in the password store")),
            }
        }
    }

    const GUID: &str = "0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn store_ref_forms() {
        assert_eq!(store_ref("@store"), Some(None));
        assert_eq!(
            store_ref("@store:piv/x/management-key"),
            Some(Some("piv/x/management-key"))
        );
        assert_eq!(store_ref("@store:"), None);
        assert_eq!(store_ref("@file"), None);
        assert_eq!(store_ref("default"), None);
        assert!(is_admin_key_arg("@store"));
        assert!(is_admin_key_arg("@store:a/b"));
        assert!(!is_admin_key_arg("@file"));
    }

    #[test]
    fn parse_accepts_the_store_forms_and_auth_test() {
        assert!(parse(&argv(&["-K", "@store", "auth-test"])).is_some());
        assert!(parse(&argv(&["auth-test"])).is_some());
        assert!(parse(&argv(&["-g", GUID, "-K", "default", "auth-test"])).is_some());
        assert!(parse(&argv(&["auth-test", "extra"])).is_none());
        assert!(
            parse(&argv(&[
                "-K",
                "@store:piv/x/management-key",
                "write-cert",
                "82"
            ]))
            .is_some()
        );
        assert!(parse(&argv(&["-K", "@store", "set-admin", "-"])).is_some());
        assert!(parse(&argv(&["-K", "default", "set-admin", "-"])).is_some());
        // The NEW key is never a store reference, and `@file` stays out.
        assert!(parse(&argv(&["set-admin", "@store"])).is_none());
        assert!(parse(&argv(&["-K", "@file", "auth-test"])).is_none());
        assert!(
            parse(&argv(&["-K", "@store", "pubkey", "9a"])).is_some(),
            "ignored by a read, as -K always was"
        );
    }

    #[test]
    fn current_key_from_the_store_defaults_to_the_selected_cards_entry() {
        let store = FakeStore(Some((
            "piv/0123456789ABCDEF0123456789ABCDEF/management-key",
            HEX24,
        )));
        let inv = parse(&argv(&["-K", "@store", "auth-test"])).unwrap();
        let key = current_admin_key(&inv, &store, GUID).unwrap();
        assert_eq!(hex::encode(&*key), HEX24);

        let inv = parse(&argv(&[
            "-K",
            "@store:piv/other/management-key",
            "auth-test",
        ]))
        .unwrap();
        let (code, msg) = current_admin_key(&inv, &store, GUID).unwrap_err();
        assert_eq!(code, 1);
        assert!(msg.contains("piv/other/management-key"), "{msg}");

        let inv = parse(&argv(&["-K", "@store", "auth-test"])).unwrap();
        let (code, msg) = current_admin_key(&inv, &FakeStore(None), GUID).unwrap_err();
        assert_eq!(code, 1);
        assert!(
            msg.contains("no sealed management key for this card")
                && msg.contains("not in the password store"),
            "{msg}"
        );

        // Literal forms do not touch the store.
        let inv = parse(&argv(&["-K", "default", "auth-test"])).unwrap();
        let key = current_admin_key(&inv, &FakeStore(None), GUID).unwrap();
        assert_eq!(key.len(), 24);
        let inv = parse(&argv(&["auth-test"])).unwrap();
        assert_eq!(
            current_admin_key(&inv, &FakeStore(None), GUID)
                .unwrap()
                .len(),
            24
        );
    }

    /// FDR 0006 owner's condition (2026-11-19): `@store` against a card with
    /// no sealed entry fails plainly and NEVER falls back to the factory key.
    /// A holder-minted virtual card has a random GUID and no entry.
    #[test]
    fn store_form_never_falls_back_to_the_factory_key() {
        use super::resolve_admin_key;
        let factory = resolve_admin_key("default").unwrap();
        for guid in [
            "0123456789ABCDEF0123456789ABCDEF",
            "4C454C35AEB9E7D2F3356DE7580556EA",
        ] {
            let inv = parse(&argv(&["-K", "@store", "auth-test"])).unwrap();
            match current_admin_key(&inv, &FakeStore(None), guid) {
                Err((1, msg)) => assert!(msg.contains("no sealed management key"), "{msg}"),
                Err((code, msg)) => panic!("exit {code}: {msg}"),
                Ok(key) => panic!(
                    "resolved a key with no entry{}",
                    if *key == factory {
                        ": the factory key"
                    } else {
                        ""
                    }
                ),
            }
        }
    }

    /// `@` is a reserved prefix: only `@store` is a key source today, so the
    /// on-card PIN-protected key (piggy#198) can become `-K @pin` later without
    /// a flag change; anything else under `@` is a usage error, not hex.
    #[test]
    fn at_prefix_is_reserved_for_key_sources() {
        for form in ["@pin", "@file", "@store:", "@", "@env"] {
            assert!(!is_admin_key_arg(form), "{form} must not parse as a key");
            assert!(parse(&argv(&["-K", form, "auth-test"])).is_none(), "{form}");
        }
    }

    // -------- piggy#397: attest-verify over generated chains --------

    mod attest_verify {
        use super::super::{AttestInputs, AttestPoint, PointStatus, parse, verify_attestation};
        use super::argv;
        use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::{PKey, Private};
        use openssl::x509::{X509, X509Builder, X509Extension, X509NameBuilder};
        use piggy_piv::{PinPolicy, TouchPolicy};

        fn key() -> PKey<Private> {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
        }

        fn point(k: &PKey<Private>) -> Vec<u8> {
            let ec = k.ec_key().unwrap();
            let mut ctx = openssl::bn::BigNumContext::new().unwrap();
            ec.public_key()
                .to_bytes(
                    ec.group(),
                    openssl::ec::PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )
                .unwrap()
        }

        fn name(cn: &str) -> openssl::x509::X509Name {
            let mut b = X509NameBuilder::new().unwrap();
            b.append_entry_by_text("CN", cn).unwrap();
            b.build()
        }

        /// A YubicoPIV-shaped extension: an arbitrary OID with raw DER contents.
        fn yk_ext(oid: &str, contents: &[u8]) -> X509Extension {
            X509Extension::new_from_der(
                &Asn1Object::from_str(oid).unwrap(),
                false,
                &Asn1OctetString::new_from_bytes(contents).unwrap(),
            )
            .unwrap()
        }

        /// A certificate for `subject` issued by `issuer` under `issuer_name`,
        /// with the given extensions.
        fn cert(
            cn: &str,
            subject: &PKey<Private>,
            issuer: &PKey<Private>,
            issuer_cn: &str,
            exts: Vec<X509Extension>,
        ) -> X509 {
            let mut b = X509Builder::new().unwrap();
            b.set_version(2).unwrap();
            b.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
                .unwrap();
            b.set_subject_name(&name(cn)).unwrap();
            b.set_issuer_name(&name(issuer_cn)).unwrap();
            b.set_pubkey(subject).unwrap();
            b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
                .unwrap();
            for e in exts {
                b.append_extension(e).unwrap();
            }
            b.sign(issuer, MessageDigest::sha256()).unwrap();
            b.build()
        }

        /// A full chain: root (self-signed), F9 under the root, the slot's
        /// attestation under F9 with policy, firmware 5.2.7 and serial.
        struct Chain {
            root: X509,
            f9: X509,
            attestation: X509,
            slot: PKey<Private>,
            f9_key: PKey<Private>,
        }

        const ROOT_CN: &str = "Yubico PIV Root CA Serial 263751";
        const F9_CN: &str = "Yubico PIV Attestation";

        fn attestation_exts(pin: u8, touch: u8) -> Vec<X509Extension> {
            vec![
                yk_ext("1.3.6.1.4.1.41482.3.8", &[pin, touch]),
                yk_ext("1.3.6.1.4.1.41482.3.3", &[5, 2, 7]),
                // INTEGER 0x00F2C8D6 = 15911126 (a leading zero for the high bit)
                yk_ext(
                    "1.3.6.1.4.1.41482.3.7",
                    &[0x02, 0x04, 0x00, 0xF2, 0xC8, 0xD6],
                ),
            ]
        }

        fn chain(pin: u8, touch: u8) -> Chain {
            let (root_key, f9_key, slot) = (key(), key(), key());
            let root = cert(ROOT_CN, &root_key, &root_key, ROOT_CN, vec![]);
            let f9 = cert(F9_CN, &f9_key, &root_key, ROOT_CN, vec![]);
            let attestation = cert(
                "YubiKey PIV Attestation 82",
                &slot,
                &f9_key,
                F9_CN,
                attestation_exts(pin, touch),
            );
            Chain {
                root,
                f9,
                attestation,
                slot,
                f9_key,
            }
        }

        fn status<'a>(points: &'a [AttestPoint], prefix: &str) -> &'a PointStatus {
            &points
                .iter()
                .find(|p| p.name.starts_with(prefix))
                .unwrap_or_else(|| panic!("no point {prefix}"))
                .status
        }

        fn diag<'a>(points: &'a [AttestPoint], prefix: &str, key: &str) -> Option<&'a str> {
            points
                .iter()
                .find(|p| p.name.starts_with(prefix))
                .and_then(|p| p.diags.iter().find(|(k, _)| k == key))
                .map(|(_, v)| v.as_str())
        }

        // YubicoPIV policy bytes: PIN 1 never, 2 once, 3 always; touch 1
        // never, 2 always, 3 cached (piggy-piv's policy table).
        const PIN_ALWAYS: u8 = 0x03;
        const PIN_ONCE: u8 = 0x02;
        const TOUCH_ALWAYS: u8 = 0x02;

        #[test]
        fn a_good_chain_passes_every_point() {
            let c = chain(PIN_ALWAYS, TOUCH_ALWAYS);
            let (att, f9, root) = (
                c.attestation.to_der().unwrap(),
                c.f9.to_der().unwrap(),
                c.root.to_pem().unwrap(),
            );
            let slot_point = point(&c.slot);
            let points = verify_attestation(&AttestInputs {
                attestation_der: &att,
                f9_der: &f9,
                slot_point: Some(&slot_point),
                root_pem: Some(&root),
                saved_pem: Some(&c.attestation.to_pem().unwrap()),
                expect_pin: Some(PinPolicy::Always),
                expect_touch: Some(TouchPolicy::Always),
            });
            assert_eq!(points.len(), 6);
            for p in &points {
                assert!(
                    matches!(p.status, PointStatus::Pass),
                    "{} did not pass: {:?}",
                    p.name,
                    p.diags
                );
            }
            assert!(
                points[3].name.contains("PIN always, touch always"),
                "{}",
                points[3].name
            );
            assert_eq!(
                diag(&points, "attestation names", "firmware"),
                Some("5.2.7")
            );
            assert_eq!(
                diag(&points, "attestation names", "serial"),
                Some("15911126")
            );
            assert!(
                diag(&points, "F9 certificate", "root_sha256")
                    .unwrap()
                    .len()
                    == 95
            );
        }

        /// The embedded root is exactly the certificate whose fingerprint FDR
        /// 0007 recorded and the coordinator's fetch confirmed; the DER hash
        /// is computed here from the PEM bytes, not copied.
        #[test]
        fn embedded_yubico_root_matches_its_pin() {
            use super::super::{
                YUBICO_PIV_ROOT_CA_PEM, YUBICO_PIV_ROOT_CA_SHA256, embedded_yubico_root,
            };
            let root = X509::from_pem(YUBICO_PIV_ROOT_CA_PEM.as_bytes()).unwrap();
            let digest = root.digest(MessageDigest::sha256()).unwrap();
            let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
            assert_eq!(hex.join(":"), YUBICO_PIV_ROOT_CA_SHA256);
            let root = embedded_yubico_root().unwrap();
            assert!(
                format!("{:?}", root.subject_name()).contains("Yubico PIV Root CA Serial 263751"),
                "{:?}",
                root.subject_name()
            );
            assert_eq!(
                root.issuer_name().to_der().unwrap(),
                root.subject_name().to_der().unwrap(),
                "self-signed"
            );
        }

        /// With no --root the embedded Yubico root is the anchor: a generated
        /// F9 does not chain to it, and the diagnostics name the source.
        #[test]
        fn no_root_means_the_embedded_yubico_root() {
            let c = chain(0x03, 0x03);
            let (att, f9) = (c.attestation.to_der().unwrap(), c.f9.to_der().unwrap());
            let slot_point = point(&c.slot);
            let points = verify_attestation(&AttestInputs {
                attestation_der: &att,
                f9_der: &f9,
                slot_point: Some(&slot_point),
                root_pem: None,
                saved_pem: None,
                expect_pin: None,
                expect_touch: None,
            });
            assert_eq!(points.len(), 5, "no --saved, no saved point");
            assert!(matches!(
                status(&points, "F9 certificate"),
                PointStatus::Fail
            ));
            assert!(
                diag(&points, "F9 certificate", "root_source")
                    .unwrap()
                    .starts_with("embedded Yubico")
            );
            assert!(
                diag(&points, "F9 certificate", "root_subject")
                    .unwrap()
                    .contains("Serial 263751")
            );
            assert!(matches!(
                status(&points, "attestation signed"),
                PointStatus::Pass
            ));
            assert!(matches!(status(&points, "attested key"), PointStatus::Pass));
        }

        #[test]
        fn each_wrong_input_fails_its_own_point() {
            let c = chain(0x03, 0x03);
            let (att, f9, root) = (
                c.attestation.to_der().unwrap(),
                c.f9.to_der().unwrap(),
                c.root.to_pem().unwrap(),
            );
            let slot_point = point(&c.slot);
            let good = |att: &[u8], f9: &[u8], root: &[u8], sp: &[u8], saved: Option<&[u8]>| {
                verify_attestation(&AttestInputs {
                    attestation_der: att,
                    f9_der: f9,
                    slot_point: Some(sp),
                    root_pem: Some(root),
                    saved_pem: saved,
                    expect_pin: None,
                    expect_touch: None,
                })
            };

            // A stranger's F9: the attestation is not signed by it.
            let stranger = key();
            let other_f9 = cert(F9_CN, &stranger, &key(), ROOT_CN, vec![])
                .to_der()
                .unwrap();
            let points = good(&att, &other_f9, &root, &slot_point, None);
            assert!(matches!(
                status(&points, "attestation signed"),
                PointStatus::Fail
            ));

            // A different root: F9 does not chain to it.
            let other_root = {
                let k = key();
                cert(ROOT_CN, &k, &k, ROOT_CN, vec![]).to_pem().unwrap()
            };
            let points = good(&att, &f9, &other_root, &slot_point, None);
            assert!(matches!(
                status(&points, "F9 certificate"),
                PointStatus::Fail
            ));
            assert!(
                diag(&points, "F9 certificate", "error")
                    .unwrap()
                    .contains("does not verify")
            );

            // A root whose key signed F9 but whose name is not F9's issuer.
            let root_key_reused = {
                // Re-sign F9's chain with a root of another name: build a
                // fresh chain whose root CN differs from F9's issuer field.
                let (rk, fk, sk) = (key(), key(), key());
                let root = cert("Other Root", &rk, &rk, "Other Root", vec![])
                    .to_pem()
                    .unwrap();
                let f9 = cert(F9_CN, &fk, &rk, ROOT_CN, vec![]).to_der().unwrap();
                let att = cert("att", &sk, &fk, F9_CN, attestation_exts(3, 3))
                    .to_der()
                    .unwrap();
                (root, f9, att, point(&sk))
            };
            let points = good(
                &root_key_reused.2,
                &root_key_reused.1,
                &root_key_reused.0,
                &root_key_reused.3,
                None,
            );
            assert!(matches!(
                status(&points, "F9 certificate"),
                PointStatus::Fail
            ));
            assert!(
                diag(&points, "F9 certificate", "error")
                    .unwrap()
                    .contains("issuer")
            );

            // A slot key other than the attested one.
            let points = good(&att, &f9, &root, &point(&key()), None);
            assert!(matches!(status(&points, "attested key"), PointStatus::Fail));

            // A saved attestation for another key.
            let other_att = cert("att", &key(), &c.f9_key, F9_CN, attestation_exts(3, 3))
                .to_pem()
                .unwrap();
            let points = good(&att, &f9, &root, &slot_point, Some(&other_att));
            assert!(matches!(
                status(&points, "saved attestation"),
                PointStatus::Fail
            ));
            assert_eq!(diag(&points, "saved attestation", "differs"), Some("key"));

            // A saved attestation with another policy for the same key.
            let other_policy = cert("att", &c.slot, &c.f9_key, F9_CN, attestation_exts(1, 1))
                .to_pem()
                .unwrap();
            let points = good(&att, &f9, &root, &slot_point, Some(&other_policy));
            assert_eq!(
                diag(&points, "saved attestation", "differs"),
                Some("policy")
            );
        }

        #[test]
        fn expected_policy_is_asserted_and_absent_extensions_are_named() {
            let c = chain(PIN_ONCE, TOUCH_ALWAYS); // PIN once, touch always
            let (att, f9) = (c.attestation.to_der().unwrap(), c.f9.to_der().unwrap());
            let slot_point = point(&c.slot);
            let points = verify_attestation(&AttestInputs {
                attestation_der: &att,
                f9_der: &f9,
                slot_point: Some(&slot_point),
                root_pem: None,
                saved_pem: None,
                expect_pin: Some(PinPolicy::Always),
                expect_touch: Some(TouchPolicy::Always),
            });
            assert!(matches!(
                status(&points, "attested policy"),
                PointStatus::Fail
            ));
            assert_eq!(
                diag(&points, "attested policy", "policy"),
                Some("PIN once, touch always")
            );
            assert_eq!(
                diag(&points, "attested policy", "expected"),
                Some("PIN always, touch always")
            );

            // No YubicoPIV extensions at all: the policy point fails naming
            // the OID, the firmware/serial point skips.
            let bare = cert("att", &c.slot, &c.f9_key, F9_CN, vec![])
                .to_der()
                .unwrap();
            let points = verify_attestation(&AttestInputs {
                attestation_der: &bare,
                f9_der: &f9,
                slot_point: Some(&slot_point),
                root_pem: None,
                saved_pem: None,
                expect_pin: None,
                expect_touch: None,
            });
            assert!(matches!(
                status(&points, "attested policy"),
                PointStatus::Fail
            ));
            assert!(
                diag(&points, "attested policy", "error")
                    .unwrap()
                    .contains("41482.3.8"),
                "{:?}",
                diag(&points, "attested policy", "error")
            );
            assert!(matches!(
                status(&points, "attestation names"),
                PointStatus::Skip(_)
            ));
        }

        #[test]
        fn parse_takes_the_verify_options_only_with_attest_verify() {
            assert!(parse(&argv(&["attest-verify", "82"])).is_some());
            assert!(
                parse(&argv(&[
                    "--root",
                    "r.pem",
                    "--saved",
                    "s.pem",
                    "attest-verify",
                    "9c"
                ]))
                .is_some()
            );
            assert!(
                parse(&argv(&[
                    "--expect-pin",
                    "always",
                    "--expect-touch",
                    "always",
                    "attest-verify",
                    "9a"
                ]))
                .is_some()
            );
            assert!(parse(&argv(&["-j", "attest-verify", "9d"])).is_some());
            assert!(
                parse(&argv(&["attest-verify", "f9"])).is_none(),
                "F9 is not a key slot"
            );
            assert!(parse(&argv(&["attest-verify"])).is_none());
            assert!(parse(&argv(&["attest-verify", "82", "extra"])).is_none());
            assert!(parse(&argv(&["--expect-pin", "sometimes", "attest-verify", "82"])).is_none());
            assert!(
                parse(&argv(&["--root", "r.pem", "attest", "82"])).is_none(),
                "only attest-verify takes --root"
            );
        }
    }

    #[test]
    fn a_store_entry_that_is_not_a_key_is_an_error_naming_the_entry() {
        let store = FakeStore(Some(("piv/x/management-key", "hunter2-not-a-key")));
        let inv = parse(&argv(&["-K", "@store:piv/x/management-key", "auth-test"])).unwrap();
        let (code, msg) = current_admin_key(&inv, &store, GUID).unwrap_err();
        assert_eq!(code, 1);
        assert!(
            msg.contains("piv/x/management-key") && msg.contains("48-hex-digit key"),
            "{msg}"
        );
        assert!(
            !msg.contains("hunter2"),
            "the entry's content is never echoed: {msg}"
        );
    }

    #[test]
    fn new_key_from_stdin_is_one_hex_line() {
        let key = read_new_admin_key(&mut format!("{HEX24}\n").as_bytes()).unwrap();
        assert_eq!(hex::encode(&*key), HEX24);
        // Trailing whitespace is tolerated; a second line is ignored.
        let key = read_new_admin_key(&mut format!("{HEX24}  \r\nsecond\n").as_bytes()).unwrap();
        assert_eq!(hex::encode(&*key), HEX24);
        let err = read_new_admin_key(&mut "".as_bytes()).unwrap_err();
        assert!(err.contains("no key line"), "{err}");
        let err = read_new_admin_key(&mut "0102\n".as_bytes()).unwrap_err();
        assert!(
            err.contains("48 hex digits") && err.contains("4 characters"),
            "{err}"
        );
        assert!(
            !err.contains("0102"),
            "the line's content is not echoed: {err}"
        );
        let err = read_new_admin_key(
            &mut "zz02030405060708010203040506070801020304050607ff\n".as_bytes(),
        )
        .unwrap_err();
        assert!(err.contains("48 hex digits"), "{err}");
    }

    /// The P-256 base point, uncompressed: a valid public key to render.
    const P256_G: &str = "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

    #[test]
    fn generated_key_line_is_openssh_with_the_slot_comment() {
        let point = hex::decode(P256_G).unwrap();
        let line = generated_key_openssh_line(&point, 0x9C, "5DA19C98AAAA").unwrap();
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 3, "{line}");
        assert_eq!(fields[0], "ecdsa-sha2-nistp256");
        assert!(fields[1].starts_with("AAAA"), "{line}");
        assert_eq!(fields[2], "PIV_slot_9C@5DA19C98AAAA");
        let err = generated_key_openssh_line(&[0x04, 1, 2], 0x9A, "G").unwrap_err();
        assert!(err.starts_with("parse generated public key"), "{err}");
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    const HEX24: &str = "0102030405060708010203040506070801020304050607ff";

    #[test]
    fn parse_claims_only_the_ported_ops() {
        assert!(parse(&argv(&["pubkey", "9d"])).is_some());
        assert!(parse(&argv(&["cert", "9a"])).is_some());
        assert!(parse(&argv(&["attest", "9d"])).is_some());
        assert!(parse(&argv(&["sign", "9c"])).is_some());
        assert!(parse(&argv(&["ecdh", "9d"])).is_some());
        assert!(parse(&argv(&["change-pin"])).is_some());
        assert!(parse(&argv(&["change-puk"])).is_some());
        assert!(parse(&argv(&["reset-pin"])).is_some());
        assert!(parse(&argv(&["set-admin", "default"])).is_some());
        assert!(parse(&argv(&["set-admin", HEX24])).is_some());
        assert!(parse(&argv(&["-K", "default", "set-admin", HEX24])).is_some());
        assert!(parse(&argv(&["delete-cert", "9d"])).is_some());
        assert!(parse(&argv(&["-K", "default", "delete-cert", "9a"])).is_some());
        assert!(parse(&argv(&["update-keyhist"])).is_some());
        assert!(parse(&argv(&["-K", "default", "update-keyhist"])).is_some());
        assert!(parse(&argv(&["write-cert", "9d"])).is_some());
        assert!(parse(&argv(&["-K", "default", "write-cert", "9a"])).is_some());
        assert!(parse(&argv(&["-a", "eccp256", "generate", "9a"])).is_some());
        assert!(parse(&argv(&["-a", "eccp384", "generate", "9d"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "-a", "eccp256", "generate", "9c"])).is_some());
        assert!(parse(&argv(&["import", "9c"])).is_some());
        assert!(parse(&argv(&["-K", "default", "-P", "123456", "import", "9a"])).is_some());
        assert!(parse(&argv(&["pinfo"])).is_some());
        assert!(parse(&argv(&["-g", "ABCD", "pinfo"])).is_some());
        // `list` in all three modes; the mode flag precedes it, and `-j` wins
        // over `-p` as in C.
        let mode = |a: &[&str]| parse(&argv(a)).map(|inv| inv.list_mode);
        assert_eq!(mode(&["list"]), Some(ListMode::Human));
        assert_eq!(mode(&["-p", "list"]), Some(ListMode::Parseable));
        assert_eq!(mode(&["-j", "list"]), Some(ListMode::Json));
        assert_eq!(mode(&["--json", "list"]), Some(ListMode::Json));
        assert_eq!(mode(&["-p", "-j", "list"]), Some(ListMode::Json));
        assert!(parse(&argv(&["version"])).is_some());
        assert!(parse(&argv(&["-g", "ABCD", "-j", "list"])).is_some());
        // `factory-reset` is claimed with or without the confirmation bypass.
        assert!(parse(&argv(&["factory-reset"])).is_some());
        assert!(parse(&argv(&["--yes", "factory-reset"])).is_some());
        assert!(parse(&argv(&["--force", "factory-reset"])).is_some());
        assert!(parse(&argv(&["-g", "ABCD", "--yes", "factory-reset"])).is_some());
        // `req-cert` claims the EC cert slots; the PIN may come via askpass, and
        // `-n` sets the subject CN.
        assert!(parse(&argv(&["req-cert", "9a"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "req-cert", "9c"])).is_some());
        assert!(parse(&argv(&["-n", "example", "-P", "123456", "req-cert", "9a"])).is_some());
        assert!(parse(&argv(&["-P", "12345678", "-P", "654321", "reset-pin"])).is_some());
        assert!(parse(&argv(&["-g", "ABCD", "pubkey", "9d"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "sign", "9a"])).is_some());
        assert!(parse(&argv(&["-P", "123456", "-P", "654321", "change-pin"])).is_some());
        // Still-unported ops are rejected (run() maps None to a usage error).
        assert!(parse(&argv(&["-j", "list", "9a"])).is_none()); // list takes no positionals
        assert!(parse(&argv(&["init"])).is_none());
        assert!(parse(&argv(&["version", "x"])).is_none()); // version takes no positionals
        // set-admin key forms this port does not model → C.
        assert!(parse(&argv(&["set-admin", "random"])).is_none());
        assert!(parse(&argv(&["set-admin", "@keyfile"])).is_none());
        assert!(parse(&argv(&["-K", "@keyfile", "set-admin", "default"])).is_none());
        assert!(parse(&argv(&["set-admin"])).is_none()); // missing new key
        assert!(parse(&argv(&["set-admin", "default", "extra"])).is_none());
        // The write ops claim the key slots, retired 82..95 included (the
        // pilot CA root lives in 82); F9 and non-slots are refused.
        assert!(parse(&argv(&["delete-cert", "82"])).is_some());
        assert!(parse(&argv(&["delete-cert", "95"])).is_some());
        assert!(parse(&argv(&["write-cert", "82"])).is_some());
        assert!(parse(&argv(&["-a", "eccp256", "generate", "82"])).is_some());
        assert!(
            parse(&argv(&[
                "-K", "default", "-a", "eccp256", "-i", "always", "-t", "always", "generate", "82"
            ]))
            .is_some()
        );
        assert!(parse(&argv(&["import", "95"])).is_some());
        assert!(parse(&argv(&["req-cert", "82"])).is_some());
        assert!(parse(&argv(&["delete-cert", "96"])).is_none()); // past the retired range
        assert!(parse(&argv(&["delete-cert", "f9"])).is_none()); // attestation slot
        assert!(parse(&argv(&["delete-cert"])).is_none()); // missing slot
        assert!(parse(&argv(&["-K", "@keyfile", "delete-cert", "9d"])).is_none());
        // update-keyhist takes no positionals.
        assert!(parse(&argv(&["update-keyhist", "9d"])).is_none());
        assert!(parse(&argv(&["-K", "@keyfile", "update-keyhist"])).is_none());
        assert!(parse(&argv(&["write-cert", "f9"])).is_none()); // attestation slot
        assert!(parse(&argv(&["write-cert"])).is_none()); // missing slot
        assert!(parse(&argv(&["-K", "@keyfile", "write-cert", "9d"])).is_none());
        // generate requires -a and an EC algorithm on a cert slot.
        assert!(parse(&argv(&["generate", "9a"])).is_none()); // no -a
        assert!(parse(&argv(&["-a", "rsa2048", "generate", "9a"])).is_none()); // RSA -> C
        assert!(parse(&argv(&["-a", "ed25519", "generate", "9a"])).is_none()); // Ed25519 -> C
        assert!(parse(&argv(&["-a", "eccp256", "generate", "f9"])).is_none()); // attestation slot
        assert!(parse(&argv(&["-a", "eccp256", "generate"])).is_none()); // no slot
        // generate's policy options take pivy-tool's names only.
        let inv = parse(&argv(&[
            "-a", "eccp256", "-i", "always", "-t", "cached", "generate", "9c",
        ]))
        .expect("-i/-t are modeled");
        assert_eq!(inv.pin_policy, super::PinPolicy::Always);
        assert_eq!(inv.touch_policy, super::TouchPolicy::Cached);
        let inv = parse(&argv(&["-a", "eccp256", "generate", "9c"])).unwrap();
        assert_eq!(inv.pin_policy, super::PinPolicy::Default);
        assert_eq!(inv.touch_policy, super::TouchPolicy::Default);
        assert!(
            parse(&argv(&[
                "-a",
                "eccp256",
                "-i",
                "sometimes",
                "generate",
                "9c"
            ]))
            .is_none()
        );
        assert!(parse(&argv(&["-a", "eccp256", "-t", "once", "generate", "9c"])).is_none());
        // ...and only generate takes them: an import must not look as if it
        // honoured a policy it ignores.
        assert!(parse(&argv(&["-i", "always", "import", "9c"])).is_none());
        assert!(parse(&argv(&["-t", "default", "pubkey", "9c"])).is_none());
        // import claims only key slots (key type is checked in cmd_import).
        assert!(parse(&argv(&["import", "f9"])).is_none()); // attestation slot
        assert!(parse(&argv(&["import"])).is_none()); // no slot
        // pinfo takes no positionals.
        assert!(parse(&argv(&["pinfo", "9d"])).is_none());
        // factory-reset takes no positionals.
        assert!(parse(&argv(&["factory-reset", "9a"])).is_none());
        // req-cert claims only the key slots.
        assert!(parse(&argv(&["req-cert", "f9"])).is_none()); // attestation slot
        assert!(parse(&argv(&["req-cert"])).is_none()); // no slot
        // An option we don't model → C handles the whole invocation.
        assert!(parse(&argv(&["-d", "pubkey", "9d"])).is_none());
        // No op at all.
        assert!(parse(&argv(&[])).is_none());
        // `-g` with no value.
        assert!(parse(&argv(&["-g"])).is_none());
    }

    #[test]
    fn parse_extracts_admin_key_for_set_admin() {
        let inv = parse(&argv(&["-K", "default", "set-admin", HEX24])).unwrap();
        assert_eq!(inv.admin_key.as_deref(), Some("default"));
        assert_eq!(inv.op, "set-admin");
        assert_eq!(inv.positionals, vec![HEX24.to_string()]);
    }

    #[test]
    fn parse_extracts_force_for_factory_reset() {
        assert!(parse(&argv(&["--yes", "factory-reset"])).unwrap().force);
        assert!(parse(&argv(&["--force", "factory-reset"])).unwrap().force);
        // Without the flag, factory-reset still parses (the tty prompt gates it).
        assert!(!parse(&argv(&["factory-reset"])).unwrap().force);
    }

    #[test]
    fn parse_extracts_cn_for_req_cert() {
        let inv = parse(&argv(&["-n", "my cn", "req-cert", "9a"])).unwrap();
        assert_eq!(inv.cn.as_deref(), Some("my cn"));
        assert_eq!(inv.op, "req-cert");
        assert_eq!(inv.positionals, vec!["9a".to_string()]);
        // Absent -n leaves cn None (cmd_req_cert then defaults it).
        assert_eq!(parse(&argv(&["req-cert", "9a"])).unwrap().cn, None);
    }

    #[test]
    fn is_admin_key_arg_accepts_default_and_hex_only() {
        assert!(is_admin_key_arg("default"));
        assert!(is_admin_key_arg(HEX24));
        assert!(!is_admin_key_arg("random"));
        assert!(!is_admin_key_arg("@file"));
        assert!(!is_admin_key_arg("0102030")); // odd length
        assert!(!is_admin_key_arg("")); // empty
    }

    #[test]
    fn is_supported_cert_slot_covers_named_and_retired_slots() {
        for s in [
            "9a", "9A", "9c", "9d", "9e", "0x9d", "82", "8a", "95", "0x82",
        ] {
            assert!(is_supported_cert_slot(s), "{s}");
        }
        // ecdh's runtime guard is the same set.
        for id in [0x9Au8, 0x9C, 0x9D, 0x9E, 0x82, 0x95] {
            assert!(is_key_slot(id), "{id:02X}");
        }
        for id in [0x81u8, 0x96, 0xF9, 0x9B] {
            assert!(!is_key_slot(id), "{id:02X}");
        }
        for s in ["81", "96", "f9", "9b", "zz", ""] {
            assert!(!is_supported_cert_slot(s), "{s}");
        }
    }

    #[test]
    fn parse_extracts_guid_pin_and_positionals() {
        let inv = parse(&argv(&["-g", "deadbeef", "-P", "123456", "sign", "9c"])).unwrap();
        assert_eq!(inv.guid.as_deref(), Some("deadbeef"));
        assert_eq!(inv.pins, vec!["123456".to_string()]);
        assert_eq!(inv.op, "sign");
        assert_eq!(inv.positionals, vec!["9c".to_string()]);
    }

    #[test]
    fn parse_collects_repeated_pins_for_change() {
        // pivy-tool consumes the first -P as the current secret, the
        // second as the new one.
        let inv = parse(&argv(&["-P", "123456", "-P", "654321", "change-pin"])).unwrap();
        assert_eq!(inv.pins, vec!["123456".to_string(), "654321".to_string()]);
        assert_eq!(inv.op, "change-pin");
    }
}
