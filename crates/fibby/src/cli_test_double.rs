//! The fibby CLI's test-double surface (FDR 0006, piggy#382): the seed
//! flags, `--auto-touch`, the hardware backend's `--reader`, and their help
//! text. Compiled only with the `test-double` feature, so none of these
//! flag names exists in the holder binary; `checks.lint-fibby-holder`
//! greps the holder for every name in [`TEST_ONLY_FLAGS`].

use fibby::virtual_card::VirtualCard;

use crate::Args;

/// Every flag only the test double accepts. `fibby --test-flags` prints
/// this list; the holder lint checks that the holder binary contains none
/// of these strings and refuses each one. A unit test checks that every
/// entry parses here, so the list cannot name a flag that does not exist.
pub const TEST_ONLY_FLAGS: &[&str] = &[
    "--test-flags",
    "--auto-touch",
    "--reader",
    "--seed-rfc6979-slot-9a-cert",
    "--seed-rfc5903-slot-9d-cert",
    "--seed-slot-9c-cert",
    "--seed-rfc6979-slot-9e-cert",
    "--seed-chuid",
    "--seed-chuid-guid",
    "--seed-pinfo",
    "--seed-pin-puk-blocked",
    "--seed-pin",
    "--seed-pin-retries",
    "--seed-slot-9a-priv",
    "--seed-slot-9c-priv",
    "--seed-slot-9d-priv",
    "--seed-slot-9e-priv",
    "--seed-slot-9a-ed25519",
    "--seed-slot-9c-ed25519",
    "--seed-slot-9d-ed25519",
    "--seed-slot-9e-ed25519",
    "--generate-slot-9a-priv",
    "--generate-slot-9c-priv",
    "--generate-slot-9d-priv",
    "--seed-mgmt-key",
    "--seed-mgmt-key-witness",
];

pub const HELP: &str = "\n\
TEST-DOUBLE FLAGS (absent from the holder build)\n\
\n\
USAGE: fibby [--backend hardware --reader SUBSTR] [--auto-touch]\n\
             [--card NAME [seed flags…]]…\n\
             [--seed-rfc6979-slot-9a-cert]\n\
             [--seed-rfc5903-slot-9d-cert] [--seed-slot-9c-cert]\n\
             [--seed-rfc6979-slot-9e-cert] [--seed-chuid]\n\
             [--seed-chuid-guid HEX32] [--seed-pinfo]\n\
             [--seed-pin ASCII] [--seed-pin-retries N] [--seed-pin-puk-blocked]\n\
             [--seed-slot-9a-priv HEX] [--seed-slot-9d-priv HEX]\n\
             [--seed-slot-9c-priv HEX] [--seed-slot-9e-priv HEX]\n\
             [--seed-slot-9a-ed25519 HEX] [--seed-slot-9c-ed25519 HEX]\n\
             [--seed-slot-9d-ed25519 HEX] [--seed-slot-9e-ed25519 HEX]\n\
             [--generate-slot-9a-priv HEX] [--generate-slot-9c-priv HEX]\n\
             [--generate-slot-9d-priv HEX]\n\
             [--seed-mgmt-key HEX] [--seed-mgmt-key-witness HEX]\n\
       fibby --test-flags\n\
\n\
--test-flags prints every test-only flag, one per line.\n\
\n\
--backend hardware proxies to the system pcscd/YubiKey (needs the\n\
`hardware-proxy` build feature); --reader SUBSTR selects its reader\n\
(default \"Yubico\").\n\
\n\
--auto-touch grants every touch-requiring operation at once, for tests\n\
that are not about touch (logs `TOUCH auto-granted <slot>`).\n\
\n\
--seed-rfc6979-slot-9a-cert installs the canonical fibby slot 9A\n\
test cert (X.509 self-signed over the RFC 6979 §A.2.5 P-256 keypair)\n\
at PIV tag 5F C1 05 AND the matching private key into slot 9A, so\n\
pivy-agent exposes one SSH identity that can both be enumerated and\n\
used to sign (RFC 6979 deterministic ECDSA). See piggy#135.\n\
\n\
--seed-rfc5903-slot-9d-cert is the slot-9D analogue: it installs a\n\
cert (over the RFC 5903 §8.1 P-256 keypair) at PIV tag 5F C1 0B AND\n\
the matching key into slot 9D, so pivy-agent exposes a key-management\n\
identity that pivy-box can ECDH against for decrypt. A distinct\n\
keypair from 9A's so the agent routes ECDH unambiguously to 9D.\n\
\n\
--seed-slot-9c-cert installs the fibby slot 9C (Digital Signature)\n\
test cert at PIV tag 5F C1 0A AND its matching key into slot 9C, so\n\
pivy-agent exposes a signature identity. Slot 9C is PIN-policy\n\
'always': each sign consumes the PIN verification (vs 9A's 'once').\n\
\n\
--seed-rfc6979-slot-9e-cert installs the RFC 6979 §A.2.5 cert and key\n\
into slot 9E (Card Authentication, PIN-never).\n\
\n\
--seed-slot-9a-priv / --seed-slot-9d-priv / --seed-slot-9c-priv /\n\
--seed-slot-9e-priv take a 32-byte (64 hex char) big-endian P-256\n\
scalar; --seed-mgmt-key takes a 24-byte 3DES key;\n\
--seed-mgmt-key-witness takes the 8-byte challenge witness. All accept\n\
an optional 0x prefix and the `--flag=HEX` form. A slot flag applied\n\
after a cert flag wins.\n\
\n\
--seed-slot-9a-ed25519 / -9c- / -9d- / -9e-ed25519 HEX install an\n\
Ed25519 key (the 32-byte RFC 8032 seed, 64 hex chars) into that slot, with\n\
a self-signed certificate over it (CN fibby-test-slot-<slot>-ed25519) and\n\
the canonical CHUID. Signing with it (GENERAL AUTHENTICATE alg E0) needs\n\
--model yk5.7, as Ed25519 needs firmware 5.7 on silicon. Applied after\n\
the P-256 slot flags.\n\
\n\
--seed-chuid installs only the canonical CHUID (no key or cert), so\n\
the card presents as initialized with empty slots — the starting\n\
point for an on-card GENERATE.\n\
\n\
--seed-pinfo installs a canonical Printed Information object.\n\
\n\
--generate-slot-9a-priv / --generate-slot-9c-priv / --generate-slot-9d-priv\n\
pin the 32-byte P-256 scalar that an on-card GENERATE ASYMMETRIC (INS\n\
0x47) will install into that slot, making keygen deterministic for\n\
tests/replay. Without it, GENERATE picks a fresh random key.\n\
\n\
--seed-pin ASCII sets a non-default application PIN (1-8 chars,\n\
0xFF-padded); --seed-pin-retries N (1-3) starts the PIN retry counter\n\
low; --seed-pin-puk-blocked starts both counters at 0.\n\
\n\
With --card groups, every seed flag AFTER a --card configures that\n\
card; seed flags before the first --card, the --reader flag, and\n\
--backend hardware don't mix with --card. Cards after the first that\n\
seed a CHUID get a distinct GUID by default (canonical GUID, last byte\n\
= card index); override it per card with --seed-chuid-guid HEX32\n\
(16 bytes, implies a CHUID).\n\
\n\
IMPORT ASYMMETRIC (INS 0xFE), `fibby ctl fault` and FIBBY_LOG=wire are\n\
also test-double only.";

/// One virtual card's seed configuration (the per-card slice of the CLI).
#[derive(Default, Clone)]
pub struct SeedSpec {
    seed_rfc6979_slot_9a_cert: bool,
    seed_rfc5903_slot_9d_cert: bool,
    seed_slot_9c_cert: bool,
    seed_rfc6979_slot_9e_cert: bool,
    /// Install just the canonical CHUID (no key/cert), so the card presents
    /// as *initialized* with empty slots — the starting state for an on-card
    /// GENERATE (`pivy-tool` needs the CHUID to find the card).
    seed_chuid: bool,
    /// Install a canonical Printed Information object (`5F C1 09`) so
    /// `pivy-tool pinfo` / piggy's `read_pinfo` return deterministic fields.
    seed_pinfo: bool,
    /// Start the card with both the PIN and PUK retry counters blocked (at 0),
    /// the precondition YubicoPIV RESET requires — so a `factory-reset` test can
    /// reset directly without first exhausting both counters.
    seed_pin_puk_blocked: bool,
    /// Override the CHUID's 16-byte GUID (piggy#242): multi-card setups
    /// need distinct GUIDs, since clients identify cards by GUID. Implies
    /// installing a CHUID. Cards after the first that seed a CHUID and
    /// give no explicit GUID get a derived default (canonical GUID with
    /// the last byte replaced by the card index).
    seed_chuid_guid: Option<[u8; 16]>,
    /// Non-default application PIN (1–8 ASCII chars; piggy#242/#177 —
    /// give each card of a multi-card fibby its own PIN).
    seed_pin: Option<String>,
    /// Start the PIN retry counter below the factory 3 (piggy#246), so a
    /// test can put a card near lockout and exercise the agent's
    /// offered-PIN lockout guard (piggy#245).
    seed_pin_retries: Option<u8>,
    /// Raw P-256 scalars / keys to install into the virtual card, parsed
    /// from `--seed-*` hex flags. Let bats/shell seed slot material that
    /// was previously Rust-only (piggy#135). Applied after the cert
    /// bundle, so an explicit `--seed-slot-9a-priv` overrides the scalar
    /// `--seed-rfc6979-slot-9a-cert` installs.
    seed_slot_9a_priv: Option<[u8; 32]>,
    seed_slot_9d_priv: Option<[u8; 32]>,
    seed_slot_9c_priv: Option<[u8; 32]>,
    seed_slot_9e_priv: Option<[u8; 32]>,
    /// `--seed-slot-<s>-ed25519`: Ed25519 seeds by slot, in flag order.
    seed_slot_ed25519: Vec<(u8, [u8; 32])>,
    seed_mgmt_key: Option<[u8; 24]>,
    seed_mgmt_key_witness: Option<[u8; 8]>,
    /// Deterministic key material for on-card GENERATE ASYMMETRIC (INS 0x47),
    /// keyed by slot. When set, a GENERATE for that slot installs this exact
    /// scalar instead of a random one (reproducible keygen for tests/replay).
    /// Distinct from `seed_slot_*_priv`, which installs a key directly without
    /// a GENERATE command.
    generate_slot_9a_priv: Option<[u8; 32]>,
    generate_slot_9c_priv: Option<[u8; 32]>,
    generate_slot_9d_priv: Option<[u8; 32]>,
}

impl SeedSpec {
    /// Whether any of this spec's flags installs a CHUID (the cert
    /// bundles do so as a side effect; `--seed-chuid`/`--seed-chuid-guid`
    /// do so directly) — i.e. whether the card presents as initialized
    /// with a GUID at all.
    fn seeds_a_chuid(&self) -> bool {
        self.seed_rfc6979_slot_9a_cert
            || self.seed_rfc5903_slot_9d_cert
            || self.seed_slot_9c_cert
            || self.seed_rfc6979_slot_9e_cert
            || self.seed_chuid
            || self.seed_chuid_guid.is_some()
    }

    /// Seed `card` as this spec says. `card_idx` derives the default
    /// distinct GUID for cards after the first (canonical GUID, last byte
    /// = index) so multi-card setups never present two cards with the
    /// same identity unless explicitly seeded that way.
    pub fn apply(&self, card: &mut VirtualCard, card_idx: usize) {
        if self.seed_rfc6979_slot_9a_cert {
            card.seed_rfc6979_slot_9a_cert();
        }
        if self.seed_rfc5903_slot_9d_cert {
            card.seed_rfc5903_slot_9d_cert();
        }
        if self.seed_slot_9c_cert {
            card.seed_fibby_slot_9c_cert();
        }
        if self.seed_rfc6979_slot_9e_cert {
            card.seed_rfc6979_slot_9e_cert();
        }
        if self.seed_chuid {
            card.seed_chuid();
        }
        if self.seed_pinfo {
            card.seed_pinfo();
        }
        if self.seed_pin_puk_blocked {
            card.seed_pin_puk_blocked();
        }
        // GUID override AFTER the cert bundles (which install the canonical
        // CHUID as a side effect): an explicit --seed-chuid-guid always wins;
        // a CHUID-seeded card after the first gets the derived default.
        match self.seed_chuid_guid {
            Some(guid) => card.seed_chuid_with_guid(guid),
            None if card_idx > 0 && self.seeds_a_chuid() => {
                let mut guid = fibby::virtual_card::CANONICAL_GUID;
                guid[15] = card_idx as u8;
                card.seed_chuid_with_guid(guid);
            }
            None => {}
        }
        if let Some(pin) = &self.seed_pin {
            card.seed_pin(pin);
        }
        // Lower the retry counter (constructed at the factory default 3) so a
        // test can start a card near lockout. Independent of seed_pin above,
        // which only sets the PIN value.
        if let Some(r) = self.seed_pin_retries {
            card.seed_pin_retries(r);
        }
        // Explicit per-slot seeds apply after the cert bundle, so an
        // explicit --seed-slot-9a-priv overrides the scalar the cert
        // flag installs.
        if let Some(s) = self.seed_slot_9a_priv {
            card.seed_slot_9a_priv(s);
        }
        if let Some(s) = self.seed_slot_9d_priv {
            card.seed_slot_9d_priv(s);
        }
        if let Some(s) = self.seed_slot_9c_priv {
            card.seed_slot_9c_priv(s);
        }
        if let Some(s) = self.seed_slot_9e_priv {
            card.seed_slot_9e_priv(s);
        }
        for &(slot, seed) in &self.seed_slot_ed25519 {
            card.seed_slot_ed25519(slot, seed);
        }
        // GENERATE overrides: make a subsequent on-card GENERATE for the
        // slot install this exact scalar instead of a random key.
        if let Some(s) = self.generate_slot_9a_priv {
            card.set_generate_override(0x9A, s);
        }
        if let Some(s) = self.generate_slot_9c_priv {
            card.set_generate_override(0x9C, s);
        }
        if let Some(s) = self.generate_slot_9d_priv {
            card.set_generate_override(0x9D, s);
        }
        if let Some(k) = self.seed_mgmt_key {
            card.seed_mgmt_key(k);
        }
        if let Some(w) = self.seed_mgmt_key_witness {
            card.seed_mgmt_key_witness(w);
        }
    }
}

/// What the test-double flags have seen so far, for the `--card` group
/// rules checked once the whole command line is read.
#[derive(Default)]
pub struct FlagState {
    reader_flag_given: bool,
    /// A sample seed flag given before the first `--card`, if any.
    global_seed_flag: Option<String>,
}

impl FlagState {
    /// Parse `key` if it is a test-double flag, returning whether it was.
    /// Seed flags target the OPEN `--card` group, else the implicit single
    /// card (piggy#242).
    pub fn parse(
        &mut self,
        args: &mut Args,
        key: &str,
        value: &mut dyn FnMut(&str) -> Result<String, String>,
    ) -> Result<bool, String> {
        if args.cards.is_empty() && (key.starts_with("--seed") || key.starts_with("--generate")) {
            self.global_seed_flag.get_or_insert_with(|| key.to_string());
        }
        let seeds = match args.cards.last_mut() {
            Some((_, s)) => s,
            None => &mut args.seeds,
        };
        match key {
            "--reader" => {
                args.reader = value("--reader")?;
                self.reader_flag_given = true;
            }
            "--auto-touch" => args.auto_touch = true,
            "--seed-rfc6979-slot-9a-cert" => seeds.seed_rfc6979_slot_9a_cert = true,
            "--seed-rfc5903-slot-9d-cert" => seeds.seed_rfc5903_slot_9d_cert = true,
            "--seed-slot-9c-cert" => seeds.seed_slot_9c_cert = true,
            "--seed-rfc6979-slot-9e-cert" => seeds.seed_rfc6979_slot_9e_cert = true,
            "--seed-chuid" => seeds.seed_chuid = true,
            "--seed-pinfo" => seeds.seed_pinfo = true,
            "--seed-pin-puk-blocked" => seeds.seed_pin_puk_blocked = true,
            "--seed-chuid-guid" => seeds.seed_chuid_guid = Some(hex_flag(value, key)?),
            "--seed-pin" => {
                let pin = value("--seed-pin")?;
                if pin.is_empty() || pin.len() > 8 || !pin.is_ascii() {
                    return Err("--seed-pin: want 1..=8 ASCII chars".into());
                }
                seeds.seed_pin = Some(pin);
            }
            "--seed-pin-retries" => {
                let n: u8 = value("--seed-pin-retries")?
                    .parse()
                    .map_err(|_| "--seed-pin-retries: want an integer".to_string())?;
                if !(1..=3).contains(&n) {
                    return Err("--seed-pin-retries: want 1..=3".into());
                }
                seeds.seed_pin_retries = Some(n);
            }
            "--seed-slot-9a-priv" => seeds.seed_slot_9a_priv = Some(hex_flag(value, key)?),
            "--seed-slot-9c-priv" => seeds.seed_slot_9c_priv = Some(hex_flag(value, key)?),
            "--seed-slot-9d-priv" => seeds.seed_slot_9d_priv = Some(hex_flag(value, key)?),
            "--seed-slot-9e-priv" => seeds.seed_slot_9e_priv = Some(hex_flag(value, key)?),
            "--seed-slot-9a-ed25519" => seeds.seed_slot_ed25519.push((0x9A, hex_flag(value, key)?)),
            "--seed-slot-9c-ed25519" => seeds.seed_slot_ed25519.push((0x9C, hex_flag(value, key)?)),
            "--seed-slot-9d-ed25519" => seeds.seed_slot_ed25519.push((0x9D, hex_flag(value, key)?)),
            "--seed-slot-9e-ed25519" => seeds.seed_slot_ed25519.push((0x9E, hex_flag(value, key)?)),
            "--generate-slot-9a-priv" => seeds.generate_slot_9a_priv = Some(hex_flag(value, key)?),
            "--generate-slot-9c-priv" => seeds.generate_slot_9c_priv = Some(hex_flag(value, key)?),
            "--generate-slot-9d-priv" => seeds.generate_slot_9d_priv = Some(hex_flag(value, key)?),
            "--seed-mgmt-key" => seeds.seed_mgmt_key = Some(hex_flag(value, key)?),
            "--seed-mgmt-key-witness" => seeds.seed_mgmt_key_witness = Some(hex_flag(value, key)?),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// `--card` group rules (piggy#242): the grouped and ungrouped styles
    /// don't mix, and the hardware proxy's `--reader` is no card name.
    pub fn check_card_groups(&self, args: &Args) -> Result<(), String> {
        if args.cards.is_empty() {
            return Ok(());
        }
        if let Some(flag) = &self.global_seed_flag {
            return Err(format!(
                "{flag} appears before the first --card; with --card groups every \
                 seed flag must follow the --card it configures"
            ));
        }
        if self.reader_flag_given {
            return Err(
                "--reader and --card don't mix: each --card NAME is its reader name".into(),
            );
        }
        Ok(())
    }
}

/// Read `key`'s value and parse it as exactly `N` hex bytes.
fn hex_flag<const N: usize>(
    value: &mut dyn FnMut(&str) -> Result<String, String>,
    key: &str,
) -> Result<[u8; N], String> {
    parse_hex_array(&value(key)?, key)
}

/// Parse a hex string into a fixed-size byte array. Accepts an optional
/// `0x` prefix; rejects non-hex characters and any length other than
/// exactly `N` bytes (`2*N` hex chars). `what` names the flag for error
/// messages.
fn parse_hex_array<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.is_ascii() {
        return Err(format!("{what}: non-ASCII hex"));
    }
    if s.len() != 2 * N {
        return Err(format!(
            "{what}: expected {N} bytes ({} hex chars), got {}",
            2 * N,
            s.len()
        ));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| format!("{what}: invalid hex byte at position {i}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_args() -> Args {
        Args {
            socket: String::new(),
            backend: "virtual".into(),
            reader: String::new(),
            model: "yk4".into(),
            serial: None,
            seeds: SeedSpec::default(),
            cards: Vec::new(),
            control_socket: None,
            auto_touch: false,
            touch_timeout: None,
            require_select: false,
        }
    }

    /// A value every test-only flag that takes one accepts.
    fn value_for(flag: &str) -> String {
        match flag {
            "--seed-pin" => "123456".into(),
            "--seed-pin-retries" => "2".into(),
            "--reader" => "Yubico".into(),
            "--seed-chuid-guid" => "00".repeat(16),
            "--seed-mgmt-key" => "00".repeat(24),
            "--seed-mgmt-key-witness" => "00".repeat(8),
            _ => "11".repeat(32),
        }
    }

    #[test]
    fn every_listed_test_flag_is_one_the_test_double_parses() {
        for &flag in TEST_ONLY_FLAGS {
            if flag == "--test-flags" {
                continue; // answered by parse_args before FlagState
            }
            let mut args = empty_args();
            let mut value = |_: &str| -> Result<String, String> { Ok(value_for(flag)) };
            let parsed = FlagState::default()
                .parse(&mut args, flag, &mut value)
                .unwrap_or_else(|e| panic!("{flag}: {e}"));
            assert!(parsed, "{flag} is listed in TEST_ONLY_FLAGS but not parsed");
        }
    }

    #[test]
    fn a_flag_both_builds_take_is_not_a_test_flag() {
        let mut args = empty_args();
        let mut value = |_: &str| -> Result<String, String> { Ok(String::new()) };
        for flag in ["--socket", "--card", "--model", "--build-profile"] {
            assert!(!TEST_ONLY_FLAGS.contains(&flag), "{flag}");
            assert!(
                !FlagState::default()
                    .parse(&mut args, flag, &mut value)
                    .unwrap(),
                "{flag}"
            );
        }
    }

    #[test]
    fn parses_exact_length_lowercase_and_uppercase() {
        let got: [u8; 4] = parse_hex_array("00ffAB10", "--x").unwrap();
        assert_eq!(got, [0x00, 0xFF, 0xAB, 0x10]);
    }

    #[test]
    fn accepts_optional_0x_prefix() {
        let got: [u8; 3] = parse_hex_array("0xDEADBE", "--x").unwrap();
        assert_eq!(got, [0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn parses_a_full_32_byte_scalar() {
        let hex = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
        let got: [u8; 32] = parse_hex_array(hex, "--seed-slot-9a-priv").unwrap();
        assert_eq!(got[0], 0xC9);
        assert_eq!(got[31], 0x21);
    }

    #[test]
    fn rejects_wrong_length() {
        let err = parse_hex_array::<32>("00ff", "--seed-slot-9a-priv").unwrap_err();
        assert!(err.contains("expected 32 bytes"), "got: {err}");
    }

    #[test]
    fn rejects_non_hex_characters() {
        // Correct length (8 chars = 4 bytes) but 'z'/'g' are not hex.
        let err = parse_hex_array::<4>("00zg1122", "--x").unwrap_err();
        assert!(err.contains("invalid hex"), "got: {err}");
    }

    #[test]
    fn rejects_non_ascii_without_panicking_on_char_boundary() {
        // A multi-byte char must be rejected before byte-slicing, or the
        // slice would panic on a non-char-boundary. 'é' is 2 bytes UTF-8,
        // so this string's byte length could otherwise look plausible.
        let err = parse_hex_array::<4>("00ffé011", "--x").unwrap_err();
        assert!(err.contains("non-ASCII"), "got: {err}");
    }
}
