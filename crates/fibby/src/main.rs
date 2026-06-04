//! fibby CLI.
//!
//! ```text
//! fibby [--socket PATH] [--backend virtual|hardware] [--reader SUBSTR]
//!
//!   --socket PATH      Unix socket to listen on. Default: $FIBBY_SOCK or
//!                      /tmp/fibby/pcscd.comm. Point clients at it with
//!                      PCSCLITE_CSOCK_NAME=PATH.
//!   --backend KIND     'virtual' (default) = in-Rust PIV card.
//!                      'hardware' = proxy to the system pcscd/YubiKey
//!                      (requires the `hardware-proxy` build feature).
//!   --reader SUBSTR    Hardware backend only: reader-name substring to
//!                      select. Default: "Yubico".
//!
//! Logging: FIBBY_LOG=info|debug|wire (see trace.rs). `wire` hex-dumps
//! every message — the firehose for protocol debugging.
//! ```
//!
//! Validation recipe (on a machine with a YubiKey):
//! ```sh
//! FIBBY_LOG=wire cargo run -p fibby --features hardware-proxy -- \
//!   --backend hardware --socket /tmp/fibby/pcscd.comm &
//! PCSCLITE_CSOCK_NAME=/tmp/fibby/pcscd.comm pivy-tool list
//! ```

use std::sync::{Arc, Mutex};

use fibby::backend::Backend;
use fibby::server::{self, SharedBackend};
use fibby::{
    trace,
    virtual_card::{Model, VirtualCard},
};

struct Args {
    socket: String,
    backend: String,
    reader: String,
    model: String,
    seed_rfc6979_slot_9a_cert: bool,
    seed_rfc5903_slot_9d_cert: bool,
    seed_slot_9c_cert: bool,
    seed_rfc6979_slot_9e_cert: bool,
    /// Install just the canonical CHUID (no key/cert), so the card presents
    /// as *initialized* with empty slots — the starting state for an on-card
    /// GENERATE (`pivy-tool` needs the CHUID to find the card).
    seed_chuid: bool,
    /// Raw P-256 scalars / keys to install into the virtual card, parsed
    /// from `--seed-*` hex flags. Let bats/shell seed slot material that
    /// was previously Rust-only (piggy#135). Applied after the cert
    /// bundle, so an explicit `--seed-slot-9a-priv` overrides the scalar
    /// `--seed-rfc6979-slot-9a-cert` installs.
    seed_slot_9a_priv: Option<[u8; 32]>,
    seed_slot_9d_priv: Option<[u8; 32]>,
    seed_slot_9c_priv: Option<[u8; 32]>,
    seed_slot_9e_priv: Option<[u8; 32]>,
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

fn parse_args() -> Result<Args, String> {
    let default_socket =
        std::env::var("FIBBY_SOCK").unwrap_or_else(|_| "/tmp/fibby/pcscd.comm".to_string());
    let mut args = Args {
        socket: default_socket,
        backend: "virtual".to_string(),
        reader: "Yubico".to_string(),
        model: "yk4".to_string(),
        seed_rfc6979_slot_9a_cert: false,
        seed_rfc5903_slot_9d_cert: false,
        seed_slot_9c_cert: false,
        seed_rfc6979_slot_9e_cert: false,
        seed_chuid: false,
        seed_slot_9a_priv: None,
        seed_slot_9d_priv: None,
        seed_slot_9c_priv: None,
        seed_slot_9e_priv: None,
        generate_slot_9a_priv: None,
        generate_slot_9c_priv: None,
        generate_slot_9d_priv: None,
        seed_mgmt_key: None,
        seed_mgmt_key_witness: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(raw) = it.next() {
        // Accept both `--flag value` and `--flag=value` (the latter is
        // handy for shell/bats orchestration of the `--seed-*` flags).
        let (key, inline) = match raw.split_once('=') {
            Some((k, v)) => (k.to_string(), Some(v.to_string())),
            None => (raw, None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            it.next().ok_or_else(|| format!("{name} needs a value"))
        };
        match key.as_str() {
            "--socket" => args.socket = value("--socket")?,
            "--backend" => args.backend = value("--backend")?,
            "--reader" => args.reader = value("--reader")?,
            "--model" => args.model = value("--model")?,
            "--seed-rfc6979-slot-9a-cert" => args.seed_rfc6979_slot_9a_cert = true,
            "--seed-rfc5903-slot-9d-cert" => args.seed_rfc5903_slot_9d_cert = true,
            "--seed-slot-9c-cert" => args.seed_slot_9c_cert = true,
            "--seed-rfc6979-slot-9e-cert" => args.seed_rfc6979_slot_9e_cert = true,
            "--seed-chuid" => args.seed_chuid = true,
            "--seed-slot-9c-priv" => {
                args.seed_slot_9c_priv = Some(parse_hex_array(
                    &value("--seed-slot-9c-priv")?,
                    "--seed-slot-9c-priv",
                )?)
            }
            "--seed-slot-9a-priv" => {
                args.seed_slot_9a_priv = Some(parse_hex_array(
                    &value("--seed-slot-9a-priv")?,
                    "--seed-slot-9a-priv",
                )?)
            }
            "--seed-slot-9d-priv" => {
                args.seed_slot_9d_priv = Some(parse_hex_array(
                    &value("--seed-slot-9d-priv")?,
                    "--seed-slot-9d-priv",
                )?)
            }
            "--seed-slot-9e-priv" => {
                args.seed_slot_9e_priv = Some(parse_hex_array(
                    &value("--seed-slot-9e-priv")?,
                    "--seed-slot-9e-priv",
                )?)
            }
            "--generate-slot-9a-priv" => {
                args.generate_slot_9a_priv = Some(parse_hex_array(
                    &value("--generate-slot-9a-priv")?,
                    "--generate-slot-9a-priv",
                )?)
            }
            "--generate-slot-9c-priv" => {
                args.generate_slot_9c_priv = Some(parse_hex_array(
                    &value("--generate-slot-9c-priv")?,
                    "--generate-slot-9c-priv",
                )?)
            }
            "--generate-slot-9d-priv" => {
                args.generate_slot_9d_priv = Some(parse_hex_array(
                    &value("--generate-slot-9d-priv")?,
                    "--generate-slot-9d-priv",
                )?)
            }
            "--seed-mgmt-key" => {
                args.seed_mgmt_key = Some(parse_hex_array(
                    &value("--seed-mgmt-key")?,
                    "--seed-mgmt-key",
                )?)
            }
            "--seed-mgmt-key-witness" => {
                args.seed_mgmt_key_witness = Some(parse_hex_array(
                    &value("--seed-mgmt-key-witness")?,
                    "--seed-mgmt-key-witness",
                )?)
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
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

fn print_help() {
    eprintln!(
        "fibby — pure-Rust virtual PIV card over the pcsc-lite protocol\n\
         \n\
         USAGE: fibby [--socket PATH] [--backend virtual|hardware]\n\
                      [--reader SUBSTR] [--model yk4|yk5]\n\
                      [--seed-rfc6979-slot-9a-cert]\n\
                      [--seed-rfc5903-slot-9d-cert] [--seed-slot-9c-cert]\n\
                      [--seed-rfc6979-slot-9e-cert] [--seed-chuid]\n\
                      [--seed-slot-9a-priv HEX] [--seed-slot-9d-priv HEX]\n\
                      [--seed-slot-9c-priv HEX] [--seed-slot-9e-priv HEX]\n\
                      [--generate-slot-9a-priv HEX] [--generate-slot-9c-priv HEX]\n\
                      [--generate-slot-9d-priv HEX]\n\
                      [--seed-mgmt-key HEX] [--seed-mgmt-key-witness HEX]\n\
         \n\
         --model selects the virtual-card hardware profile (ATR + advertised\n\
         firmware version). Only meaningful when --backend=virtual; the\n\
         hardware backend reports whatever the real card advertises.\n\
         Default: yk4 (the wet-env-verified profile).\n\
         \n\
         --seed-rfc6979-slot-9a-cert installs the canonical fibby slot 9A\n\
         test cert (X.509 self-signed over the RFC 6979 §A.2.5 P-256 keypair)\n\
         at PIV tag 5F C1 05 AND the matching private key into slot 9A, so\n\
         pivy-agent exposes one SSH identity that can both be enumerated and\n\
         used to sign (RFC 6979 deterministic ECDSA). Only meaningful when\n\
         --backend=virtual; ignored by the hardware backend. See piggy#135.\n\
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
         A fibby-generated keypair (the sign path is RFC 6979 deterministic,\n\
         so no published vector is needed), distinct from 9A/9D.\n\
         \n\
         --seed-slot-9a-priv / --seed-slot-9d-priv / --seed-slot-9c-priv take\n\
         a 32-byte (64 hex\n\
         char) big-endian P-256 scalar; --seed-mgmt-key takes a 24-byte\n\
         3DES key; --seed-mgmt-key-witness takes the 8-byte challenge\n\
         witness. All accept an optional 0x prefix and the `--flag=HEX`\n\
         form. They let shell/bats seed slot material that was previously\n\
         Rust-only. --seed-slot-9a-priv applied after the cert flag wins.\n\
         Virtual backend only.\n\
         \n\
         --seed-chuid installs only the canonical CHUID (no key or cert), so\n\
         the card presents as initialized with empty slots — the starting\n\
         point for an on-card GENERATE (pivy-tool needs a CHUID to find the\n\
         card). Virtual backend only.\n\
         \n\
         --generate-slot-9a-priv / --generate-slot-9c-priv / --generate-slot-9d-priv\n\
         pin the 32-byte P-256 scalar that an on-card GENERATE ASYMMETRIC (INS\n\
         0x47) will install into that slot, making keygen deterministic for\n\
         tests/replay. Unlike --seed-slot-*-priv (which installs a key\n\
         directly), this only takes effect when a client sends a GENERATE.\n\
         Without it, GENERATE picks a fresh random key. Virtual backend only.\n\
         \n\
         Point clients at the socket via PCSCLITE_CSOCK_NAME.\n\
         Set FIBBY_LOG=info|debug|wire for logging."
    );
}

fn main() {
    proto_sanity();
    trace::init_from_env();

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fibby: {e}");
            print_help();
            std::process::exit(2);
        }
    };

    if let Some(dir) = std::path::Path::new(&args.socket).parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    let backend = match make_backend(&args) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fibby: backend init failed: {e}");
            std::process::exit(1);
        }
    };

    trace::emit(
        trace::INFO,
        "main",
        &format!("backend={} socket={}", args.backend, args.socket),
    );
    if let Err(e) = server::serve(&args.socket, backend) {
        eprintln!("fibby: serve failed: {e}");
        std::process::exit(1);
    }
}

fn make_backend(args: &Args) -> Result<SharedBackend, String> {
    match args.backend.as_str() {
        "virtual" => {
            let model = Model::parse_arg(&args.model)?;
            let mut card = VirtualCard::with_model(model);
            if args.seed_rfc6979_slot_9a_cert {
                card.seed_rfc6979_slot_9a_cert();
            }
            if args.seed_rfc5903_slot_9d_cert {
                card.seed_rfc5903_slot_9d_cert();
            }
            if args.seed_slot_9c_cert {
                card.seed_fibby_slot_9c_cert();
            }
            if args.seed_rfc6979_slot_9e_cert {
                card.seed_rfc6979_slot_9e_cert();
            }
            if args.seed_chuid {
                card.seed_chuid();
            }
            // Explicit per-slot seeds apply after the cert bundle, so an
            // explicit --seed-slot-9a-priv overrides the scalar the cert
            // flag installs.
            if let Some(s) = args.seed_slot_9a_priv {
                card.seed_slot_9a_priv(s);
            }
            if let Some(s) = args.seed_slot_9d_priv {
                card.seed_slot_9d_priv(s);
            }
            if let Some(s) = args.seed_slot_9c_priv {
                card.seed_slot_9c_priv(s);
            }
            if let Some(s) = args.seed_slot_9e_priv {
                card.seed_slot_9e_priv(s);
            }
            // GENERATE overrides: make a subsequent on-card GENERATE for the
            // slot install this exact scalar instead of a random key.
            if let Some(s) = args.generate_slot_9a_priv {
                card.set_generate_override(0x9A, s);
            }
            if let Some(s) = args.generate_slot_9c_priv {
                card.set_generate_override(0x9C, s);
            }
            if let Some(s) = args.generate_slot_9d_priv {
                card.set_generate_override(0x9D, s);
            }
            if let Some(k) = args.seed_mgmt_key {
                card.seed_mgmt_key(k);
            }
            if let Some(w) = args.seed_mgmt_key_witness {
                card.seed_mgmt_key_witness(w);
            }
            Ok(into_shared(card))
        }
        "hardware" => make_hardware_backend(&args.reader),
        other => Err(format!(
            "unknown backend {other:?} (want 'virtual' or 'hardware')"
        )),
    }
}

#[cfg(feature = "hardware-proxy")]
fn make_hardware_backend(reader: &str) -> Result<SharedBackend, String> {
    Ok(into_shared(fibby::hardware_proxy::HardwareProxy::new(
        reader,
    )?))
}

#[cfg(not(feature = "hardware-proxy"))]
fn make_hardware_backend(_reader: &str) -> Result<SharedBackend, String> {
    Err(
        "the 'hardware' backend needs the `hardware-proxy` build feature: \
         cargo run -p fibby --features hardware-proxy"
            .to_string(),
    )
}

fn into_shared<B: Backend + 'static>(b: B) -> SharedBackend {
    Arc::new(Mutex::new(b))
}

fn proto_sanity() {
    fibby::proto::assert_le_host();
}

#[cfg(test)]
mod tests {
    use super::parse_hex_array;

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
