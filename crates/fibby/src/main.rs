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
    /// The implicit single card's seeds (every pre-#242 invocation).
    seeds: SeedSpec,
    /// `--card NAME` groups (piggy#242): each starts a new virtual card;
    /// seed flags after it apply to that card. Mutually exclusive with
    /// seed flags before the first `--card`, with `--reader`, and with
    /// the hardware backend.
    cards: Vec<(String, SeedSpec)>,
    /// Optional control socket (piggy#130) for runtime insert/remove of a
    /// card by reader name, driven by `fibby ctl`. Unset by default.
    control_socket: Option<String>,
}

/// One virtual card's seed configuration (the per-card slice of the CLI).
#[derive(Default, Clone)]
struct SeedSpec {
    seed_rfc6979_slot_9a_cert: bool,
    seed_rfc5903_slot_9d_cert: bool,
    seed_slot_9c_cert: bool,
    seed_rfc6979_slot_9e_cert: bool,
    /// Install just the canonical CHUID (no key/cert), so the card presents
    /// as *initialized* with empty slots — the starting state for an on-card
    /// GENERATE (`pivy-tool` needs the CHUID to find the card).
    seed_chuid: bool,
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
}

fn parse_args() -> Result<Args, String> {
    let default_socket =
        std::env::var("FIBBY_SOCK").unwrap_or_else(|_| "/tmp/fibby/pcscd.comm".to_string());
    let mut args = Args {
        socket: default_socket,
        backend: "virtual".to_string(),
        reader: "Yubico".to_string(),
        model: "yk4".to_string(),
        seeds: SeedSpec::default(),
        cards: Vec::new(),
        control_socket: None,
    };
    let mut reader_flag_given = false;
    let mut global_seed_flag: Option<String> = None;
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
        // Seed flags target the OPEN `--card` group, else the implicit
        // single card (piggy#242). Track a sample pre-`--card` seed flag
        // so mixing the two styles can be rejected below.
        if args.cards.is_empty() && (key.starts_with("--seed") || key.starts_with("--generate")) {
            global_seed_flag.get_or_insert_with(|| key.clone());
        }
        fn seeds(args: &mut Args) -> &mut SeedSpec {
            match args.cards.last_mut() {
                Some((_, s)) => s,
                None => &mut args.seeds,
            }
        }
        match key.as_str() {
            "--socket" => args.socket = value("--socket")?,
            "--control-socket" => args.control_socket = Some(value("--control-socket")?),
            "--backend" => args.backend = value("--backend")?,
            "--reader" => {
                args.reader = value("--reader")?;
                reader_flag_given = true;
            }
            "--model" => args.model = value("--model")?,
            "--card" => {
                let name = value("--card")?;
                if name.is_empty() {
                    return Err("--card needs a non-empty reader name".into());
                }
                if args.cards.iter().any(|(n, _)| *n == name) {
                    return Err(format!("duplicate --card name {name:?}"));
                }
                args.cards.push((name, SeedSpec::default()));
            }
            "--seed-rfc6979-slot-9a-cert" => seeds(&mut args).seed_rfc6979_slot_9a_cert = true,
            "--seed-rfc5903-slot-9d-cert" => seeds(&mut args).seed_rfc5903_slot_9d_cert = true,
            "--seed-slot-9c-cert" => seeds(&mut args).seed_slot_9c_cert = true,
            "--seed-rfc6979-slot-9e-cert" => seeds(&mut args).seed_rfc6979_slot_9e_cert = true,
            "--seed-chuid" => seeds(&mut args).seed_chuid = true,
            "--seed-chuid-guid" => {
                seeds(&mut args).seed_chuid_guid = Some(parse_hex_array(
                    &value("--seed-chuid-guid")?,
                    "--seed-chuid-guid",
                )?)
            }
            "--seed-pin" => {
                let pin = value("--seed-pin")?;
                if pin.is_empty() || pin.len() > 8 || !pin.is_ascii() {
                    return Err("--seed-pin: want 1..=8 ASCII chars".into());
                }
                seeds(&mut args).seed_pin = Some(pin);
            }
            "--seed-pin-retries" => {
                let n: u8 = value("--seed-pin-retries")?
                    .parse()
                    .map_err(|_| "--seed-pin-retries: want an integer".to_string())?;
                if !(1..=3).contains(&n) {
                    return Err("--seed-pin-retries: want 1..=3".into());
                }
                seeds(&mut args).seed_pin_retries = Some(n);
            }
            "--seed-slot-9c-priv" => {
                seeds(&mut args).seed_slot_9c_priv = Some(parse_hex_array(
                    &value("--seed-slot-9c-priv")?,
                    "--seed-slot-9c-priv",
                )?)
            }
            "--seed-slot-9a-priv" => {
                seeds(&mut args).seed_slot_9a_priv = Some(parse_hex_array(
                    &value("--seed-slot-9a-priv")?,
                    "--seed-slot-9a-priv",
                )?)
            }
            "--seed-slot-9d-priv" => {
                seeds(&mut args).seed_slot_9d_priv = Some(parse_hex_array(
                    &value("--seed-slot-9d-priv")?,
                    "--seed-slot-9d-priv",
                )?)
            }
            "--seed-slot-9e-priv" => {
                seeds(&mut args).seed_slot_9e_priv = Some(parse_hex_array(
                    &value("--seed-slot-9e-priv")?,
                    "--seed-slot-9e-priv",
                )?)
            }
            "--generate-slot-9a-priv" => {
                seeds(&mut args).generate_slot_9a_priv = Some(parse_hex_array(
                    &value("--generate-slot-9a-priv")?,
                    "--generate-slot-9a-priv",
                )?)
            }
            "--generate-slot-9c-priv" => {
                seeds(&mut args).generate_slot_9c_priv = Some(parse_hex_array(
                    &value("--generate-slot-9c-priv")?,
                    "--generate-slot-9c-priv",
                )?)
            }
            "--generate-slot-9d-priv" => {
                seeds(&mut args).generate_slot_9d_priv = Some(parse_hex_array(
                    &value("--generate-slot-9d-priv")?,
                    "--generate-slot-9d-priv",
                )?)
            }
            "--seed-mgmt-key" => {
                seeds(&mut args).seed_mgmt_key = Some(parse_hex_array(
                    &value("--seed-mgmt-key")?,
                    "--seed-mgmt-key",
                )?)
            }
            "--seed-mgmt-key-witness" => {
                seeds(&mut args).seed_mgmt_key_witness = Some(parse_hex_array(
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
    // `--card` group rules (piggy#242): the grouped and ungrouped styles
    // don't mix, and only the virtual backend can serve several cards.
    if !args.cards.is_empty() {
        if let Some(flag) = global_seed_flag {
            return Err(format!(
                "{flag} appears before the first --card; with --card groups every \
                 seed flag must follow the --card it configures"
            ));
        }
        if reader_flag_given {
            return Err(
                "--reader and --card don't mix: each --card NAME is its reader name".into(),
            );
        }
        if args.backend != "virtual" {
            return Err("--card requires --backend virtual".into());
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
                      [--card NAME [seed flags…]]…\n\
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
         --seed-pin ASCII sets a non-default application PIN (1-8 chars,\n\
         0xFF-padded). Virtual backend only; per --card group.\n\
         \n\
         --card NAME starts a new virtual card served as its own reader\n\
         named NAME (piggy#242): every seed flag AFTER a --card configures\n\
         that card, and multiple --card groups make fibby serve multiple\n\
         readers on one socket. Seed flags before the first --card, the\n\
         --reader flag, and --backend hardware don't mix with --card.\n\
         Cards after the first that seed a CHUID get a distinct GUID by\n\
         default (canonical GUID, last byte = card index); override it\n\
         per card with --seed-chuid-guid HEX32 (16 bytes, implies a\n\
         CHUID).\n\
         \n\
         Point clients at the socket via PCSCLITE_CSOCK_NAME.\n\
         Set FIBBY_LOG=info|debug|wire for logging."
    );
}

fn main() {
    proto_sanity();
    trace::init_from_env();

    // piggy#130: `fibby ctl --socket <ctl-path> <insert|remove|list> [<reader>]`
    // is the control client — it talks to a running fibby's control socket to
    // toggle a card's runtime presence.
    if std::env::args().nth(1).as_deref() == Some("ctl") {
        std::process::exit(run_ctl_client());
    }

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

    let backends = match make_backends(&args) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fibby: backend init failed: {e}");
            std::process::exit(1);
        }
    };

    trace::emit(
        trace::INFO,
        "main",
        &format!(
            "backend={} readers={} socket={}",
            args.backend,
            backends.len(),
            args.socket
        ),
    );
    if let Err(e) = server::serve(&args.socket, backends, args.control_socket.as_deref()) {
        eprintln!("fibby: serve failed: {e}");
        std::process::exit(1);
    }
}

/// piggy#130 control client: connect to a running fibby's `--control-socket`,
/// send one command, print the reply. Returns a process exit code (0 on an
/// `ok` reply). Usage: `fibby ctl --socket <path> <insert|remove|list>
/// [<reader-name>]` — the reader name may contain spaces (quoted or not).
fn run_ctl_client() -> i32 {
    use std::io::{Read, Write};
    let mut it = std::env::args().skip(2); // past argv[0] and "ctl"
    let mut socket: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    while let Some(a) = it.next() {
        if a == "--socket" {
            match it.next() {
                Some(v) => socket = Some(v),
                None => {
                    eprintln!("fibby ctl: --socket needs a value");
                    return 2;
                }
            }
        } else {
            rest.push(a);
        }
    }
    let Some(socket) = socket else {
        eprintln!("fibby ctl: --socket <control-path> is required");
        return 2;
    };
    if rest.is_empty() {
        eprintln!("fibby ctl: want <insert|remove|list> [<reader-name>]");
        return 2;
    }
    let command = rest.join(" ");
    let mut stream = match std::os::unix::net::UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fibby ctl: connect {socket}: {e}");
            return 1;
        }
    };
    if let Err(e) = writeln!(stream, "{command}") {
        eprintln!("fibby ctl: write: {e}");
        return 1;
    }
    let mut reply = String::new();
    if let Err(e) = stream.read_to_string(&mut reply) {
        eprintln!("fibby ctl: read: {e}");
        return 1;
    }
    print!("{reply}");
    if reply.starts_with("ok") { 0 } else { 1 }
}

/// Build the reader table (piggy#242): one backend per `--card` group,
/// or the single implicit card / hardware proxy of every pre-#242
/// invocation.
fn make_backends(args: &Args) -> Result<Vec<SharedBackend>, String> {
    match args.backend.as_str() {
        "virtual" => {
            let model = Model::parse_arg(&args.model)?;
            if args.cards.is_empty() {
                return Ok(vec![into_shared(build_virtual_card(
                    model,
                    &args.seeds,
                    None,
                    0,
                ))]);
            }
            args.cards
                .iter()
                .enumerate()
                .map(|(idx, (name, seeds))| {
                    Ok(into_shared(build_virtual_card(
                        model,
                        seeds,
                        Some(name),
                        idx,
                    )))
                })
                .collect()
        }
        "hardware" => Ok(vec![make_hardware_backend(&args.reader)?]),
        other => Err(format!(
            "unknown backend {other:?} (want 'virtual' or 'hardware')"
        )),
    }
}

/// Build one seeded [`VirtualCard`]. `reader_name` overrides the default
/// reader string (each `--card` is its own reader); `card_idx` derives
/// the default distinct GUID for cards after the first (canonical GUID,
/// last byte = index) so multi-card setups never present two cards with
/// the same identity unless explicitly seeded that way.
fn build_virtual_card(
    model: Model,
    seeds: &SeedSpec,
    reader_name: Option<&str>,
    card_idx: usize,
) -> VirtualCard {
    let mut card = VirtualCard::with_model(model);
    if let Some(name) = reader_name {
        card.set_reader_name(name);
    }
    if seeds.seed_rfc6979_slot_9a_cert {
        card.seed_rfc6979_slot_9a_cert();
    }
    if seeds.seed_rfc5903_slot_9d_cert {
        card.seed_rfc5903_slot_9d_cert();
    }
    if seeds.seed_slot_9c_cert {
        card.seed_fibby_slot_9c_cert();
    }
    if seeds.seed_rfc6979_slot_9e_cert {
        card.seed_rfc6979_slot_9e_cert();
    }
    if seeds.seed_chuid {
        card.seed_chuid();
    }
    // GUID override AFTER the cert bundles (which install the canonical
    // CHUID as a side effect): an explicit --seed-chuid-guid always wins;
    // a CHUID-seeded card after the first gets the derived default.
    match seeds.seed_chuid_guid {
        Some(guid) => card.seed_chuid_with_guid(guid),
        None if card_idx > 0 && seeds.seeds_a_chuid() => {
            let mut guid = fibby::virtual_card::CANONICAL_GUID;
            guid[15] = card_idx as u8;
            card.seed_chuid_with_guid(guid);
        }
        None => {}
    }
    if let Some(pin) = &seeds.seed_pin {
        card.seed_pin(pin);
    }
    // Lower the retry counter (constructed at the factory default 3) so a
    // test can start a card near lockout. Independent of seed_pin above,
    // which only sets the PIN value.
    if let Some(r) = seeds.seed_pin_retries {
        card.seed_pin_retries(r);
    }
    // Explicit per-slot seeds apply after the cert bundle, so an
    // explicit --seed-slot-9a-priv overrides the scalar the cert
    // flag installs.
    if let Some(s) = seeds.seed_slot_9a_priv {
        card.seed_slot_9a_priv(s);
    }
    if let Some(s) = seeds.seed_slot_9d_priv {
        card.seed_slot_9d_priv(s);
    }
    if let Some(s) = seeds.seed_slot_9c_priv {
        card.seed_slot_9c_priv(s);
    }
    if let Some(s) = seeds.seed_slot_9e_priv {
        card.seed_slot_9e_priv(s);
    }
    // GENERATE overrides: make a subsequent on-card GENERATE for the
    // slot install this exact scalar instead of a random key.
    if let Some(s) = seeds.generate_slot_9a_priv {
        card.set_generate_override(0x9A, s);
    }
    if let Some(s) = seeds.generate_slot_9c_priv {
        card.set_generate_override(0x9C, s);
    }
    if let Some(s) = seeds.generate_slot_9d_priv {
        card.set_generate_override(0x9D, s);
    }
    if let Some(k) = seeds.seed_mgmt_key {
        card.seed_mgmt_key(k);
    }
    if let Some(w) = seeds.seed_mgmt_key_witness {
        card.seed_mgmt_key_witness(w);
    }
    card
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
