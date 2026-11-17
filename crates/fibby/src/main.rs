//! fibby CLI.
//!
//! ```text
//! fibby [--socket PATH] [--control-socket PATH] [--card NAME]… [...]
//! fibby --build-profile
//! fibby ctl --socket PATH <verb> …
//! ```
//!
//! Two builds (FDR 0006, piggy#382). The `test-double` build (the cargo
//! default, nix `.#fibby`) carries every test convenience: seed flags, the
//! fixed RFC vectors, IMPORT, `--auto-touch`, fault injection, the
//! hardware proxy and `FIBBY_LOG=wire`. The holder build
//! (`--no-default-features`, nix `.#fibby-holder`) has none of them: the
//! code and the flag names are absent from the binary, and the holder
//! answers any of those flags as an unknown argument. `--build-profile`
//! prints `test-double` or `holder`.
//!
//! Logging: FIBBY_LOG=info|debug (and `wire` in the test double; see
//! trace.rs).
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

#[cfg(feature = "test-double")]
mod cli_test_double;
#[cfg(feature = "test-double")]
use cli_test_double as test_double;
#[cfg(feature = "test-double")]
use test_double::SeedSpec;

/// The holder build seeds nothing: a `--card` is a blank card.
#[cfg(not(feature = "test-double"))]
#[derive(Default, Clone)]
struct SeedSpec {}

struct Args {
    socket: String,
    backend: String,
    /// Hardware backend only: reader-name substring to select.
    #[cfg(feature = "test-double")]
    reader: String,
    model: String,
    /// `--serial N`: the YubiKey serial every virtual card reports, in
    /// place of the model's captured physical-card serial (piggy#328).
    serial: Option<u32>,
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
    /// `--auto-touch`: every virtual card grants touch-requiring
    /// operations immediately instead of waiting for `fibby ctl touch`.
    #[cfg(feature = "test-double")]
    auto_touch: bool,
    /// `--touch-timeout-ms`: how long a touch-requiring operation waits
    /// for a touch on every virtual card. `None` keeps the 15 s default.
    touch_timeout: Option<std::time::Duration>,
    /// `--require-select`: every virtual card answers 6D00 while no applet
    /// is selected, as a real card does after a reset (piggy#325).
    require_select: bool,
}

/// What the command line asked for: serve, or answer a question and exit.
enum Invocation {
    Serve(Box<Args>),
    PrintAndExit(String),
}

fn parse_args() -> Result<Invocation, String> {
    let default_socket =
        std::env::var("FIBBY_SOCK").unwrap_or_else(|_| "/tmp/fibby/pcscd.comm".to_string());
    let mut args = Args {
        socket: default_socket,
        backend: "virtual".to_string(),
        #[cfg(feature = "test-double")]
        reader: "Yubico".to_string(),
        model: "yk4".to_string(),
        serial: None,
        seeds: SeedSpec::default(),
        cards: Vec::new(),
        control_socket: None,
        #[cfg(feature = "test-double")]
        auto_touch: false,
        touch_timeout: None,
        require_select: false,
    };
    #[cfg(feature = "test-double")]
    let mut test_flags = test_double::FlagState::default();
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
            "--control-socket" => args.control_socket = Some(value("--control-socket")?),
            "--backend" => args.backend = value("--backend")?,
            "--model" => args.model = value("--model")?,
            "--serial" => {
                args.serial = Some(
                    value("--serial")?
                        .parse()
                        .map_err(|_| "--serial: want a whole number below 4294967296")?,
                );
            }
            "--require-select" => args.require_select = true,
            "--touch-timeout-ms" => {
                let millis: u64 = value("--touch-timeout-ms")?
                    .parse()
                    .map_err(|_| "--touch-timeout-ms: want a whole number of milliseconds")?;
                args.touch_timeout = Some(std::time::Duration::from_millis(millis));
            }
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
            "--build-profile" => {
                return Ok(Invocation::PrintAndExit(fibby::BUILD_PROFILE.to_string()));
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            #[cfg(feature = "test-double")]
            "--test-flags" => {
                return Ok(Invocation::PrintAndExit(
                    test_double::TEST_ONLY_FLAGS.join("\n"),
                ));
            }
            other => {
                #[cfg(feature = "test-double")]
                if test_flags.parse(&mut args, other, &mut value)? {
                    continue;
                }
                return Err(unknown_argument(other));
            }
        }
    }
    #[cfg(feature = "test-double")]
    test_flags.check_card_groups(&args)?;
    if !args.cards.is_empty() && args.backend != "virtual" {
        return Err("--card requires --backend virtual".into());
    }
    Ok(Invocation::Serve(Box::new(args)))
}

#[cfg(feature = "test-double")]
fn unknown_argument(arg: &str) -> String {
    format!("unknown argument: {arg}")
}

/// The holder build names no test flag, not even to refuse it: the lint
/// that proves the flags are absent greps the binary for their names.
#[cfg(not(feature = "test-double"))]
fn unknown_argument(arg: &str) -> String {
    format!("unknown argument: {arg} (this fibby is the holder build, which has no test flags)")
}

fn print_help() {
    eprintln!(
        "fibby — pure-Rust virtual PIV card over the pcsc-lite protocol\n\
         build profile: {profile}\n\
         \n\
         USAGE: fibby [--socket PATH] [--backend virtual] [--model yk4|yk5|yk5.7]\n\
                      [--serial N] [--control-socket PATH]\n\
                      [--touch-timeout-ms MILLIS] [--require-select]\n\
                      [--card NAME]…\n\
                fibby --build-profile\n\
                fibby ctl --socket PATH <insert|remove|list|touch|profile> [READER]\n\
         \n\
         --build-profile prints which build this is: test-double (the test\n\
         lanes' build, with seeding, fixed vectors, key import, fault\n\
         injection, the hardware proxy and wire logging) or holder (none of\n\
         them).\n\
         \n\
         --model selects the virtual-card hardware profile (ATR + advertised\n\
         firmware version). Default: yk4 (the wet-env-verified profile).\n\
         yk5.7 is UNCAPTURED (yk5's placeholder ATR, firmware 5.7.1; #133)\n\
         and the only model that does Ed25519 (algorithm E0).\n\
         \n\
         --serial N replaces the serial every virtual card reports (a whole\n\
         number); without it yk5 reports the serial captured from a physical\n\
         card. yk4 still has no PIV serial, only the OTP-applet one.\n\
         \n\
         --card NAME starts a new virtual card served as its own reader\n\
         named NAME (piggy#242); multiple --card groups make fibby serve\n\
         multiple readers on one socket.\n\
         \n\
         Touch policy. A key GENERATEd with touch policy 'always' or\n\
         'cached' does not sign or do ECDH until the card is touched:\n\
         `fibby ctl --socket CTL touch READER` grants that card one touch,\n\
         which its next touch-requiring operation consumes (a 'cached' slot\n\
         then needs no further touch for 15 seconds). An operation with no\n\
         touch available waits; --touch-timeout-ms MILLIS sets how long\n\
         (default 15000) before it fails with status word 6982. FIBBY_LOG\n\
         lines to grep: `TOUCH needed <slot>`, `TOUCH granted <slot>`,\n\
         `TOUCH cached <slot>`, `TOUCH timeout <slot> -> 6982`.\n\
         \n\
         Card state. A transaction ended with a reset disposition resets\n\
         the card for every client: no applet stays selected, and the PIN\n\
         and management-key authentication are cleared. A PIN-always key\n\
         needs its VERIFY immediately before its operation; any other\n\
         command in between answers the operation 6982. --require-select\n\
         makes every virtual card answer 6D00 while no applet is selected,\n\
         as a real card does after a reset.\n\
         \n\
         Point clients at the socket via PCSCLITE_CSOCK_NAME.\n\
         SIGTERM or SIGINT removes the sockets and exits 0.\n\
         Set FIBBY_LOG=info|debug for logging.",
        profile = fibby::BUILD_PROFILE
    );
    #[cfg(feature = "test-double")]
    eprintln!("{}", test_double::HELP);
}

fn main() {
    proto_sanity();

    // piggy#130: `fibby ctl --socket <ctl-path> <insert|remove|list|touch|fault> …`
    // is the control client — it talks to a running fibby's control socket to
    // toggle a card's runtime presence, grant a simulated touch, or queue an
    // injected fault (piggy#284).
    if std::env::args().nth(1).as_deref() == Some("ctl") {
        std::process::exit(run_ctl_client());
    }

    let args = match parse_args() {
        Ok(Invocation::Serve(a)) => *a,
        Ok(Invocation::PrintAndExit(text)) => {
            println!("{text}");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("fibby: {e}");
            eprintln!("fibby: run `fibby --help` for usage");
            std::process::exit(2);
        }
    };

    if let Err(e) = trace::init_from_env() {
        eprintln!("fibby: {e}");
        std::process::exit(2);
    }

    // The holder keeps its secrets out of core files and ptrace as the
    // agent does (piggy#382 item 3, FDR 0006 "Guarded memory"). The test
    // double stays debuggable.
    #[cfg(not(feature = "test-double"))]
    harden_holder_process();

    if let Some(dir) = std::path::Path::new(&args.socket).parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    // Before any thread is spawned, so every thread inherits the mask.
    exit_cleanly_on_sigterm_and_sigint(
        std::iter::once(args.socket.clone())
            .chain(args.control_socket.clone())
            .collect(),
    );

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
            "profile={} backend={} readers={} socket={}",
            fibby::BUILD_PROFILE,
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

/// Non-dumpable and a zero core limit, each step reported; a step that
/// fails is a warning, and the holder keeps running, as the agent does.
#[cfg(not(feature = "test-double"))]
fn harden_holder_process() {
    let hardening = piggy_guard::harden_process();
    let dumpable = match &hardening.non_dumpable {
        Some(Ok(())) => "non-dumpable".to_string(),
        Some(Err(e)) => format!("still dumpable ({e})"),
        None => "dumpable flag unavailable on this platform".to_string(),
    };
    let core = match &hardening.core_limit_zero {
        Ok(()) => "core limit 0".to_string(),
        Err(e) => format!("core limit unchanged ({e})"),
    };
    let failed =
        matches!(hardening.non_dumpable, Some(Err(_))) || hardening.core_limit_zero.is_err();
    if failed {
        eprintln!("fibby: warning: process hardening incomplete: {dumpable}, {core}");
    }
    trace::emit(
        trace::INFO,
        "main",
        &format!("process hardening: {dumpable}, {core}"),
    );
}

/// piggy#270: block SIGTERM and SIGINT in every thread and take them on a
/// dedicated `sigwait` thread, which unlinks `sockets` and exits 0 through
/// libc's `exit`, so atexit handlers (an instrumented build's LLVM profile
/// writer) run. Must be called before any other thread exists.
fn exit_cleanly_on_sigterm_and_sigint(sockets: Vec<String>) {
    // SAFETY: plain libc signal-set calls on a local, zero-initialised set.
    let set = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
            0,
            "pthread_sigmask"
        );
        set
    };
    std::thread::spawn(move || {
        let mut signal: libc::c_int = 0;
        // SAFETY: `set` is a valid signal set; `signal` is a valid out-pointer.
        if unsafe { libc::sigwait(&set, &mut signal) } != 0 {
            return;
        }
        trace::emit(
            trace::INFO,
            "main",
            &format!("signal {signal}: removing sockets and exiting"),
        );
        for socket in &sockets {
            let _ = std::fs::remove_file(socket);
        }
        std::process::exit(0);
    });
}

#[cfg(feature = "test-double")]
const CTL_USAGE: &str = "fibby ctl: want <insert|remove|list> [<reader-name>] | touch <reader-name> | profile | fault <INS|*> <SW>[x<count>] <reader-name> | fault clear <reader-name>";
#[cfg(not(feature = "test-double"))]
const CTL_USAGE: &str =
    "fibby ctl: want <insert|remove|list> [<reader-name>] | touch <reader-name> | profile";

/// piggy#130 control client: connect to a running fibby's `--control-socket`,
/// send one command, print the reply. Returns a process exit code (0 on an
/// `ok` reply). Usage: `fibby ctl --socket <path> <insert|remove|list>
/// [<reader-name>]`, `fibby ctl --socket <path> touch <reader-name>` (grant
/// one simulated touch), `fibby ctl --socket <path> profile` (the running
/// fibby's build profile), or, in the test double, `fibby ctl --socket
/// <path> fault <INS|*> <SW>[x<count>] <reader-name>` / `fault clear
/// <reader-name>` (piggy#284) — the reader name may contain spaces (quoted
/// or not).
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
        eprintln!("{CTL_USAGE}");
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
            // FDR 0006 "Attestation" (piggy#382 item 5): one attestation key
            // per fibby start, in guarded memory, issuing for every card.
            let authority = Arc::new(fibby::attest::AttestationAuthority::generate());
            // The touch flags are global: they configure every virtual
            // card this fibby serves.
            let with_touch_flags = |mut card: VirtualCard| {
                card.set_attestation_authority(authority.clone());
                #[cfg(feature = "test-double")]
                card.set_auto_touch(args.auto_touch);
                card.set_require_select(args.require_select);
                if let Some(serial) = args.serial {
                    card.set_serial(serial);
                }
                if let Some(timeout) = args.touch_timeout {
                    card.set_touch_timeout(timeout);
                }
                into_shared(card)
            };
            if args.cards.is_empty() {
                return Ok(vec![with_touch_flags(build_virtual_card(
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
                    Ok(with_touch_flags(build_virtual_card(
                        model,
                        seeds,
                        Some(name),
                        idx,
                    )))
                })
                .collect()
        }
        "hardware" => make_hardware_backend(args),
        other => Err(format!(
            "unknown backend {other:?} (want 'virtual' or 'hardware')"
        )),
    }
}

/// Build one [`VirtualCard`], seeded in the test double. `reader_name`
/// overrides the default reader string (each `--card` is its own reader);
/// `card_idx` lets the test double derive a distinct default GUID for
/// cards after the first.
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
    #[cfg(feature = "test-double")]
    seeds.apply(&mut card, card_idx);
    #[cfg(not(feature = "test-double"))]
    let _ = (seeds, card_idx);
    card
}

#[cfg(feature = "hardware-proxy")]
fn make_hardware_backend(args: &Args) -> Result<Vec<SharedBackend>, String> {
    Ok(vec![into_shared(
        fibby::hardware_proxy::HardwareProxy::new(&args.reader)?,
    )])
}

#[cfg(not(feature = "hardware-proxy"))]
fn make_hardware_backend(_args: &Args) -> Result<Vec<SharedBackend>, String> {
    Err(format!(
        "the 'hardware' backend is absent from this build (profile {}); it needs \
         the `hardware-proxy` build feature",
        fibby::BUILD_PROFILE
    ))
}

fn into_shared<B: Backend + 'static>(b: B) -> SharedBackend {
    Arc::new(Mutex::new(b))
}

fn proto_sanity() {
    fibby::proto::assert_le_host();
}
