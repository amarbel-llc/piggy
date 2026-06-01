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
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => args.socket = it.next().ok_or("--socket needs a value")?,
            "--backend" => args.backend = it.next().ok_or("--backend needs a value")?,
            "--reader" => args.reader = it.next().ok_or("--reader needs a value")?,
            "--model" => args.model = it.next().ok_or("--model needs a value")?,
            "--seed-rfc6979-slot-9a-cert" => args.seed_rfc6979_slot_9a_cert = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn print_help() {
    eprintln!(
        "fibby — pure-Rust virtual PIV card over the pcsc-lite protocol\n\
         \n\
         USAGE: fibby [--socket PATH] [--backend virtual|hardware]\n\
                      [--reader SUBSTR] [--model yk4|yk5]\n\
                      [--seed-rfc6979-slot-9a-cert]\n\
         \n\
         --model selects the virtual-card hardware profile (ATR + advertised\n\
         firmware version). Only meaningful when --backend=virtual; the\n\
         hardware backend reports whatever the real card advertises.\n\
         Default: yk4 (the wet-env-verified profile).\n\
         \n\
         --seed-rfc6979-slot-9a-cert installs the canonical fibby slot 9A\n\
         test cert (X.509 self-signed over the RFC 6979 §A.2.5 P-256 keypair)\n\
         at PIV tag 5F C1 01. pivy-agent then exposes one SSH identity\n\
         backed by the test-vector pubkey. Only meaningful when\n\
         --backend=virtual; ignored by the hardware backend. See piggy#135.\n\
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
