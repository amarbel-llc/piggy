use std::ffi::CString;
use std::time::{Duration, Instant};

use clap::Parser;
use pcsc::{Context, Protocols, ReaderState, Scope, ShareMode, State};

const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

#[derive(Parser)]
#[command(about = "Wait for a PIV smart card to become ready on a PC/SC reader")]
struct Args {
    #[arg(long)]
    reader: String,

    #[arg(long, default_value = "30")]
    timeout: u64,

    #[arg(
        long,
        help = "Hex-encoded APDU to send before the readiness probe (whitespace stripped)"
    )]
    activate: Option<String>,
}

fn main() {
    let args = Args::parse();
    let deadline = Instant::now() + Duration::from_secs(args.timeout);

    let ctx = match Context::establish(Scope::System) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fib-wait-ready: SCardEstablishContext failed: {e}");
            std::process::exit(1);
        }
    };

    let reader_cstr = match CString::new(args.reader.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fib-wait-ready: invalid reader name: {e}");
            std::process::exit(2);
        }
    };

    if let Some(ref hex_apdu) = args.activate {
        let stripped: String = hex_apdu.chars().filter(|c| !c.is_whitespace()).collect();
        let apdu = match hex::decode(&stripped) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("fib-wait-ready: bad --activate hex: {e}");
                std::process::exit(2);
            }
        };
        if !activate_loop(&ctx, &reader_cstr, &apdu, deadline) {
            eprintln!("fib-wait-ready: activation APDU never succeeded (timeout)");
            std::process::exit(1);
        }
    }

    if !wait_card_present(&ctx, &reader_cstr, deadline) {
        eprintln!("fib-wait-ready: card never became present (timeout)");
        std::process::exit(1);
    }

    if !piv_select(&ctx, &reader_cstr) {
        eprintln!("fib-wait-ready: PIV AID SELECT failed after card present");
        std::process::exit(1);
    }
}

fn is_retryable(e: pcsc::Error) -> bool {
    matches!(
        e,
        pcsc::Error::UnknownReader
            | pcsc::Error::NoSmartcard
            | pcsc::Error::ReaderUnavailable
            | pcsc::Error::NoReadersAvailable
            | pcsc::Error::RemovedCard
            | pcsc::Error::ResetCard
            | pcsc::Error::UnpoweredCard
    )
}

fn activate_loop(ctx: &Context, reader: &CString, apdu: &[u8], deadline: Instant) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => {
                let mut resp = [0u8; 258];
                match card.transmit(apdu, &mut resp) {
                    Ok(r) if r.len() >= 2 => {
                        let sw1 = r[r.len() - 2];
                        if sw1 == 0x90 || sw1 == 0x9F {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
            Err(e) if is_retryable(e) => {}
            Err(e) => {
                eprintln!("fib-wait-ready: activate SCardConnect: {e}");
                return false;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_card_present(ctx: &Context, reader: &CString, deadline: Instant) -> bool {
    let mut rs = ReaderState::new(reader.clone(), State::UNAWARE);
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        match ctx.get_status_change(remaining, std::slice::from_mut(&mut rs)) {
            Ok(()) => {}
            Err(pcsc::Error::Timeout) => return false,
            Err(e) if is_retryable(e) => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                eprintln!("fib-wait-ready: SCardGetStatusChange: {e}");
                return false;
            }
        }
        let state = rs.event_state();
        if state.contains(State::PRESENT) && !state.contains(State::MUTE) {
            return true;
        }
        rs.sync_current_state();
    }
}

fn piv_select(ctx: &Context, reader: &CString) -> bool {
    let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fib-wait-ready: SCardConnect for PIV SELECT: {e}");
            return false;
        }
    };
    // ISO 7816-4 SELECT by AID: CLA=00 INS=A4 P1=04 P2=00 Lc=len(AID) AID
    let mut cmd = vec![0x00, 0xA4, 0x04, 0x00, PIV_AID.len() as u8];
    cmd.extend_from_slice(PIV_AID);
    let mut resp = [0u8; 258];
    match card.transmit(&cmd, &mut resp) {
        Ok(r) if r.len() >= 2 => {
            let sw = ((r[r.len() - 2] as u16) << 8) | r[r.len() - 1] as u16;
            if sw == 0x9000 {
                return true;
            }
            eprintln!("fib-wait-ready: PIV SELECT returned SW={sw:#06X}");
            false
        }
        Ok(_) => {
            eprintln!("fib-wait-ready: PIV SELECT response too short");
            false
        }
        Err(e) => {
            eprintln!("fib-wait-ready: PIV SELECT transmit: {e}");
            false
        }
    }
}
