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
}

fn main() {
    let args = Args::parse();
    let deadline = Instant::now() + Duration::from_secs(args.timeout);

    let ctx = match Context::establish(Scope::System) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fibby-wait-ready:SCardEstablishContext failed: {e}");
            std::process::exit(1);
        }
    };

    let reader_cstr = match CString::new(args.reader.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fibby-wait-ready:invalid reader name: {e}");
            std::process::exit(2);
        }
    };

    if !wait_card_present(&ctx, &reader_cstr, deadline) {
        eprintln!("fibby-wait-ready:card never became present (timeout)");
        std::process::exit(1);
    }

    if !piv_select(&ctx, &reader_cstr) {
        eprintln!("fibby-wait-ready:PIV AID SELECT failed after card present");
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
                eprintln!("fibby-wait-ready:SCardGetStatusChange: {e}");
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
            eprintln!("fibby-wait-ready:SCardConnect for PIV SELECT: {e}");
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
            eprintln!("fibby-wait-ready:PIV SELECT returned SW={sw:#06X}");
            false
        }
        Ok(_) => {
            eprintln!("fibby-wait-ready:PIV SELECT response too short");
            false
        }
        Err(e) => {
            eprintln!("fibby-wait-ready:PIV SELECT transmit: {e}");
            false
        }
    }
}
