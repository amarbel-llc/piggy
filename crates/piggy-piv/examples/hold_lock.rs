//! Diagnostic for piggy#56: hold an `SCardBeginTransaction` lock on a card
//! (selected by GUID) indefinitely, so a co-resident pivy-tool / piggy-agent
//! must block on the lock. Used to prove that transaction contention
//! actually reaches another client on the same physical card (vs. silently
//! running in isolation, which would make a race test hollow).
//!
//! Read-only: it grabs the card transaction via `PivToken::begin_pin_session`
//! and sleeps — no PIN, no sign. The lock is released when the process exits
//! (the `PinSession` drops, ending the transaction). Run via
//! `just debug-hold-card-lock <guid> [secs]`.

use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let want = args.next().expect("usage: hold_lock <guid-hex> [seconds]");
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(3600);

    let ctx = piggy_piv::PivContext::new().expect("open PCSC context");
    let tokens = ctx.enumerate_tokens().expect("enumerate PIV tokens");
    let mut token = tokens
        .into_iter()
        .find(|t| t.guid().to_hex().eq_ignore_ascii_case(&want))
        .unwrap_or_else(|| panic!("no PIV card with GUID {want} present"));

    let _session = token
        .begin_pin_session()
        .expect("begin SCardBeginTransaction");
    eprintln!("HOLDING card lock on {want} for {secs}s (SCardBeginTransaction) — kill to release");
    std::thread::sleep(Duration::from_secs(secs));
    eprintln!("releasing lock on {want}");
}
