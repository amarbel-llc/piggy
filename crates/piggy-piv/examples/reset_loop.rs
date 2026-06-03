//! Faithful-ish piggy#56 contender: repeatedly reset the card's PIN state
//! from a co-resident client, to race a non-transactional verify→crypto
//! sequence (piggy#56). Each cycle: connect, begin a transaction, VERIFY the
//! PIN, and end the transaction with `SCARD_RESET_CARD`.
//!
//! It reconnects a FRESH connection every cycle (like the agent's
//! reconnect_to_token per request). A single *persistent* connection that
//! resets every cycle wedges: its own `end(ResetCard)` makes the next
//! `begin_pin_session` storm on `SCARD_W_RESET_CARD` (the retry cap is
//! exhausted re-resetting), so it completes 0 cycles. Re-connecting re-selects
//! the applet cleanly after each reset. (A real C `pivy-agent` contender —
//! the issue's literal scenario — is the next step; see the just recipes.)
//!
//! Safety: a single fail-fast verify runs first; a wrong PIN aborts BEFORE
//! the loop so the retry counter is never burned. With the correct PIN every
//! verify succeeds (a successful VERIFY does not decrement). Run via
//! `just debug-reset-loop <guid> <pin> [secs]`.

use std::time::{Duration, Instant};

use piggy_piv::{PivContext, PivError};

/// One connect → begin → verify → end(ResetCard) cycle on a fresh connection.
fn one_cycle(ctx: &PivContext, want: &str, pin: &str) -> Result<(), PivError> {
    let tokens = ctx.enumerate_tokens()?;
    let mut token = tokens
        .into_iter()
        .find(|t| t.guid().to_hex().eq_ignore_ascii_case(want))
        .ok_or_else(|| PivError::Other(format!("card {want} not present")))?;
    let mut s = token.begin_pin_session()?;
    s.verify_pin(pin)?; // sets pin_verified -> end() uses ResetCard
    s.end() // SCardEndTransaction(SCARD_RESET_CARD)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let want = args
        .next()
        .expect("usage: reset_loop <guid-hex> <pin> [seconds]");
    let pin = args
        .next()
        .expect("usage: reset_loop <guid-hex> <pin> [seconds]");
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(120);

    let ctx = PivContext::new().expect("open PCSC context");

    // Fail-fast: abort on a bad PIN before looping (retry-counter safety).
    match one_cycle(&ctx, &want, &pin) {
        Ok(()) => eprintln!("RESETLOOP pin OK; starting on {want} for {secs}s"),
        Err(e @ (PivError::PinIncorrect { .. } | PivError::PinBlocked)) => {
            eprintln!("RESETLOOP REFUSING — bad PIN ({e}); not looping");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("RESETLOOP preflight error: {e}");
            std::process::exit(1);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut cycles, mut errs): (u64, u64) = (0, 0);
    while Instant::now() < deadline {
        match one_cycle(&ctx, &want, &pin) {
            Ok(()) => cycles += 1,
            Err(PivError::PinIncorrect { .. } | PivError::PinBlocked) => {
                eprintln!(
                    "RESETLOOP aborting — PIN became incorrect/blocked after {cycles} cycles"
                );
                std::process::exit(1);
            }
            Err(_) => errs += 1,
        }
    }
    eprintln!("RESETLOOP done: {cycles} reset cycles, {errs} transient errors");
}
