//! Lightweight, dependency-free leveled logging + hex dumping.
//!
//! The whole point of fibby is to be debugged against real hardware by
//! other agents, so wire visibility is a feature, not an afterthought.
//! Control verbosity with the `FIBBY_LOG` env var:
//!
//! ```text
//! FIBBY_LOG=info    connection lifecycle, one line per command
//! FIBBY_LOG=debug   + decoded struct fields
//! FIBBY_LOG=wire    + full hex dump of every rx/tx body (the firehose)
//! ```
//!
//! Everything goes to stderr with a `[fibby:<tag>]` prefix so it
//! interleaves cleanly with `pivy-tool`/`pcscd` output during a capture.

use std::sync::atomic::{AtomicU8, Ordering};

pub const OFF: u8 = 0;
pub const INFO: u8 = 1;
pub const DEBUG: u8 = 2;
pub const WIRE: u8 = 3;

static LEVEL: AtomicU8 = AtomicU8::new(OFF);

/// Read `FIBBY_LOG` once at startup. Unknown values default to `info`.
pub fn init_from_env() {
    let lvl = match std::env::var("FIBBY_LOG").ok().as_deref() {
        Some("off") | None => OFF,
        Some("info") => INFO,
        Some("debug") => DEBUG,
        Some("wire") | Some("trace") => WIRE,
        Some(_) => INFO,
    };
    LEVEL.store(lvl, Ordering::Relaxed);
}

#[inline]
pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

#[inline]
pub fn enabled(lvl: u8) -> bool {
    level() >= lvl
}

/// Emit one log line at `lvl` if enabled. `tag` is a short subsystem
/// label (e.g. "conn", "rx", "tx", "proxy").
pub fn emit(lvl: u8, tag: &str, msg: &str) {
    if enabled(lvl) {
        eprintln!("[fibby:{tag}] {msg}");
    }
}

/// Hex dump in the canonical `offset  hex…  |ascii|` form, only built
/// when the WIRE level is active (so the formatting cost is skipped
/// otherwise).
pub fn hexdump(tag: &str, bytes: &[u8]) {
    if !enabled(WIRE) {
        return;
    }
    if bytes.is_empty() {
        eprintln!("[fibby:{tag}] <empty>");
        return;
    }
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::with_capacity(48);
        let mut asc = String::with_capacity(16);
        for b in chunk {
            hex.push_str(&format!("{b:02x} "));
            asc.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        eprintln!("[fibby:{tag}] {:04x}  {:<48} |{}|", i * 16, hex, asc);
    }
}
