//! `wire-to-apdu-fixtures` — extract structured APDU request/response
//! pairs from a `FIBBY_LOG=wire` capture log.
//!
//! Wire log convention (see `crates/fibby/src/trace.rs` and the
//! `[fibby:apdu>]`/`[fibby:apdu<]` markers in server.rs's
//! TRANSMIT handler): each APDU is hex-dumped one line per 16 bytes,
//! tagged with the direction. The fixture format below preserves the
//! request/response pairing without the offset+gutter noise of the
//! original hexdump.
//!
//! Output format (line-based text, one fixture file per capture):
//!
//! ```text
//! # fibby APDU fixture v1
//! # source: <relative-path-of-input>
//!
//! > 00a4040000000ba000000308000010000100
//! < 61114f0600001000010079074f05a000000308 9000
//!
//! > 00cb3fff0000055c035fc1 0700 00
//! < 6a82
//! ```
//!
//! Rules: `#` lines are metadata. Blank lines separate pairs. Each
//! pair is exactly two lines (`> request`, `< response`). Hex is
//! contiguous; whitespace within hex is ignored by the parser.
//!
//! Usage:
//!
//! ```sh
//! wire-to-apdu-fixtures <input.log>     # writes fixture to stdout
//! wire-to-apdu-fixtures - < input.log   # stdin variant
//! ```
//!
//! Pure stdlib so the tool can be built with default features (no
//! pcsclite-dev / pcsc-sys involvement). Lives under `src/bin/` so
//! cargo auto-discovers it; not in fibby's library surface.

use std::fs;
use std::io::{self, Read};
use std::process;

fn main() {
    let mut args = std::env::args().skip(1);
    let arg = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: wire-to-apdu-fixtures <input.log>\n       wire-to-apdu-fixtures - < input.log"
        );
        process::exit(2);
    });

    let (source, input) = match arg.as_str() {
        "-" => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
                eprintln!("read stdin: {e}");
                process::exit(1);
            });
            ("<stdin>".to_string(), buf)
        }
        path => {
            let buf = fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("read {path}: {e}");
                process::exit(1);
            });
            (path.to_string(), buf)
        }
    };

    let pairs = extract_apdu_pairs(&input);

    let mut out = String::new();
    out.push_str("# fibby APDU fixture v1\n");
    out.push_str(&format!("# source: {source}\n"));
    out.push_str(&format!("# pairs: {}\n", pairs.len()));
    out.push('\n');
    for (i, (req, resp)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("> {}\n", to_hex(req)));
        out.push_str(&format!("< {}\n", to_hex(resp)));
    }

    print!("{out}");
}

/// Walk wire-log lines, group consecutive `[fibby:apdu>]` lines into a
/// request, consecutive `[fibby:apdu<]` lines into a response, emit
/// each `(request, response)` pair as a tuple. A new `[fibby:apdu>]`
/// after a response opens the next pair. Anything between APDU lines
/// (protocol-level rx/tx, info messages, blanks) is ignored.
pub fn extract_apdu_pairs(input: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut req: Vec<u8> = Vec::new();
    let mut resp: Vec<u8> = Vec::new();
    let mut last_dir: Option<Dir> = None;

    for line in input.lines() {
        let parsed = parse_apdu_line(line);
        let Some((dir, bytes)) = parsed else {
            continue;
        };

        match (last_dir, dir) {
            // First-ever line OR continuing the same direction: extend
            // the current accumulator.
            (None, Dir::Req) => req.extend_from_slice(&bytes),
            (None, Dir::Resp) => resp.extend_from_slice(&bytes),
            (Some(Dir::Req), Dir::Req) => req.extend_from_slice(&bytes),
            (Some(Dir::Resp), Dir::Resp) => resp.extend_from_slice(&bytes),
            // Request → response: keep building, the response will land
            // in the pair when the next request opens (or at EOF below).
            (Some(Dir::Req), Dir::Resp) => resp.extend_from_slice(&bytes),
            // Response → request: emit the just-finished pair, start
            // a fresh one. Skip emission if the prior request was empty
            // (defensive — shouldn't happen in well-formed logs).
            (Some(Dir::Resp), Dir::Req) => {
                if !req.is_empty() {
                    pairs.push((std::mem::take(&mut req), std::mem::take(&mut resp)));
                } else {
                    resp.clear();
                }
                req.extend_from_slice(&bytes);
            }
        }
        last_dir = Some(dir);
    }
    // EOF: emit the final pair if we have one.
    if !req.is_empty() {
        pairs.push((req, resp));
    }
    pairs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Req,
    Resp,
}

/// Parse a single hexdump line. Returns `Some((direction, bytes))`
/// when the line is an APDU hexdump fragment; `None` otherwise.
///
/// Expected shape:
///
/// ```text
/// [fibby:apdu>] 0000  00 a4 04 00 00 00 0b a0 00 00 03 08 00 00 10 00  |....|
/// ```
///
/// The offset, hex span, and ASCII gutter are all advisory; only the
/// hex span between offset and the trailing `|...|` matters.
fn parse_apdu_line(line: &str) -> Option<(Dir, Vec<u8>)> {
    let line = line.trim_start();
    let dir = if let Some(rest) = line.strip_prefix("[fibby:apdu>] ") {
        (Dir::Req, rest)
    } else if let Some(rest) = line.strip_prefix("[fibby:apdu<] ") {
        (Dir::Resp, rest)
    } else {
        return None;
    };
    let (dir, rest) = dir;

    // After the prefix: "OFFSET  HEX_BYTES  |ASCII|" or, on the last
    // hexdump line of a short payload, "OFFSET  HEX_BYTES  |ASCII|"
    // with shorter HEX. Split at the ASCII gutter first.
    let hex_span = match rest.find('|') {
        Some(idx) => &rest[..idx],
        None => rest, // tolerant: no gutter — take the whole rest
    };
    // Drop the offset (first whitespace-delimited token), keep the rest
    // as hex bytes.
    let mut tokens = hex_span.split_whitespace();
    let _offset = tokens.next()?;
    let bytes: Vec<u8> = tokens
        .map(|tok| u8::from_str_radix(tok, 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some((dir, bytes))
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_apdu_line_extracts_bytes_from_well_formed_hexdump() {
        let line = "[fibby:apdu>] 0000  00 a4 04 00 00 00 0b a0 00 00 03 08 00 00 10 00  |................|";
        let (dir, bytes) = parse_apdu_line(line).expect("should parse");
        assert_eq!(dir, Dir::Req);
        assert_eq!(
            bytes,
            vec![
                0x00, 0xa4, 0x04, 0x00, 0x00, 0x00, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00,
                0x10, 0x00
            ]
        );
    }

    #[test]
    fn parse_apdu_line_handles_short_last_line() {
        let line = "[fibby:apdu>] 0010  01 00 00 00                                      |....|";
        let (dir, bytes) = parse_apdu_line(line).expect("should parse");
        assert_eq!(dir, Dir::Req);
        assert_eq!(bytes, vec![0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn parse_apdu_line_handles_response_direction() {
        let line = "[fibby:apdu<] 0000  6a 82                                            |j.|";
        let (dir, bytes) = parse_apdu_line(line).expect("should parse");
        assert_eq!(dir, Dir::Resp);
        assert_eq!(bytes, vec![0x6a, 0x82]);
    }

    #[test]
    fn parse_apdu_line_rejects_non_apdu_lines() {
        assert!(parse_apdu_line("[fibby:rx] command=...").is_none());
        assert!(parse_apdu_line("[fibby:tx] 0000  04 00 00 00  |....|").is_none());
        assert!(parse_apdu_line("").is_none());
    }

    #[test]
    fn extract_apdu_pairs_groups_multi_line_request_and_response() {
        let log = "\
[fibby:apdu>] 0000  00 a4 04 00 0b a0 00 00 03 08 00 00 10 00 01 00  |................|
[fibby:apdu<] 0000  61 11 4f 06 00 00 10 00 01 00 79 07 4f 05 a0 00  |a.O.......y.O...|
[fibby:apdu<] 0010  00 03 08 90 00                                   |.....|
[fibby:apdu>] 0000  00 cb 3f ff 00 00 05 5c 03 5f c1 07 00 00        |..?....\\._....|
[fibby:apdu<] 0000  6a 82                                            |j.|
";
        let pairs = extract_apdu_pairs(log);
        assert_eq!(pairs.len(), 2);
        // Pair 0: SELECT PIV → FCI + 9000
        assert_eq!(pairs[0].0[0..2], [0x00, 0xa4]);
        assert_eq!(&pairs[0].1[pairs[0].1.len() - 2..], &[0x90, 0x00]);
        assert_eq!(pairs[0].1.len(), 21);
        // Pair 1: GET DATA → 6A82
        assert_eq!(pairs[1].0[0..2], [0x00, 0xcb]);
        assert_eq!(pairs[1].1, vec![0x6a, 0x82]);
    }

    #[test]
    fn extract_apdu_pairs_ignores_protocol_level_noise() {
        let log = "\
[fibby:rx] command=Some(Transmit) (0x09) size=32
[fibby:rx] 0000  01 00 00 00 02 00 00 00  |........|
[fibby:apdu>] 0000  00 a4 04 00                                      |....|
[fibby:apdu<] 0000  90 00                                            |..|
[fibby:tx] 0000  01 00 00 00  |....|
";
        let pairs = extract_apdu_pairs(log);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, vec![0x00, 0xa4, 0x04, 0x00]);
        assert_eq!(pairs[0].1, vec![0x90, 0x00]);
    }
}
