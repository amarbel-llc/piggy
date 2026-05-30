//! pcsc-lite message framing over a byte stream (the `pcscd.comm`
//! Unix socket).
//!
//! Asymmetry worth remembering (winscard_msg.c):
//!
//! - **client → server**: an 8-byte `rxHeader { size, command }` then a
//!   `size`-byte body. Some commands (TRANSMIT, GET_ATTRIB) stream extra
//!   variable-length data *after* the fixed body, with no second header —
//!   the server knows to read it from the just-decoded struct.
//! - **server → client**: a *bare* body, no header. The client already
//!   knows the size it asked for, so the daemon never re-sends a header.
//!
//! These helpers keep that asymmetry explicit so the server code reads
//! the way the protocol actually works.

use std::io::{self, Read, Write};

use crate::proto::{HEADER_LEN, Header};

/// Reject absurd body sizes early. A real request body tops out around
/// `getset_struct` / extended APDU buffers (~64 KiB); 1 MiB is a generous
/// ceiling that still stops a malformed/hostile `size` from allocating
/// the address space.
pub const MAX_BODY: usize = 1024 * 1024;

/// Read one client→server message: the header plus its fixed body.
/// Returns `Ok(None)` on a clean EOF at the message boundary (client
/// disconnected), `Err` on a partial/short read or oversized body.
pub fn read_message(r: &mut impl Read) -> io::Result<Option<(Header, Vec<u8>)>> {
    let mut hbuf = [0u8; HEADER_LEN];
    match read_full(r, &mut hbuf)? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Short => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short read on rxHeader",
            ));
        }
        ReadOutcome::Full => {}
    }
    let header = Header::from_bytes(&hbuf).expect("HEADER_LEN bytes decode");
    let size = header.size as usize;
    if size > MAX_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("body size {size} exceeds MAX_BODY {MAX_BODY}"),
        ));
    }
    let mut body = vec![0u8; size];
    r.read_exact(&mut body)?;
    Ok(Some((header, body)))
}

/// Read exactly `n` more bytes (a command's trailing variable-length
/// payload, e.g. the TRANSMIT send buffer).
pub fn read_payload(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    if n > MAX_BODY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload size {n} exceeds MAX_BODY {MAX_BODY}"),
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Write a server→client response body (no header) and flush.
pub fn write_body(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    w.write_all(body)?;
    w.flush()
}

enum ReadOutcome {
    Full,
    Short,
    Eof,
}

/// Like `read_exact` but distinguishes a clean EOF-at-boundary (zero
/// bytes read) from a truncated read, so the caller can treat client
/// disconnects as normal rather than as errors.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    ReadOutcome::Eof
                } else {
                    ReadOutcome::Short
                });
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(ReadOutcome::Full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Command, VersionStruct};
    use std::io::Cursor;

    #[test]
    fn reads_header_and_body() {
        let ver = VersionStruct {
            major: 4,
            minor: 6,
            rv: 0,
        };
        let mut wire = Header {
            size: VersionStruct::WIRE_LEN as u32,
            command: Command::Version as u32,
        }
        .to_bytes()
        .to_vec();
        wire.extend_from_slice(&ver.to_bytes());
        let mut cur = Cursor::new(wire);
        let (h, body) = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(h.command, Command::Version as u32);
        assert_eq!(VersionStruct::from_bytes(&body), Some(ver));
    }

    #[test]
    fn clean_eof_is_none_not_error() {
        let mut empty = Cursor::new(Vec::new());
        assert!(read_message(&mut empty).unwrap().is_none());
    }

    #[test]
    fn oversized_body_is_rejected() {
        let wire = Header {
            size: (MAX_BODY + 1) as u32,
            command: Command::Transmit as u32,
        }
        .to_bytes();
        let mut cur = Cursor::new(wire.to_vec());
        assert!(read_message(&mut cur).is_err());
    }
}
