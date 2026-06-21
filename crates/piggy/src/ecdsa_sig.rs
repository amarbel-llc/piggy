//! Shared ECDSA signature reframing: DER `SEQUENCE { INTEGER r, INTEGER s }`
//! → either the raw fixed-width `r‖s` payload or the constituent `(r, s)`
//! integers.
//!
//! A PIV card returns an ECDSA signature as DER (`piggy_piv`
//! `PinSession::sign_prehash`). Two consumers need to reframe it:
//!
//! - the Rust agent (`cmd::agent::session`) wraps `(r, s)` into the SSH
//!   signature wire format;
//! - `piggy sign-bytes` emits the raw fixed-width `r‖s` markl payload
//!   (`…@ecdsa_p256_sig`, what a downstream markl consumer blech32-wraps).
//!
//! The bounds-checked DER parser lives here once so both share it. Errors
//! are plain `String` so the module stays decoupled from any caller's error
//! type (the agent maps them into `ssh_agent_lib::error::AgentError`).

/// Decode a DER-encoded ECDSA signature into `(r, s)` as big-endian byte
/// vectors (each as encoded in the DER INTEGER, i.e. possibly with a leading
/// `0x00` sign byte and possibly shorter than the field width).
///
/// DER format: `SEQUENCE { INTEGER r, INTEGER s }`.
///
/// Every bounds check is explicit — the card may return arbitrary bytes, and
/// a malformed length field (e.g. `r_len = 0xFF` on a short buffer) must be
/// rejected with an error, never cause an index-out-of-bounds panic.
///
/// Supports DER long-form SEQUENCE / INTEGER lengths (`0x81 LL`, `0x82 LL LL`)
/// so P-384 signatures at or beyond the short-form 0-127 threshold decode
/// correctly.
pub fn decode_der_ecdsa_signature(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Outer SEQUENCE tag.
    if der.first().copied() != Some(0x30) {
        return Err("invalid DER ECDSA signature: not a SEQUENCE".to_string());
    }

    // Parse SEQUENCE length and its header size (tag + length-of-length).
    let (seq_len, seq_hdr) = parse_der_length(&der[1..])?;
    let seq_start = 1 + seq_hdr;
    let seq_end = seq_start
        .checked_add(seq_len)
        .ok_or("DER SEQUENCE length overflows usize")?;
    if der.len() < seq_end {
        return Err("invalid DER ECDSA signature: truncated body".to_string());
    }

    let (r, after_r) = read_der_integer(der, seq_start, seq_end, "r")?;
    let (s, after_s) = read_der_integer(der, after_r, seq_end, "s")?;
    if after_s != seq_end {
        return Err("invalid DER ECDSA signature: trailing bytes after s".to_string());
    }

    Ok((r, s))
}

/// Decode a DER ECDSA signature and reframe it as the raw fixed-width `r‖s`
/// payload: `r` and `s` each left-padded (or stripped of a DER sign byte) to
/// exactly `field_len` big-endian bytes, concatenated (`2 * field_len` total).
///
/// `field_len` is the curve's field width: 32 for P-256, 48 for P-384.
pub fn der_to_raw_rs(der: &[u8], field_len: usize) -> Result<Vec<u8>, String> {
    let (r, s) = decode_der_ecdsa_signature(der)?;
    let mut out = Vec::with_capacity(field_len * 2);
    out.extend_from_slice(&fixed_width_be(&r, field_len, "r")?);
    out.extend_from_slice(&fixed_width_be(&s, field_len, "s")?);
    Ok(out)
}

/// Normalize a DER INTEGER's big-endian bytes to exactly `field_len`: drop a
/// leading `0x00` sign byte (DER adds one when the high bit is set to keep the
/// integer positive), then left-pad with zeros. Errors if the significant
/// bytes still exceed `field_len`.
fn fixed_width_be(int_bytes: &[u8], field_len: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut b = int_bytes;
    while b.len() > field_len && b[0] == 0x00 {
        b = &b[1..];
    }
    if b.len() > field_len {
        return Err(format!(
            "ECDSA {label} integer is {} bytes, exceeds field length {field_len}",
            b.len()
        ));
    }
    let mut out = vec![0u8; field_len];
    out[field_len - b.len()..].copy_from_slice(b);
    Ok(out)
}

/// Read a DER INTEGER `{ 0x02 len bytes }` starting at `pos`. Returns the
/// integer bytes and the position just past the integer. `end` caps the
/// enclosing SEQUENCE body so we never read past it.
fn read_der_integer(
    der: &[u8],
    pos: usize,
    end: usize,
    label: &str,
) -> Result<(Vec<u8>, usize), String> {
    if pos >= end {
        return Err(format!(
            "invalid DER ECDSA signature: missing INTEGER for {label}"
        ));
    }
    if der[pos] != 0x02 {
        return Err(format!("expected INTEGER tag for {label}"));
    }
    let (int_len, int_hdr) = parse_der_length(&der[pos + 1..end])?;
    let int_start = pos + 1 + int_hdr;
    let int_end = int_start
        .checked_add(int_len)
        .ok_or("DER INTEGER length overflows usize")?;
    if int_end > end {
        return Err(format!(
            "invalid DER ECDSA signature: {label} INTEGER length exceeds SEQUENCE"
        ));
    }
    Ok((der[int_start..int_end].to_vec(), int_end))
}

/// Parse a DER length prefix. Returns `(length, header_byte_count)` where
/// `header_byte_count` is 1 (short form), 2 (`0x81 LL`), or 3 (`0x82 LL LL`).
/// Rejects indefinite form (`0x80`) and lengths > `0x82` (longer than needed
/// for any realistic ECDSA signature).
fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize), String> {
    let first = *bytes.first().ok_or("DER length: missing length byte")?;
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        let b = *bytes.get(1).ok_or("DER length: truncated 0x81")?;
        // 0x81 MUST be used only for lengths >= 128; reject non-canonical encoding.
        if b < 0x80 {
            return Err("DER length: non-canonical 0x81 short length".to_string());
        }
        Ok((b as usize, 2))
    } else if first == 0x82 {
        let hi = *bytes.get(1).ok_or("DER length: truncated 0x82")?;
        let lo = *bytes.get(2).ok_or("DER length: truncated 0x82")?;
        // 0x82 MUST be used only for lengths >= 256.
        if hi == 0 {
            return Err("DER length: non-canonical 0x82 encoding".to_string());
        }
        Ok((u16::from_be_bytes([hi, lo]) as usize, 3))
    } else {
        Err(format!("DER length: unsupported form 0x{first:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `SEQUENCE { INTEGER r, INTEGER s }` from raw integer byte slices
    /// (caller supplies the exact DER INTEGER body, sign byte included).
    fn der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(0x02);
        body.push(r.len() as u8);
        body.extend_from_slice(r);
        body.push(0x02);
        body.push(s.len() as u8);
        body.extend_from_slice(s);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        der
    }

    #[test]
    fn decode_minimal_valid() {
        let der = der_sig(&[0x01], &[0x02]);
        let (r, s) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(r, vec![0x01]);
        assert_eq!(s, vec![0x02]);
    }

    #[test]
    fn decode_rejects_non_sequence() {
        let err = decode_der_ecdsa_signature(&[0x31, 0x00]).unwrap_err();
        assert!(err.contains("not a SEQUENCE"));
    }

    #[test]
    fn der_to_raw_rs_pads_short_integers_to_field_len() {
        // r = 0x01, s = 0x02 → each left-padded to 32 bytes, 64 total.
        let der = der_sig(&[0x01], &[0x02]);
        let raw = der_to_raw_rs(&der, 32).unwrap();
        assert_eq!(raw.len(), 64);
        let mut want = vec![0u8; 64];
        want[31] = 0x01;
        want[63] = 0x02;
        assert_eq!(raw, want);
    }

    #[test]
    fn der_to_raw_rs_strips_der_sign_byte() {
        // A 33-byte INTEGER with a leading 0x00 sign byte (high bit set in the
        // next byte) must drop the sign byte to fit a 32-byte field.
        let mut r = vec![0x00];
        r.extend_from_slice(&[0xFF; 32]); // 0x00 || 32 bytes
        let s = vec![0xAB; 32];
        let der = der_sig(&r, &s);
        let raw = der_to_raw_rs(&der, 32).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..32], &[0xFF; 32]);
        assert_eq!(&raw[32..], &[0xAB; 32]);
    }

    #[test]
    fn der_to_raw_rs_full_width_integers() {
        let r = vec![0x11; 32];
        let s = vec![0x22; 32];
        let der = der_sig(&r, &s);
        let raw = der_to_raw_rs(&der, 32).unwrap();
        assert_eq!(&raw[..32], r.as_slice());
        assert_eq!(&raw[32..], s.as_slice());
    }

    #[test]
    fn der_to_raw_rs_rejects_oversized_integer() {
        // A 33-byte integer whose first byte is NOT a 0x00 sign byte cannot
        // fit a 32-byte field.
        let r = vec![0x7F; 33];
        let s = vec![0x01; 32];
        let der = der_sig(&r, &s);
        let err = der_to_raw_rs(&der, 32).unwrap_err();
        assert!(err.contains("exceeds field length"), "got: {err}");
    }

    #[test]
    fn der_to_raw_rs_p384_field_width() {
        let r = vec![0x11; 48];
        let s = vec![0x22; 48];
        let der = der_sig(&r, &s);
        let raw = der_to_raw_rs(&der, 48).unwrap();
        assert_eq!(raw.len(), 96);
    }

    #[test]
    fn decode_never_panics_on_malformed_input() {
        // Exhaustive small fuzz: every short byte string must Ok or Err, never
        // panic. Mirrors the agent's original guard for the moved parser.
        for len in 0..=6usize {
            let mut buf = vec![0u8; len];
            // a few patterns per length
            for fill in [0x00u8, 0x30, 0x02, 0xFF, 0x81, 0x82] {
                buf.iter_mut().for_each(|b| *b = fill);
                let _ = decode_der_ecdsa_signature(&buf);
            }
        }
    }
}
