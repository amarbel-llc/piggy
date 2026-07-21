//! Blech32 encoding — a modified BIP173 bech32 with `-` separator.
//!
//! Hand-ported from `go/internal/alfa/blech32/main.go` in
//! amarbel-llc/madder (commit 322b6cd at time of writing). The polymod
//! XOR target stays at `1` (BIP173-style), the charset and generator
//! are unchanged from BIP173, the only substantive difference is the
//! separator character.
//!
//! BIP173's 90-character total-length cap is **not** enforced (see
//! man markl-id(7) §3.6 / RFC 0002 §3.6).

use thiserror::Error;

/// Charset is the 32-character bech32 alphabet, excluding the visually
/// ambiguous `1`, `b`, `i`, `o`.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Separator — the **first** `-` in the string is the HRP/data divider.
///
/// Single-separator split (RFC 0011 §3.2, linenisgreat/madder#273 ruling
/// 9). Formerly the LAST `-`: with the HRP charset narrowed to
/// `[a-zA-Z0-9_]` (ruling 8) a well-formed string has exactly one `-`,
/// so a second one is a malformed input to REJECT rather than a still-
/// decodable string to guess at.
pub const SEPARATOR: char = '-';

/// BIP173 generator polynomial (also used by BIP350 bech32m, but we
/// keep the BIP173 polymod-XOR target of 1).
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Length of the trailing BCH checksum, in 5-bit groups.
const CHECKSUM_LEN: usize = 6;

/// Minimum length of the data portion: ≥1 payload + 6 checksum chars.
const DATA_PORTION_MIN: usize = 7;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("HRP must not be empty")]
    EmptyHrp,
    #[error("HRP contains invalid character at position {pos}: {char:?}")]
    InvalidHrpCharacter { pos: usize, char: char },
    #[error("string is mixed-case (markl-ids are lowercase only)")]
    MixedCase,
    /// All-uppercase input. RFC 0011 §3.5 (linenisgreat/madder#273
    /// ruling 6) narrows bech32's all-lower-or-all-upper rule to
    /// LOWERCASE ONLY, so uppercase is now its own rejection rather
    /// than an accepted alternate spelling. bech32 permits uppercase
    /// to enable QR alphanumeric mode, but that mode's charset (0-9,
    /// A-Z, space, `$%*+-./:`) has no lowercase, no `@`, and no `_` —
    /// a markl-id can never be QR-alphanumeric-encoded regardless of
    /// payload case, so the allowance buys nothing and costs one extra
    /// spelling per identifier.
    #[error("uppercase: markl-ids are lowercase only")]
    Uppercase,
    #[error("separator '{}' missing from input", SEPARATOR)]
    SeparatorMissing,
    #[error("data portion too short: need >= {expected}, got {actual}")]
    DataPortionTooShort { expected: usize, actual: usize },
    #[error("invalid character at position {pos}: {char:?}")]
    InvalidCharacterInData { pos: usize, char: char },
    #[error("checksum verification failed")]
    InvalidChecksum,
    #[error("invalid 5-bit value at position {pos}: {value} (max {max})")]
    InvalidDataRange { pos: usize, value: u8, max: u8 },
    #[error("non-zero padding in 5→8 bit conversion")]
    NonZeroPadding,
    #[error("illegal zero padding in 8→5 bit conversion")]
    IllegalZeroPadding,
}

pub type Result<T> = core::result::Result<T, Error>;

/// BCH polymod over the given 5-bit values. Returns the residue.
fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for i in 0..5 {
            if (top >> i) & 1 == 1 {
                chk ^= GENERATOR[i as usize];
            }
        }
    }
    chk
}

/// HRP expansion: each byte's top-3 bits, a separator zero, then each
/// byte's low-5 bits. Matches BIP173 exactly.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    if hrp.is_empty() {
        return Vec::new();
    }
    let lower: Vec<u8> = hrp.bytes().map(|c| c.to_ascii_lowercase()).collect();
    let mut out = Vec::with_capacity(lower.len() * 2 + 1);
    for &c in &lower {
        out.push(c >> 5);
    }
    out.push(0);
    for &c in &lower {
        out.push(c & 0x1f);
    }
    out
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

fn create_checksum(hrp: &str, data: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; CHECKSUM_LEN]);
    let polymod_v = polymod(&values) ^ 1;
    let mut out = [0u8; CHECKSUM_LEN];
    for (p, slot) in out.iter_mut().enumerate() {
        let shift = 5 * (5 - p);
        *slot = ((polymod_v >> shift) as u8) & 0x1f;
    }
    out
}

/// Convert between bit groupings, e.g. 8→5 (encode) or 5→8 (decode).
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>> {
    let max_v: u32 = (1u32 << to_bits) - 1;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity((data.len() * from_bits as usize).div_ceil(to_bits as usize));

    for (idx, &v) in data.iter().enumerate() {
        if (v as u32) >> from_bits != 0 {
            return Err(Error::InvalidDataRange {
                pos: idx,
                value: v,
                max: ((1u32 << from_bits) - 1) as u8,
            });
        }
        acc = (acc << from_bits) | u32::from(v);
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & max_v) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to_bits - bits)) & max_v) as u8);
        }
    } else if bits >= from_bits {
        return Err(Error::IllegalZeroPadding);
    } else if (acc << (to_bits - bits)) & max_v != 0 {
        return Err(Error::NonZeroPadding);
    }

    Ok(out)
}

/// Enforce RFC 0011 §3.5: lowercase only.
///
/// Formerly this classified the input as all-lower OR all-upper and let
/// the caller mirror that case in its output, matching bech32. Ruling 6
/// narrowed that to lowercase, so mixed case and all-uppercase are now
/// BOTH rejections — the first still as `MixedCase` (a distinct
/// malformation worth naming), the second as `Uppercase`.
fn validate_case(s: &str) -> Result<()> {
    let mut has_lower = false;
    let mut has_upper = false;
    for c in s.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        }
        if has_lower && has_upper {
            return Err(Error::MixedCase);
        }
    }
    if has_upper {
        return Err(Error::Uppercase);
    }
    Ok(())
}

/// Enforce RFC 0011 §3's HRP charset: `[a-zA-Z0-9_]`.
///
/// NARROWED (linenisgreat/madder#273 ruling 8) from printable ASCII
/// 33–126. The narrowing is what makes the separator unambiguous:
/// blech32 is bech32 with the HRP/data separator changed from `1` to
/// `-`, and that swap only works if `-` cannot itself occur in an HRP.
/// Under the old printable-ASCII rule it could, which is why the decoder
/// had to guess by taking the LAST `-`; see `SEPARATOR` and ruling 9.
///
/// Evidence the narrowing costs nothing: every format-id across piggy,
/// madder, and dodder uses `_` as its word separator, never `-`.
///
/// `A-Z` is admitted here (mirroring the Go reference) even though
/// `validate_case` independently rejects uppercase — the charset rule
/// and the case rule are separate constraints with separate errors.
fn validate_hrp(hrp: &str) -> Result<()> {
    for (pos, c) in hrp.char_indices() {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return Err(Error::InvalidHrpCharacter { pos, char: c });
        }
    }
    Ok(())
}

/// Encode `data` (8-bit bytes) under the human-readable part `hrp`.
/// Output is always lowercase (RFC 0011 §3.5); an uppercase `hrp` is a
/// rejection, not a request for uppercase output.
pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
    if hrp.is_empty() {
        return Err(Error::EmptyHrp);
    }
    validate_hrp(hrp)?;
    validate_case(hrp)?;

    let values_5bit = convert_bits(data, 8, 5, true)?;
    let checksum = create_checksum(hrp, &values_5bit);

    let mut out = String::with_capacity(hrp.len() + 1 + values_5bit.len() + CHECKSUM_LEN);
    out.push_str(hrp);
    out.push(SEPARATOR);
    for &v in &values_5bit {
        out.push(CHARSET[v as usize] as char);
    }
    for &v in &checksum {
        out.push(CHARSET[v as usize] as char);
    }

    Ok(out)
}

/// Decode a blech32 string. Returns `(hrp, data)` where `data` is the
/// raw 8-bit payload (without the checksum). Input must be lowercase.
pub fn decode(input: &str) -> Result<(String, Vec<u8>)> {
    validate_case(input)?;

    // First separator, not last — see `SEPARATOR`. Taking the last `-`
    // would silently accept `a-b-<data>` by treating `a-b` as the HRP;
    // `validate_hrp` now rejects that anyway, but only after the split
    // has already committed to the wrong boundary.
    let pos = input.find(SEPARATOR).ok_or(Error::SeparatorMissing)?;
    if pos < 1 {
        return Err(Error::EmptyHrp);
    }
    let data_str = &input[pos + 1..];
    if data_str.len() < DATA_PORTION_MIN {
        return Err(Error::DataPortionTooShort {
            expected: DATA_PORTION_MIN,
            actual: data_str.len(),
        });
    }

    let hrp = &input[..pos];
    validate_hrp(hrp)?;

    // `validate_case` already guaranteed the whole input is lowercase,
    // so HRP and data go into the checksum verbatim.
    let mut data_5bit = Vec::with_capacity(data_str.len());
    for (p, c) in data_str.char_indices() {
        let idx =
            CHARSET
                .iter()
                .position(|&x| x as char == c)
                .ok_or(Error::InvalidCharacterInData {
                    pos: p + pos + 1,
                    char: c,
                })?;
        data_5bit.push(idx as u8);
    }

    if !verify_checksum(hrp, &data_5bit) {
        return Err(Error::InvalidChecksum);
    }

    let payload_5bit = &data_5bit[..data_5bit.len() - CHECKSUM_LEN];
    let payload = convert_bits(payload_5bit, 5, 8, false)?;

    Ok((hrp.to_string(), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_payload_rejected_by_data_portion_minimum() {
        // An empty payload still emits a 6-char checksum, so the data
        // portion is exactly 6 chars — below the >=7 minimum. Decode
        // should reject.
        let encoded = encode("test", &[]).unwrap();
        // Confirm the encoded output has the form "test-XXXXXX"
        assert_eq!(encoded.len(), "test-".len() + CHECKSUM_LEN);
        let err = decode(&encoded).unwrap_err();
        assert!(
            matches!(err, Error::DataPortionTooShort { .. }),
            "expected DataPortionTooShort, got {err:?}"
        );
    }

    #[test]
    fn round_trip_one_byte() {
        let encoded = encode("x", &[0x42]).unwrap();
        let (hrp, data) = decode(&encoded).unwrap();
        assert_eq!(hrp, "x");
        assert_eq!(data, vec![0x42]);
    }

    #[test]
    fn round_trip_thirty_three_bytes() {
        // 33 bytes is the size of pivy_ecdh_p256_pub.
        let payload: Vec<u8> = (0..33u8).map(|i| i.wrapping_mul(7)).collect();
        let encoded = encode("pivy_ecdh_p256_pub", &payload).unwrap();
        let (hrp, data) = decode(&encoded).unwrap();
        assert_eq!(hrp, "pivy_ecdh_p256_pub");
        assert_eq!(data, payload);
    }

    #[test]
    fn mixed_case_rejected() {
        let err = decode("Test-qpzry9").unwrap_err();
        assert_eq!(err, Error::MixedCase);
    }

    #[test]
    fn missing_separator_rejected() {
        assert_eq!(decode("noseparator").unwrap_err(), Error::SeparatorMissing);
        // Also cover the all-charset case to confirm the separator search,
        // not something else, is the source of the rejection.
        assert_eq!(decode("abc").unwrap_err(), Error::SeparatorMissing);
    }

    #[test]
    fn invalid_charset_rejected() {
        // 'b' is not in the bech32 alphabet (deliberately excluded).
        let err = decode("test-bbbbbbb").unwrap_err();
        assert!(
            matches!(err, Error::InvalidCharacterInData { .. }),
            "expected InvalidCharacterInData, got {err:?}"
        );
    }

    #[test]
    fn flipped_checksum_byte_rejected() {
        let payload = b"hello world!";
        let encoded = encode("test", payload).unwrap();
        let mut bytes: Vec<char> = encoded.chars().collect();
        // Flip one charset entry to its neighbour in the alphabet to
        // produce a single-character substitution.
        let last = bytes.len() - 1;
        let original = bytes[last];
        let alt_idx =
            (CHARSET.iter().position(|&c| c as char == original).unwrap() + 1) % CHARSET.len();
        bytes[last] = CHARSET[alt_idx] as char;
        let mutated: String = bytes.into_iter().collect();
        let err = decode(&mutated).unwrap_err();
        assert_eq!(err, Error::InvalidChecksum);
    }

    #[test]
    fn upper_case_rejected_on_encode_and_decode() {
        // REVERSED by RFC 0011 §3.5 (linenisgreat/madder#273 ruling 6).
        // This test used to be `upper_case_round_trips_to_upper_case_output`
        // and asserted that an upper-case HRP produced upper-case output
        // which decoded back to the upper-case HRP (bech32's
        // all-lower-or-all-upper rule). Uppercase is now its own rejection.
        assert_eq!(encode("TEST", b"abc").unwrap_err(), Error::Uppercase);
        let lower = encode("test", b"abc").unwrap();
        assert_eq!(
            decode(&lower.to_ascii_uppercase()).unwrap_err(),
            Error::Uppercase
        );
    }

    #[test]
    fn empty_input_is_separator_missing() {
        // Truly empty: no separator to find.
        let err = decode("").unwrap_err();
        assert_eq!(err, Error::SeparatorMissing);
    }

    #[test]
    fn separator_only_is_empty_hrp() {
        // "-" — the separator is at index 0, so the HRP is empty.
        let err = decode("-").unwrap_err();
        assert_eq!(err, Error::EmptyHrp);
    }

    #[test]
    fn leading_separator_is_empty_hrp() {
        // Regression: "-a" / "-abc" are exactly what end up in piggy-ids
        // when a user typos `pass recipients add -a`. Before the variant
        // split, these resolved to SeparatorMissing with the literally-false
        // message "separator '-' missing from input".
        assert_eq!(decode("-a").unwrap_err(), Error::EmptyHrp);
        assert_eq!(decode("-abc").unwrap_err(), Error::EmptyHrp);
    }

    #[test]
    fn double_dash_hrp_resolves_to_empty_hrp() {
        // `--all-attachedc` is the exact regression input from a piggy
        // pass recipients add typo.
        //
        // REVERSED by madder#273 rulings 8 and 9. This test used to be
        // `double_dash_hrp_resolves_to_invalid_checksum` and asserted
        // InvalidChecksum: rfind picked the LAST '-', making the HRP the
        // non-empty "--all", which the old printable-ASCII 33-126
        // validate_hrp admitted, so failure only surfaced at checksum
        // verification. The forward hazard that comment flagged has now
        // happened: the first-separator split puts the boundary at index
        // 0, so this is an empty HRP.
        assert_eq!(decode("--all-attachedc").unwrap_err(), Error::EmptyHrp);
    }

    #[test]
    fn second_separator_in_data_portion_rejected() {
        // madder#273 ruling 9: a well-formed blech32 string has exactly
        // one '-'. The first-separator split leaves any further '-' in
        // the data portion, where it is outside the blech32 alphabet.
        let err = decode("a-qpzry9x-qpzry9x").unwrap_err();
        assert!(
            matches!(err, Error::InvalidCharacterInData { char: '-', .. }),
            "expected the second separator to be rejected as data, got {err:?}"
        );
    }

    #[test]
    fn hrp_charset_narrowed_to_alnum_underscore() {
        // madder#273 ruling 8: HRP is [a-zA-Z0-9_]. Under the former
        // printable-ASCII 33-126 rule '.' was an acceptable HRP char.
        let err = encode("a.b", b"abc").unwrap_err();
        assert_eq!(err, Error::InvalidHrpCharacter { pos: 1, char: '.' });
        assert!(encode("a_b9", b"abc").is_ok());
    }

    #[test]
    fn separator_at_end_is_data_portion_too_short() {
        // "a-" — HRP "a" is fine, data is empty (0 chars < 7 min).
        let err = decode("a-").unwrap_err();
        assert!(
            matches!(err, Error::DataPortionTooShort { actual: 0, .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn empty_hrp_message_does_not_claim_separator_missing() {
        // Regression: the original bug was that EmptyHrp and
        // SeparatorMissing returned the same variant, producing a
        // message that said "separator '-' missing" when in fact the
        // separator was present.
        let err = decode("-a").unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("missing"),
            "EmptyHrp must not be reported as missing-separator: {msg}"
        );
        assert!(
            msg.contains("empty") || msg.contains("HRP"),
            "EmptyHrp message should mention 'empty' or 'HRP': {msg}"
        );
    }

    #[test]
    fn long_input_no_90_char_cap() {
        // 64-byte payload (= ed25519_sec / sig size). Under BIP173's
        // 90-char cap this would be rejected; blech32 lifts the cap.
        let payload: Vec<u8> = (0..64u8).collect();
        let encoded = encode("ed25519_sec", &payload).unwrap();
        assert!(encoded.len() > 90);
        let (hrp, data) = decode(&encoded).unwrap();
        assert_eq!(hrp, "ed25519_sec");
        assert_eq!(data, payload);
    }
}
