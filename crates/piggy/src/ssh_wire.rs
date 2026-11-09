//! SSH wire fields (RFC 4251 §5): the `uint32` and `string` encodings the
//! agent extensions and sshsig blobs are made of, written and read in one
//! place for the operator-act codec (`operator_act`) and the act seal
//! (`act::seal`).

/// Append a big-endian `uint32`.
pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Append a `string`: its length as a `uint32`, then the bytes.
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// A cursor over SSH wire fields. Every read is bounds-checked and answers
/// `None` on a short or malformed field, never panics.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    pub fn u32(&mut self) -> Option<u32> {
        let (head, tail) = self.rest.split_first_chunk::<4>()?;
        self.rest = tail;
        Some(u32::from_be_bytes(*head))
    }

    pub fn string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32()?).ok()?;
        if self.rest.len() < len {
            return None;
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Some(head)
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip_and_short_reads_are_none() {
        let mut out = Vec::new();
        put_u32(&mut out, 7);
        put_string(&mut out, b"abc");
        let mut reader = Reader::new(&out);
        assert_eq!(reader.u32(), Some(7));
        assert_eq!(reader.string(), Some(&b"abc"[..]));
        assert!(reader.is_empty());

        for cut in 0..out.len() {
            let mut reader = Reader::new(&out[..cut]);
            let whole = reader.u32().is_some() && reader.string().is_some();
            assert!(!whole, "a read past {cut} bytes succeeded");
        }
    }
}
