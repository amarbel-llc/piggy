use crate::error::{BoxError, Result};

pub struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(BoxError::Wire(format!(
                "need {} bytes at offset {}, only {} remain",
                n,
                self.pos,
                self.remaining()
            )));
        }
        Ok(())
    }

    pub fn get_u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        self.need(8)?;
        let v = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    /// `string8`: u8 length prefix + that many bytes.
    pub fn get_string8(&mut self) -> Result<Vec<u8>> {
        let len = self.get_u8()? as usize;
        self.need(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    /// `cstring8`: u8 length prefix (includes trailing NUL) + bytes + NUL.
    /// Returns the string without the NUL terminator.
    pub fn get_cstring8(&mut self) -> Result<String> {
        let raw = self.get_string8()?;
        if raw.is_empty() {
            return Err(BoxError::Wire("cstring8 is empty (no NUL)".into()));
        }
        if raw[raw.len() - 1] != 0 {
            return Err(BoxError::Wire("cstring8 missing NUL terminator".into()));
        }
        let s = &raw[..raw.len() - 1];
        if s.contains(&0u8) {
            return Err(BoxError::Wire("cstring8 contains interior NUL".into()));
        }
        String::from_utf8(s.to_vec())
            .map_err(|e| BoxError::Wire(format!("cstring8 not UTF-8: {e}")))
    }

    /// `eckey8`: u8 length prefix + compressed EC point bytes.
    pub fn get_eckey8(&mut self) -> Result<Vec<u8>> {
        self.get_string8()
    }

    /// `string`: u32 BE length prefix + that many bytes.
    pub fn get_string(&mut self) -> Result<Vec<u8>> {
        let len = self.get_u32()? as usize;
        self.need(len)?;
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
}

pub struct WireWriter {
    buf: Vec<u8>,
}

impl Default for WireWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl WireWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// `string8`: u8 length prefix + bytes.
    pub fn put_string8(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > 255 {
            return Err(BoxError::Wire(format!(
                "string8 too long: {} bytes",
                data.len()
            )));
        }
        self.buf.push(data.len() as u8);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// `cstring8`: u8 length prefix (includes trailing NUL) + bytes + NUL.
    pub fn put_cstring8(&mut self, s: &str) -> Result<()> {
        let with_nul_len = s.len() + 1;
        if with_nul_len > 255 {
            return Err(BoxError::Wire(format!(
                "cstring8 too long: {} bytes",
                with_nul_len
            )));
        }
        if s.as_bytes().contains(&0u8) {
            return Err(BoxError::Wire("cstring8 contains interior NUL".into()));
        }
        self.buf.push(with_nul_len as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    /// `eckey8`: u8 length prefix + compressed EC point bytes.
    pub fn put_eckey8(&mut self, point: &[u8]) -> Result<()> {
        self.put_string8(point)
    }

    /// `string`: u32 BE length prefix + bytes.
    pub fn put_string(&mut self, data: &[u8]) {
        self.put_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
    }

    /// Write raw bytes with no framing.
    pub fn put_raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}


pub(crate) fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    padded
}

pub(crate) fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(BoxError::BadPadding);
    }
    let pad_byte = data[data.len() - 1];
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > data.len() || pad_len > block_size {
        return Err(BoxError::BadPadding);
    }
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(BoxError::BadPadding);
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string8_roundtrip() {
        let mut w = WireWriter::new();
        w.put_string8(b"hello").unwrap();
        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_string8().unwrap(), b"hello");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn string8_empty() {
        let mut w = WireWriter::new();
        w.put_string8(b"").unwrap();
        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_string8().unwrap(), b"");
    }

    #[test]
    fn cstring8_roundtrip() {
        let mut w = WireWriter::new();
        w.put_cstring8("chacha20-poly1305").unwrap();
        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_cstring8().unwrap(), "chacha20-poly1305");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn cstring8_rejects_interior_nul() {
        let mut w = WireWriter::new();
        assert!(w.put_cstring8("bad\0string").is_err());
    }

    #[test]
    fn string_u32_roundtrip() {
        let mut w = WireWriter::new();
        let data = vec![0xAA; 300];
        w.put_string(&data);
        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_string().unwrap(), data);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn u8_u32_u64_roundtrip() {
        let mut w = WireWriter::new();
        w.put_u8(0x42);
        w.put_u32(0xDEADBEEF);
        w.put_u64(0x0102030405060708);
        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_u8().unwrap(), 0x42);
        assert_eq!(r.get_u32().unwrap(), 0xDEADBEEF);
        assert_eq!(r.get_u64().unwrap(), 0x0102030405060708);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reader_underflow() {
        let mut r = WireReader::new(&[0x01]);
        assert!(r.get_u32().is_err());
    }

    #[test]
    fn string8_overflow() {
        let mut w = WireWriter::new();
        assert!(w.put_string8(&[0u8; 256]).is_err());
    }

    #[test]
    fn eckey8_roundtrip() {
        let point = vec![0x03, 0xAA, 0xBB, 0xCC];
        let mut w = WireWriter::new();
        w.put_eckey8(&point).unwrap();
        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_eckey8().unwrap(), point);
    }

    #[test]
    fn mixed_fields_roundtrip() {
        let mut w = WireWriter::new();
        w.put_u8(0xB0);
        w.put_u8(0xC5);
        w.put_u8(0x02);
        w.put_cstring8("chacha20-poly1305").unwrap();
        w.put_cstring8("sha512").unwrap();
        w.put_string8(&[0xDD; 16]).unwrap();
        w.put_cstring8("nistp256").unwrap();
        w.put_eckey8(&[0x03; 33]).unwrap();
        w.put_eckey8(&[0x02; 33]).unwrap();
        w.put_string8(&[0x00; 12]).unwrap();
        w.put_string(&[0xFF; 48]);

        let mut r = WireReader::new(w.as_bytes());
        assert_eq!(r.get_u8().unwrap(), 0xB0);
        assert_eq!(r.get_u8().unwrap(), 0xC5);
        assert_eq!(r.get_u8().unwrap(), 0x02);
        assert_eq!(r.get_cstring8().unwrap(), "chacha20-poly1305");
        assert_eq!(r.get_cstring8().unwrap(), "sha512");
        assert_eq!(r.get_string8().unwrap(), vec![0xDD; 16]);
        assert_eq!(r.get_cstring8().unwrap(), "nistp256");
        assert_eq!(r.get_eckey8().unwrap(), vec![0x03; 33]);
        assert_eq!(r.get_eckey8().unwrap(), vec![0x02; 33]);
        assert_eq!(r.get_string8().unwrap(), vec![0x00; 12]);
        assert_eq!(r.get_string().unwrap(), vec![0xFF; 48]);
        assert_eq!(r.remaining(), 0);
    }
}
