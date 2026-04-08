use crate::error::PivError;

/// BER-TLV tag/length/value reader.
///
/// Reads BER-TLV encoded data following ISO 7816-4 / PIV conventions.
/// Supports single-byte and multi-byte tags, and short/long length forms.
pub struct TlvReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> TlvReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a BER-TLV tag. Single-byte tags have their value directly.
    /// Multi-byte tags have the low 5 bits of the first byte all set (0x1F),
    /// followed by continuation bytes with bit 7 set, ending with a byte
    /// without bit 7.
    pub fn read_tag(&mut self) -> Result<u32, PivError> {
        if self.pos >= self.data.len() {
            return Err(PivError::Tlv {
                message: "read_tag called past end of data".into(),
            });
        }

        let first = self.data[self.pos];
        self.pos += 1;
        let mut tag = first as u32;

        // Check if lower 5 bits are all set -> multi-byte tag
        if (first & 0x1F) == 0x1F {
            loop {
                if self.pos >= self.data.len() {
                    return Err(PivError::Tlv {
                        message: "multi-byte tag continued past end of data".into(),
                    });
                }
                let b = self.data[self.pos];
                self.pos += 1;
                tag = (tag << 8) | (b as u32);
                // Continuation bit (bit 7) clear means this is the last byte
                if (b & 0x80) == 0 {
                    break;
                }
            }
        }

        Ok(tag)
    }

    /// Read a BER-TLV length and return the value bytes as a slice.
    ///
    /// Short form: single byte < 0x80 is the length directly.
    /// Long form: first byte is 0x80 | n where n is the number of
    /// subsequent bytes encoding the length (1-3 bytes supported).
    pub fn read_value(&mut self) -> Result<&'a [u8], PivError> {
        let len = self.read_length()?;
        if self.pos + len > self.data.len() {
            return Err(PivError::Tlv {
                message: format!(
                    "value length {} exceeds remaining data {}",
                    len,
                    self.data.len() - self.pos
                ),
            });
        }
        let value = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(value)
    }

    fn read_length(&mut self) -> Result<usize, PivError> {
        if self.pos >= self.data.len() {
            return Err(PivError::Tlv {
                message: "read_length called past end of data".into(),
            });
        }

        let first = self.data[self.pos];
        self.pos += 1;

        if (first & 0x80) == 0 {
            // Short form
            return Ok(first as usize);
        }

        // Long form: lower 7 bits = number of subsequent length bytes
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 3 {
            return Err(PivError::Tlv {
                message: format!("invalid length indicator: {} octets", num_bytes),
            });
        }
        if self.pos + num_bytes > self.data.len() {
            return Err(PivError::Tlv {
                message: format!(
                    "length bytes ({}) exceed remaining data ({})",
                    num_bytes,
                    self.data.len() - self.pos
                ),
            });
        }

        let mut len: usize = 0;
        for _ in 0..num_bytes {
            len = (len << 8) | (self.data[self.pos] as usize);
            self.pos += 1;
        }

        Ok(len)
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn has_remaining(&self) -> bool {
        self.pos < self.data.len()
    }
}

/// BER-TLV tag/length/value writer.
pub struct TlvWriter {
    buf: Vec<u8>,
}

impl TlvWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn write_tag_value(&mut self, tag: u32, value: &[u8]) {
        self.write_tag(tag);
        self.write_length(value.len());
        self.buf.extend_from_slice(value);
    }

    fn write_tag(&mut self, tag: u32) {
        // Encode tag as big-endian, skipping leading zero bytes
        if tag == 0 {
            self.buf.push(0);
            return;
        }

        let bytes = tag.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        self.buf.extend_from_slice(&bytes[start..]);
    }

    fn write_length(&mut self, len: usize) {
        if len < 0x80 {
            self.buf.push(len as u8);
        } else if len < 0x100 {
            self.buf.push(0x81);
            self.buf.push(len as u8);
        } else if len < 0x10000 {
            self.buf.push(0x82);
            self.buf.push((len >> 8) as u8);
            self.buf.push((len & 0xFF) as u8);
        } else if len < 0x1000000 {
            self.buf.push(0x83);
            self.buf.push((len >> 16) as u8);
            self.buf.push(((len >> 8) & 0xFF) as u8);
            self.buf.push((len & 0xFF) as u8);
        } else {
            panic!("TLV length too large: {}", len);
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for TlvWriter {
    fn default() -> Self {
        Self::new()
    }
}
