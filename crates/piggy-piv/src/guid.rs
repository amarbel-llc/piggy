use std::fmt;

use crate::error::PivError;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn from_hex(s: &str) -> Result<Self, PivError> {
        let bytes = hex::decode(s).map_err(|e| PivError::InvalidGuid(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PivError> {
        let arr: [u8; 16] = bytes.try_into().map_err(|_| {
            PivError::InvalidGuid(format!("expected 16 bytes, got {}", bytes.len()))
        })?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }

    pub fn short_id(&self) -> String {
        hex::encode_upper(&self.0[..4])
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self.to_hex())
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_id())
    }
}
