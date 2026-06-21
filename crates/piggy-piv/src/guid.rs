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

    /// True for the all-zeros GUID, i.e. a factory-blank / uninitialized PIV
    /// card (one with no CHUID). See `PivToken::connect_allowing_uninitialized`.
    pub fn is_all_zeros(&self) -> bool {
        self.0 == [0u8; 16]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_all_zeros_true_for_blank_guid() {
        assert!(Guid::from_bytes(&[0u8; 16]).unwrap().is_all_zeros());
    }

    #[test]
    fn is_all_zeros_false_when_any_byte_set() {
        let mut b = [0u8; 16];
        b[15] = 1;
        assert!(!Guid::from_bytes(&b).unwrap().is_all_zeros());
    }
}
