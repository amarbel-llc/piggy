use thiserror::Error;

#[derive(Debug, Error)]
pub enum PivError {
    #[error("PCSC error: {0}")]
    Pcsc(#[from] pcsc::Error),

    #[error("TLV parse error: {message}")]
    Tlv { message: String },

    #[error("invalid GUID: {0}")]
    InvalidGuid(String),

    #[error("APDU error: SW={sw:#06x}")]
    Apdu { sw: u16 },

    #[error("card not found")]
    CardNotFound,

    #[error("no PIN provided")]
    NoPin,

    #[error("PIN incorrect, {retries} retries remaining")]
    PinIncorrect { retries: u32 },

    #[error("PIN required for this operation")]
    PinRequired,

    #[error("PIN is blocked")]
    PinBlocked,

    #[error("slot {0:#04x} not found or empty")]
    SlotEmpty(u8),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("OpenSSL error: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("{0}")]
    Other(String),
}
