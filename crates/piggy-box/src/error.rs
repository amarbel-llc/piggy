use thiserror::Error;

#[derive(Debug, Error)]
pub enum BoxError {
    #[error("wire format: {0}")]
    Wire(String),

    #[error("bad magic: expected {expected:#06x}, got {got:#06x}")]
    BadMagic { expected: u16, got: u16 },

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("unsupported KDF: {0}")]
    UnsupportedKdf(String),

    #[error("unsupported curve: {0}")]
    UnsupportedCurve(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("PKCS#7 padding invalid")]
    BadPadding,

    #[error("box not sealed")]
    NotSealed,

    #[error("box not opened")]
    NotOpened,

    #[error("ebox type invalid: {0}")]
    BadEboxType(u8),

    #[error("ebox config type invalid: {0}")]
    BadConfigType(u8),

    #[error("ebox not unlocked")]
    NotUnlocked,

    #[error("ebox already unlocked")]
    AlreadyUnlocked,

    #[error("no configs could be unlocked")]
    UnlockFailed,

    #[error("recovery threshold not met: have {have}, need {need}")]
    ThresholdNotMet { have: usize, need: usize },

    #[error("stream HMAC verification failed on chunk {seqnr}")]
    HmacMismatch { seqnr: u32 },

    #[error("stream sequence number mismatch: expected {expected}, got {got}")]
    SequenceMismatch { expected: u32, got: u32 },

    #[error("PIV: {0}")]
    Piv(#[from] piggy_piv::PivError),

    #[error("OpenSSL: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),

    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BoxError>;
