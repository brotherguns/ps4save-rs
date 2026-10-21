use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid length for {what}: expected {expected}, got {got}")]
    InvalidLength {
        what: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("missing key: {0}")]
    MissingKey(String),

    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),

    #[error("invalid sealed key magic")]
    InvalidSealedKeyMagic,

    #[error("invalid sealed key digest")]
    InvalidSealedKeyDigest,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("{0}")]
    Message(String),
}
