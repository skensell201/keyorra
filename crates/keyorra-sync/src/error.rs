use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Bytes that do not follow the format (bad magic, bad CBOR, wrong lengths, bad padding).
    #[error("malformed {0}")]
    Malformed(String),
    /// A newer format than this build understands; the caller keeps the bytes untouched.
    #[error("unsupported {0}")]
    Unsupported(String),
    #[error("decryption failed")]
    Decrypt,
    #[error("bad signature")]
    BadSignature,
    #[error("incorrect password or secret key")]
    WrongPassword,
    #[error(transparent)]
    Core(#[from] keyorra_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)] // used from Task 3 on
pub(crate) fn malformed(what: impl Into<String>) -> Error {
    Error::Malformed(what.into())
}
