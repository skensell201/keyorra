use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("incorrect password")]
    WrongPassword,
    #[error("decryption failed")]
    Decrypt,
    #[error("vault is locked")]
    Locked,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid data: {0}")]
    Invalid(String),
    /// The file exists but is not a Keepsake database (or is damaged beyond opening).
    #[error("not a keepsake database: {0}")]
    NotADatabase(String),
    #[error("network: {0}")]
    Network(String),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_password_message_is_generic() {
        assert_eq!(Error::WrongPassword.to_string(), "incorrect password");
    }
}
