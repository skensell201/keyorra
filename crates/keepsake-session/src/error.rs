use keepsake_core::Error as CoreError;
use serde::Serialize;

/// What the UI receives for a failed command: a stable `kind` to branch on, a message to show.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CmdError {
    pub kind: ErrorKind,
    pub message: String,
    /// Seconds until the next unlock attempt is allowed (only for `Throttled`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorKind {
    WrongPassword,
    Locked,
    Throttled,
    NotFound,
    Invalid,
    /// The database file is not a Keepsake database: offer "Start over".
    NotADatabase,
    /// Touch ID can't be used right now (off, expired, fingerprints changed): ask for the password.
    PasswordRequired,
    Other,
}

pub type CmdResult<T> = Result<T, CmdError>;

impl CmdError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn throttled(retry_after: u64) -> Self {
        Self {
            kind: ErrorKind::Throttled,
            message: format!("Too many attempts. Try again in {retry_after} s."),
            retry_after: Some(retry_after),
        }
    }
}

impl From<CoreError> for CmdError {
    fn from(e: CoreError) -> Self {
        let kind = match &e {
            CoreError::WrongPassword => ErrorKind::WrongPassword,
            CoreError::Locked => ErrorKind::Locked,
            CoreError::NotFound(_) => ErrorKind::NotFound,
            CoreError::Invalid(_) => ErrorKind::Invalid,
            CoreError::NotADatabase(_) => ErrorKind::NotADatabase,
            _ => ErrorKind::Other,
        };
        Self::new(kind, e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepsake_core::Error as CoreError;

    #[test]
    fn core_errors_map_to_kinds() {
        let cases = [
            (CoreError::WrongPassword, ErrorKind::WrongPassword),
            (CoreError::Locked, ErrorKind::Locked),
            (CoreError::NotFound("x".into()), ErrorKind::NotFound),
            (CoreError::Invalid("x".into()), ErrorKind::Invalid),
            (CoreError::Decrypt, ErrorKind::Other),
            (CoreError::Network("x".into()), ErrorKind::Other),
            (CoreError::NotADatabase("x".into()), ErrorKind::NotADatabase),
        ];
        for (core, kind) in cases {
            assert_eq!(CmdError::from(core).kind, kind);
        }
    }

    #[test]
    fn serializes_for_the_ui() {
        let json = serde_json::to_string(&CmdError::from(CoreError::WrongPassword)).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"wrongPassword","message":"incorrect password"}"#
        );
        let json = serde_json::to_value(CmdError::throttled(4)).unwrap();
        assert_eq!(json["kind"], "throttled");
        assert_eq!(json["retryAfter"], 4);
        assert_eq!(json["message"], "Too many attempts. Try again in 4 s.");
    }
}
