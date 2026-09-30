//! Errors with the stable codes of the JSON API (§12.1) and exit codes (§10.3).

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    General,
    Usage,
    AccessDenied,
    NotFound,
    AlreadyExists,
    PasswordRequired,
    BadCredentials,
    WeakPassword,
    IdentityDisabled,
    UntrustedRoot,
    SignatureInvalid,
    UnauthorizedOperation,
    RollbackDetected,
    ForkDetected,
    StaleBelowPin,
    Offline,
    SyncContention,
    Conflict,
    UnsupportedSshKey,
    UnsupportedFormat,
    TemplateValidation,
    GitError,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::General => "GENERAL",
            Code::Usage => "USAGE",
            Code::AccessDenied => "ACCESS_DENIED",
            Code::NotFound => "NOT_FOUND",
            Code::AlreadyExists => "ALREADY_EXISTS",
            Code::PasswordRequired => "PASSWORD_REQUIRED",
            Code::BadCredentials => "BAD_CREDENTIALS",
            Code::WeakPassword => "WEAK_PASSWORD",
            Code::IdentityDisabled => "IDENTITY_DISABLED",
            Code::UntrustedRoot => "UNTRUSTED_ROOT",
            Code::SignatureInvalid => "SIGNATURE_INVALID",
            Code::UnauthorizedOperation => "UNAUTHORIZED_OPERATION",
            Code::RollbackDetected => "ROLLBACK_DETECTED",
            Code::ForkDetected => "FORK_DETECTED",
            Code::StaleBelowPin => "STALE_BELOW_PIN",
            Code::Offline => "OFFLINE",
            Code::SyncContention => "SYNC_CONTENTION",
            Code::Conflict => "CONFLICT",
            Code::UnsupportedSshKey => "UNSUPPORTED_SSH_KEY",
            Code::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Code::TemplateValidation => "TEMPLATE_VALIDATION",
            Code::GitError => "GIT_ERROR",
        }
    }

    /// Exit code (§10.3).
    pub fn exit_code(self) -> i32 {
        match self {
            Code::Usage => 2,
            Code::AccessDenied | Code::IdentityDisabled | Code::BadCredentials => 3,
            Code::UntrustedRoot
            | Code::SignatureInvalid
            | Code::UnauthorizedOperation
            | Code::RollbackDetected
            | Code::ForkDetected
            | Code::StaleBelowPin
            | Code::UnsupportedFormat => 4,
            Code::Offline | Code::GitError => 5,
            Code::Conflict | Code::SyncContention => 6,
            Code::PasswordRequired => 7,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: Code,
    pub message: String,
    pub details: Map<String, Value>,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Error {
            code,
            message: message.into(),
            details: Map::new(),
        }
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }

    pub fn general(m: impl Into<String>) -> Self {
        Self::new(Code::General, m)
    }
    pub fn usage(m: impl Into<String>) -> Self {
        Self::new(Code::Usage, m)
    }
    pub fn format(m: impl Into<String>) -> Self {
        Self::new(Code::UnsupportedFormat, m)
    }
    pub fn decrypt() -> Self {
        Self::new(Code::General, "decryption failed")
    }
    pub fn bad_credentials() -> Self {
        Self::new(Code::BadCredentials, "wrong password or passphrase")
    }
    pub fn access_denied(path: &str) -> Self {
        Self::new(Code::AccessDenied, format!("access denied: {path}")).with("path", path)
    }
    pub fn not_found(what: &str) -> Self {
        Self::new(Code::NotFound, format!("not found: {what}")).with("path", what)
    }
    pub fn unauthorized(m: impl Into<String>) -> Self {
        Self::new(Code::UnauthorizedOperation, m)
    }
    pub fn git(m: impl Into<String>) -> Self {
        Self::new(Code::GitError, m)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::general(format!("I/O error: {e}"))
    }
}
