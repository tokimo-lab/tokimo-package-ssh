use std::fmt;

/// Errors from SSH terminal operations.
#[derive(Debug)]
pub enum SshError {
    Connection(String),
    Auth(String),
    Channel(String),
    Exec(String),
    Parse(String),
    NotFound(String),
    BadInput(String),
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(msg) => write!(f, "SSH connection: {msg}"),
            Self::Auth(msg) => write!(f, "SSH auth: {msg}"),
            Self::Channel(msg) => write!(f, "SSH channel: {msg}"),
            Self::Exec(msg) => write!(f, "SSH exec: {msg}"),
            Self::Parse(msg) => write!(f, "parse: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::BadInput(msg) => write!(f, "bad input: {msg}"),
        }
    }
}

impl std::error::Error for SshError {}
