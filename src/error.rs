use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
pub enum RelayError {
    Io(std::io::Error),
    Tls(tokio_native_tls::native_tls::Error),
    Handshake(String),
    Session(String),
    Connection(String),
    Timeout(String),
    InvalidConfig(String),
    PublishRejected(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Handshake(msg) => write!(f, "Handshake error: {msg}"),
            Self::Session(msg) => write!(f, "Session error: {msg}"),
            Self::Connection(msg) => write!(f, "Connection error: {msg}"),
            Self::Timeout(msg) => write!(f, "Timeout: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "Invalid config: {msg}"),
            Self::PublishRejected(msg) => write!(f, "Publish rejected: {msg}"),
            Self::Tls(error) => write!(f, "Tls on rtmps: {error}"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<std::io::Error> for RelayError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<tokio_native_tls::native_tls::Error> for RelayError {
    fn from(e: tokio_native_tls::native_tls::Error) -> Self {
        Self::Tls(e)
    }
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, RelayError>;
