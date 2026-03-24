use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("watcher error: {0}")]
    Watcher(String),
    #[error("assessment error: {0}")]
    Assessment(String),
    #[error("alert error: {0}")]
    Alert(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, ScannerError>;
