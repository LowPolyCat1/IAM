use thiserror::Error;

/// Custom error types for the application.
#[derive(Error, Debug)]
pub enum CustomError {
    /// Represents an unknown error.
    #[error("Unknown error occurred")]
    Unknown,
}
