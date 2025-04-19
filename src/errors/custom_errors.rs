use thiserror::Error;

/// Custom error types for the application.
#[derive(Error, Debug)]
pub enum CustomError {
    /// Represents an unknown error.
    #[error("Unknown error occurred")]
    Unknown,
    /// Represents an error when a user already exists.
    #[error("User already exists")]
    UserAlreadyExists,
    /// Represents an error during hashing.
    #[error("Hashing error")]
    HashingError,
    /// Represents an encryption error.
    #[error("Encryption error")]
    EncryptionError,
    /// Represents a database error.
    #[error("Database error")]
    DatabaseError,
    /// Represents an invalid password error.
    #[error("Invalid password")]
    InvalidPassword,
    /// Represents a user not found error.
    #[error("User not found")]
    UserNotFound,
}

impl From<surrealdb::Error> for CustomError {
    fn from(error: surrealdb::Error) -> Self {
        tracing::error!("Database error: {}", error);
        CustomError::DatabaseError
    }
}
