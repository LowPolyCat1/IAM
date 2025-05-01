//! src/errors/custom_errors.rs
//!
//! This module defines custom error types for the IAM project.

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
    /// Represents an decryption error.
    #[error("Decryption error")]
    DecryptionError,
    /// Represents a database error.
    #[error("Database error: {0}")]
    DatabaseError(String),
    /// Represents an invalid password error.
    #[error("Invalid password")]
    InvalidPassword,
    /// Represents a user not found error.
    #[error("User not found")]
    UserNotFound,
    /// Represents an error during tracing initialization.
    #[error("Tracing initialization error: {0}")]
    TracingInitializationError(String),
    /// Represents an error during Actix Web binding.
    #[error("Actix Web binding error: {0}")]
    ActixWebBindingError(String),
    /// Represents an error during Actix Web runtime.
    #[error("Actix Web runtime error: {0}")]
    ActixWebRuntimeError(String),
    /// Represents an error loading environment variables.
    #[error("Environment variable error: {0}")]
    EnvironmentVariableError(String),
    #[error("Environment variable error: {0}")]
    ParsingServerPortError(String),
    #[error("Environment variable error: {0}")]
    GovernorCreationError(String),
}

impl From<surrealdb::Error> for CustomError {
    fn from(error: surrealdb::Error) -> Self {
        tracing::error!("Database error: {}", error);
        CustomError::DatabaseError(error.to_string())
    }
}

impl From<dotenvy::Error> for CustomError {
    fn from(error: dotenvy::Error) -> Self {
        tracing::error!("dotenvy error: {}", error);
        CustomError::EnvironmentVariableError(error.to_string())
    }
}

impl From<actix_web::Error> for CustomError {
    fn from(error: actix_web::Error) -> Self {
        tracing::error!("Actix Web error: {}", error);
        CustomError::ActixWebRuntimeError(error.to_string())
    }
}
