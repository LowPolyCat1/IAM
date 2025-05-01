//! src/hashing.rs
//!
//! This module provides password hashing and verification functionalities using the Argon2id algorithm.

use argon2::{
    password_hash::{
        rand_core::OsRng, Error as Argon2Error, PasswordHash, PasswordHasher, PasswordVerifier,
        SaltString,
    },
    Argon2,
};

use std::error::Error as StdError;

/// Hashes the given string with a random salt using Argon2.
///
/// # Arguments
///
/// * `unhashed` - The string to be hashed.
///
/// # Returns
///
/// A `Result` containing the hashed string or an `Argon2Error` if an error occurs.
pub fn hash_random_salt(unhashed: &str) -> Result<String, Argon2Error> {
    // Generate a random salt.
    let salt = SaltString::generate(&mut OsRng);

    // Configure Argon2id.
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );

    // Hash the password with the salt.
    let hashed_password = argon2
        .hash_password(unhashed.as_bytes(), &salt)
        .map_err(|err| {
            let _error: Box<dyn StdError> = format!("Error hashing unhashed: {}", err).into();
            Argon2Error::Password
        })?
        .to_string();

    // Return the hashed password and the salt.
    Ok(hashed_password)
}

/// Verifies a password against a password hash using Argon2id and constant-time comparison.
///
/// # Arguments
///
/// * `unhashed` - The unhashed password to verify.
/// * `password_hash` - The password hash to compare against.
///
/// # Returns
///
/// A result indicating whether the password is valid or an error if verification fails.
pub fn verify_password(unhashed: &str, password_hash: &str) -> Result<(), Argon2Error> {
    // Parse the password hash.
    let parsed_hash = PasswordHash::new(password_hash)?;

    // Verify password against hash using Argon2.
    let is_valid = Argon2::default().verify_password(unhashed.as_bytes(), &parsed_hash);

    // Compare the result in constant time to prevent timing attacks.
    match is_valid {
        Ok(_) => Ok(()),
        Err(_) => Err(Argon2Error::Password),
    }
}
