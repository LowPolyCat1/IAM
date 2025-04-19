use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use std::error::Error;

/// Hashes a password using Argon2id.
///
/// # Arguments
///
/// * `unhashed` - The data to hash.
///
/// # Returns
///
/// A result containing the hashed password and the salt, or an error if hashing fails.
pub fn hash(unhashed: &str) -> Result<(String, String), Box<dyn Error>> {
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
        .map_err(|err| format!("Error hashing unhashed: {}", err))?
        .to_string();

    // Return the hashed password and the salt.
    Ok((hashed_password, salt.to_string()))
}
