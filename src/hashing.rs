use argon2::{
    password_hash::{
        rand_core::OsRng, Error as Argon2Error, PasswordHash, PasswordHashString, PasswordHasher,
        PasswordVerifier, SaltString,
    },
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
pub fn hash_random_salt(unhashed: &str) -> Result<PasswordHashString, Argon2Error> {
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
            let error: Box<dyn Error> = format!("Error hashing unhashed: {}", err).into();
            Argon2Error::Password
        })?
        .serialize();

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
