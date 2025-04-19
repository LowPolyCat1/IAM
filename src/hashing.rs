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
pub fn hash_random_salt(unhashed: &str) -> Result<(String, String), Box<dyn Error>> {
    // Generate a random salt.
    let salt = SaltString::generate(&mut OsRng).to_string();

    let hashed_password = hash_with_salt(unhashed, &salt)?;

    // Return the hashed password and the salt.
    Ok((hashed_password, salt))
}

pub fn hash_with_salt(unhashed: &str, salt: &str) -> Result<String, Box<dyn Error>> {
    // Configure Argon2id.
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );

    // Hash the password with the salt.
    let salt_string = argon2::password_hash::SaltString::from_b64(salt)
        .map_err(|err| format!("Error creating salt string: {}", err))?;

    let hashed_password = argon2
        .hash_password(unhashed.as_bytes(), &salt_string)
        .map_err(|err| format!("Error hashing data: {}", err))?
        .to_string();

    // Return the hashed password.
    Ok(hashed_password)
}
