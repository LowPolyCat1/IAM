use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

use std::error::Error;

pub fn hash(unhashed: &str) -> Result<(String, String), Box<dyn Error>> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );

    let hashed_password = argon2
        .hash_password(unhashed.as_bytes(), &salt)
        .map_err(|err| format!("Error hashing unhashed: {}", err))?
        .to_string();

    Ok((hashed_password, salt.to_string()))
}
