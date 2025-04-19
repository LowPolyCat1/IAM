use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use dotenvy::var;
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn hash_email(email: &String) -> Result<String, Box<dyn Error>> {
    let static_salt = match var("STATIC_SALT") {
        Ok(salt) => salt,
        Err(e) => {
            return Err(From::from(format!(
                "Error getting STATIC_SALT env variable: {}",
                e
            )))
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(static_salt.as_bytes());
    hasher.update(email.as_bytes());
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

pub fn hash_password(password: String) -> Result<(String, String), Box<dyn Error>> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(4096, 3, 1, None).unwrap(),
    );

    let hashed_password = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| format!("Error hashing password: {}", err))?
        .to_string();

    Ok((hashed_password, salt.to_string()))
}
