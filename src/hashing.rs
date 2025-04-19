use argon2::{password_hash, Argon2, PasswordHasher};
use base64::Engine;
use dotenvy::var;
use rand::rng;
use rand_core::RngCore;
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

pub fn hash_password(password: String, uuid: String) -> Result<String, Box<dyn Error>> {
    let salt = var("SALT").map_err(|e| format!("Error getting SALT env variable: {}", e))?;

    let combined_salt = format!("{}{}", salt, uuid);

    let engine = base64::engine::general_purpose::STANDARD;
    let encoded_salt = engine.encode(combined_salt.as_bytes());

    let salt = match password_hash::SaltString::from_b64(&encoded_salt) {
        Ok(salt) => salt,
        Err(e) => return Err(From::from(format!("Error encoding combined salt: {}", e))),
    };

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(4096, 3, 1, None).unwrap(),
    );

    let hashed_password_result =
        match PasswordHasher::hash_password(&argon2, password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(err) => return Err(From::from(err)),
        };

    let mut pepper = [0u8; 32];
    rng().fill_bytes(&mut pepper);
    let pepper_string = base64::engine::general_purpose::STANDARD.encode(pepper);

    let combined_password = format!("{}{}", hashed_password_result, pepper_string);

    Ok(combined_password)
}
