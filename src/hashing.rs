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
