use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user ID)
    exp: usize,      // Expiration time (timestamp)
    iat: usize,      // Issued at (timestamp)
}

const SECRET_KEY_ENV: &str = "JWT_SECRET";

fn get_secret_key() -> String {
    env::var(SECRET_KEY_ENV).expect("JWT_SECRET not found in environment")
}

pub fn generate_jwt(user_id: String) -> Result<String, Error> {
    let secret_key = get_secret_key();
    let expiration = Utc::now()
        .checked_add_signed(Duration::days(1))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id,
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
    };

    let header = Header::default();
    let encoding_key = EncodingKey::from_secret(secret_key.as_bytes());
    encode(&header, &claims, &encoding_key)
}

pub fn validate_jwt(token: &str) -> Result<Claims, Error> {
    let secret_key = get_secret_key();
    let decoding_key = DecodingKey::from_secret(secret_key.as_bytes());

    let validation = Validation::default();
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;

    Ok(token_data.claims)
}

pub fn extract_user_id_from_jwt(token: &str) -> Result<String, Error> {
    let claims = validate_jwt(token)?;
    Ok(claims.sub)
}
