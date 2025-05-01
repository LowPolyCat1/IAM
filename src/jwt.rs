//! src/jwt.rs
//!
//! This module provides JWT (JSON Web Token) generation and validation functionalities.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;

/// Represents the claims stored within a JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// The subject of the JWT (typically the user ID).
    pub sub: String,
    /// The expiration timestamp of the JWT.
    exp: usize,
    /// The issued at timestamp of the JWT.
    iat: usize,
}

const SECRET_KEY_ENV: &str = "JWT_SECRET";

/// Retrieves the secret key used for JWT signing and validation from the environment.
///
/// # Panics
///
/// This function panics if the `JWT_SECRET` environment variable is not set.
fn get_secret_key() -> String {
    env::var(SECRET_KEY_ENV).expect("JWT_SECRET not found in environment")
}

/// Generates a new JWT for the given user ID.
///
/// # Arguments
///
/// * `user_id` - The ID of the user to generate the JWT for.
///
/// # Returns
///
/// A `Result` containing the generated JWT or an error if generation fails.
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

/// Validates the given JWT.
///
/// # Arguments
///
/// * `token` - The JWT to validate.
///
/// # Returns
///
/// A `Result` containing the claims if the JWT is valid or an error if validation fails.
pub fn validate_jwt(token: &str) -> Result<Claims, Error> {
    let secret_key = get_secret_key();
    let decoding_key = DecodingKey::from_secret(secret_key.as_bytes());

    let validation = Validation::default();
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;

    Ok(token_data.claims)
}

/// Extracts the user ID from the given JWT.
///
/// # Arguments
///
/// * `token` - The JWT to extract the user ID from.
///
/// # Returns
///
/// A `Result` containing the user ID or an error if extraction fails.
pub fn extract_user_id_from_jwt(token: &str) -> Result<String, Error> {
    let claims = validate_jwt(token)?;
    Ok(claims.sub)
}
