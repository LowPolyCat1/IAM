#[cfg(test)]
pub mod tests;

use serde::{Deserialize, Serialize};

pub mod database;
pub mod encryption;
pub mod hashing;
pub mod logging;
pub mod server;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub encrypted_firstname: String,
    pub encrypted_lastname: String,
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub encrypted_email: String,
    pub email_hash: String,
    pub email_salt: String,
    pub created_at: String,
}
