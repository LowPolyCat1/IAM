use crate::encryption::{encrypt_with_random_nonce, generate_key};
use crate::hashing::hash_email;
use argon2::{password_hash, Argon2, PasswordHasher};
use base64::Engine;
use dotenvy::var;
use std::error::Error;
use surrealdb::{
    engine::local::{Db, RocksDb},
    Surreal,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pub db: Surreal<Db>,
}

impl Database {
    pub async fn new() -> Self {
        let database_path = var("DATABASE_PATH").unwrap_or("/database".to_string());
        let db = Surreal::new::<RocksDb>(database_path).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        Database { db }
    }

    pub async fn register(
        &self,
        firstname: String,
        lastname: String,
        username: String,
        password: String,
        email: String,
    ) -> Result<String, Box<dyn Error>> {
        let salt = match var("SALT") {
            Ok(salt) => salt,
            Err(e) => {
                return Err(From::from(format!(
                    "Error getting SALT env variable: {}",
                    e
                )))
            }
        };

        let uuid = Uuid::new_v4().to_string();
        let key = generate_key(uuid.clone());
        let key_bytes: [u8; 32] = key.into();

        let encrypted_firstname = encrypt_with_random_nonce(&key_bytes, &firstname);
        let encrypted_lastname = encrypt_with_random_nonce(&key_bytes, &lastname);
        let encrypted_email = encrypt_with_random_nonce(&key_bytes, &email);

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

        let email_hash = match hash_email(&email) {
            Ok(hash) => hash,
            Err(e) => return Err(e),
        };

        let sql = "CREATE users SET id = $id, encrypted_firstname = $encrypted_firstname, encrypted_lastname = $encrypted_lastname, username = $username, password = $password, encrypted_email = $encrypted_email, email_hash = $email_hash, created_at = time::now();\nDEFINE INDEX users_id ON users FIELDS id UNIQUE;";

        let created: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(("id", uuid))
            .bind(("encrypted_firstname", encrypted_firstname))
            .bind(("encrypted_lastname", encrypted_lastname))
            .bind(("username", username))
            .bind(("password", hashed_password_result))
            .bind(("encrypted_email", encrypted_email))
            .bind(("email_hash", email_hash))
            .await
            .map(|mut response| response.take(0).unwrap());

        match created {
            Ok(_) => Ok("User registered successfully".to_string()),
            Err(error) => Err(From::from(error)),
        }
    }

    pub async fn find_user_by_email_hash(
        &self,
        email_hash: String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let found: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query("SELECT *, encrypted_firstname, encrypted_lastname, encrypted_email FROM users WHERE email_hash = $email_hash")
            .bind(("email_hash", email_hash))
            .await
            .map(|mut response| response.take(0).unwrap());

        match found {
            Ok(mut user) => {
                let uuid = user[0].clone();
                let key = generate_key(uuid.clone());
                let key_bytes: [u8; 32] = key.into();

                let encrypted_firstname = user.get(1).map(|s| s.clone()).unwrap_or_default();
                let encrypted_lastname = user.get(2).map(|s| s.clone()).unwrap_or_default();
                let encrypted_email = user.get(3).map(|s| s.clone()).unwrap_or_default();

                let firstname =
                    crate::encryption::decrypt_with_nonce(&key_bytes, &encrypted_firstname);
                let lastname =
                    crate::encryption::decrypt_with_nonce(&key_bytes, &encrypted_lastname);
                let email = crate::encryption::decrypt_with_nonce(&key_bytes, &encrypted_email);

                user[1] = firstname;
                user[2] = lastname;
                user[3] = email;

                Ok(user)
            }
            Err(error) => Err(From::from(error)),
        }
    }
}
