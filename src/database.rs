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

        let sql = "CREATE users SET id = $id, firstname = $firstname, lastname = $lastname, username = $username, password = $password, email = $email, email_hash = $email_hash, created_at = time::now();\nDEFINE INDEX users_id ON users FIELDS id UNIQUE;";

        let created: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(("id", uuid))
            .bind(("firstname", firstname))
            .bind(("lastname", lastname))
            .bind(("username", username))
            .bind(("password", hashed_password_result))
            .bind(("email", email))
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
            .query("SELECT * FROM users WHERE email_hash = $email_hash")
            .bind(("email_hash", email_hash))
            .await
            .map(|mut response| response.take(0).unwrap());

        match found {
            Ok(user) => Ok(user),
            Err(error) => Err(From::from(error)),
        }
    }
}
