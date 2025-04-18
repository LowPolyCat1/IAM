use argon2::{password_hash, Argon2, PasswordHasher};
use dotenvy::var;
use rand_core::{OsRng, TryRngCore};
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
        let mut salt = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| format!("Error generating salt: {}", e))?;

        let salt_string = match password_hash::SaltString::encode_b64(&salt[..]) {
            Ok(salt) => salt.to_string(),
            Err(e) => return Err(From::from(format!("Error encoding salt: {}", e))),
        };

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(4096, 3, 1, None).unwrap(),
        );

        let salt = match password_hash::SaltString::from_b64(salt_string.as_str()) {
            Ok(salt) => salt,
            Err(e) => return Err(From::from(format!("Error decoding salt: {}", e))),
        };

        let hashed_password_result =
            match PasswordHasher::hash_password(&argon2, password.as_bytes(), &salt) {
                Ok(hash) => hash.to_string(),
                Err(err) => return Err(From::from(err)),
            };

        let uuid = Uuid::new_v4().to_string();

        let sql = "CREATE users SET id = $id, firstname = $firstname, lastname = $lastname, username = $username, password = $password, email = $email, created_at = time::now();\nDEFINE INDEX users_id ON users FIELDS id UNIQUE;";

        let created: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(("id", uuid))
            .bind(("firstname", firstname))
            .bind(("lastname", lastname))
            .bind(("username", username))
            .bind(("password", hashed_password_result))
            .bind(("email", email))
            .await
            .map(|mut response| response.take(0).unwrap());

        match created {
            Ok(_) => {
                return Ok("User registered successfully".to_string());
            }
            Err(error) => {
                return Err(From::from(error));
            }
        }
    }
}
