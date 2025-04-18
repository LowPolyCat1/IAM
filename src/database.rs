use argon2::{password_hash, Argon2, PasswordHasher};
use rand_core::{OsRng, TryRngCore};
use std::error::Error;
use surrealdb::{engine::remote::ws::Client, Surreal};

#[derive(Clone)]
pub struct Database {
    pub db: Surreal<Client>,
}

impl Database {
    pub async fn new() -> Self {
        let db = Surreal::new::<surrealdb::engine::remote::ws::Ws>("ws://localhost:8000")
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        Database { db }
    }

    pub async fn register(
        &self,
        username: String,
        password: String,
        email: String,
    ) -> Result<String, Box<dyn Error>> {
        let mut salt = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| format!("Error generating salt: {}", e))?;

        let salt = match password_hash::SaltString::encode_b64(&salt) {
            Ok(salt) => salt.to_string(),
            Err(e) => return Err(From::from(format!("Error encoding salt: {}", e))),
        };
        let argon2 = Argon2::default();

        let salt = password_hash::SaltString::new(&salt).unwrap();

        let hashed_password_result =
            match PasswordHasher::hash_password(&argon2, password.as_bytes(), &salt) {
                Ok(hash) => hash.to_string(),
                Err(err) => return Err(From::from(err)),
            };

        let created: Result<Vec<String>, surrealdb::Error> = self
        .db
        .query(
            "CREATE users SET username = $username, password = $password, email = $email, created_at = time::now()",
        )
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
