use crate::encryption::{encrypt_with_random_nonce, generate_key};
use crate::hashing::hash;

use dotenvy::var;
use std::collections::BTreeMap;
use std::error::Error;
use surrealdb::{
    engine::local::{Db, RocksDb},
    sql::Value,
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
        let uuid = Uuid::new_v4().to_string();
        let key = generate_key();
        let key_bytes: [u8; 32] = key.into();

        let encrypted_firstname = encrypt_with_random_nonce(&key_bytes, &firstname);
        let encrypted_lastname = encrypt_with_random_nonce(&key_bytes, &lastname);
        let encrypted_email = encrypt_with_random_nonce(&key_bytes, &email);

        let password_hash_and_salt = match hash(&password) {
            Ok(result) => result,
            Err(e) => return Err(From::from(e)),
        };

        let email_hash = match hash(&email) {
            Ok(hash) => hash,
            Err(e) => return Err(e),
        };

        let sql = "CREATE users SET id = $id, encrypted_firstname = $encrypted_firstname, encrypted_lastname = $encrypted_lastname, username = $username, password_hash_and_salt = $password_hash_and_salt, salt = $salt, encrypted_email = $encrypted_email, email_hash = $email_hash, created_at = time::now();";

        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("id".into(), Value::from(uuid.as_str()));
        vars.insert(
            "encrypted_firstname".into(),
            Value::from(encrypted_firstname.as_str()),
        );
        vars.insert(
            "encrypted_lastname".into(),
            Value::from(encrypted_lastname.as_str()),
        );
        vars.insert("username".into(), Value::from(username.as_str()));
        let (password_hash, salt) = password_hash_and_salt;
        vars.insert(
            "password_hash_and_salt".into(),
            Value::from(password_hash.as_str()),
        );
        vars.insert("salt".into(), Value::from(salt.as_str()));
        vars.insert(
            "encrypted_email".into(),
            Value::from(encrypted_email.as_str()),
        );
        vars.insert("email_hash".into(), Value::from(email_hash.0.as_str()));

        let created: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(vars)
            .await
            .map(|mut response| response.take(0).unwrap());

        let _: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query("DEFINE INDEX users_id ON users FIELDS id UNIQUE")
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
        let sql = "SELECT *, encrypted_firstname, encrypted_lastname, encrypted_email FROM users WHERE email_hash = $email_hash";

        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email_hash".into(), Value::from(email_hash.as_str()));

        let found: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(vars)
            .await
            .map(|mut response| response.take(0).unwrap());

        match found {
            Ok(user) => Ok(user),
            Err(error) => Err(From::from(error)),
        }
    }

    pub async fn authenticate_user(
        &self,
        email: String,
        password: String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let email_hash = match hash(&email) {
            Ok(hash) => hash,
            Err(e) => return Err(From::from(e)),
        };

        let sql = "SELECT *, encrypted_firstname, encrypted_lastname, encrypted_email, password_hash_and_salt, salt FROM users WHERE email_hash = $email_hash";

        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email_hash".into(), Value::from(email_hash.0.as_str()));

        let found: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(vars)
            .await
            .map(|mut response| response.take(0).unwrap());

        match found {
            Ok(user) => {
                if user.is_empty() {
                    return Err(From::from("User not found".to_string()));
                }

                let password_hash_and_salt = user.get(4).map(|s| s.clone()).unwrap_or_default();

                let (combined_password, _) = match hash(&password) {
                    Ok(result) => (result.0, result.1),
                    Err(e) => return Err(From::from(e)),
                };

                if combined_password == password_hash_and_salt {
                    Ok(user)
                } else {
                    Err(From::from("Invalid password".to_string()))
                }
            }
            Err(error) => Err(From::from(error)),
        }
    }
}
