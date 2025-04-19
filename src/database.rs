use crate::encryption::{encrypt_with_random_nonce, generate_key};
use crate::hashing::hash;

use actix_web::dev::Response;
use dotenvy::var;
use std::collections::BTreeMap;
use std::error::Error;
use std::process::exit;
use subtle::ConstantTimeEq;
use surrealdb::{
    engine::local::{Db, RocksDb},
    sql::Value,
    Surreal,
};
use uuid::Uuid;

#[derive(Clone, Debug)]
struct SecretString(String);

impl SecretString {
    fn new(s: String) -> Self {
        SecretString(s)
    }
}

impl ConstantTimeEq for SecretString {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_bytes().ct_eq(other.0.as_bytes())
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Represents the database connection.
#[derive(Clone)]
pub struct Database {
    /// The SurrealDB database connection.
    pub db: Surreal<Db>,
}

impl Database {
    /// Creates a new database connection.
    pub async fn new() -> Self {
        // Get the database path from the environment variables.
        let database_path = var("DATABASE_PATH").unwrap_or("/database".to_string());
        // Connect to the database.
        let db = Surreal::new::<RocksDb>(database_path).await.unwrap();
        // Use the namespace and database from the environment variables.
        let database_namespace = var("DATABASE_NAMESPACE").unwrap_or("test".to_string());
        let database_name = var("DATABASE_NAME").unwrap_or("test".to_string());
        db.use_ns(&database_namespace)
            .use_db(&database_name)
            .await
            .unwrap();

        // Define a unique index on the users table.
        match db
            .query("DEFINE INDEX users_id ON users FIELDS id UNIQUE")
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("{}", error);
                exit(1);
            }
        };

        Database { db }
    }

    /// Registers a new user in the database.
    ///
    /// # Arguments
    ///
    /// * `firstname` - The user's first name.
    /// * `lastname` - The user's last name.
    /// * `username` - The user's username.
    /// * `password` - The user's password.
    /// * `email` - The user's email address.
    ///
    /// # Returns
    ///
    /// A result containing a success message or an error if registration fails.
    pub async fn register(
        &self,
        firstname: String,
        lastname: String,
        username: String,
        password: String,
        email: String,
    ) -> Result<String, Box<dyn Error>> {
        // Generate a new UUID for the user.
        let uuid = Uuid::new_v4().to_string();
        // Generate a new encryption key.
        let key = generate_key();
        let key_bytes: [u8; 32] = key.into();

        // Encrypt the user's personal information.
        let encrypted_firstname = encrypt_with_random_nonce(&key_bytes, &firstname);
        let encrypted_lastname = encrypt_with_random_nonce(&key_bytes, &lastname);
        let encrypted_email = encrypt_with_random_nonce(&key_bytes, &email);

        // Hash the password and email.
        let (password_hash, password_salt) = match hash(&password) {
            Ok(result) => result,
            Err(e) => return Err(From::from(e)),
        };

        let (email_hash, email_salt) = match hash(&email) {
            Ok(hash) => hash,
            Err(e) => return Err(From::from(e)),
        };

        // Create the SQL query.
        let sql = "CREATE users SET id = $id, encrypted_firstname = $encrypted_firstname, encrypted_lastname = $encrypted_lastname, username = $username, password_hash = $password_hash, password_salt = $password_salt, encrypted_email = $encrypted_email, email_hash = $email_hash, email_salt = $email_salt, created_at = time::now();";

        // Bind the parameters to the query.
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
        vars.insert("password_hash".into(), Value::from(password_hash.as_str()));
        vars.insert("password_salt".into(), Value::from(password_salt.as_str()));
        vars.insert(
            "encrypted_email".into(),
            Value::from(encrypted_email.as_str()),
        );
        vars.insert("email_hash".into(), Value::from(email_hash.as_str()));
        vars.insert("email_salt".into(), Value::from(email_salt.as_str()));

        // Execute the query.
        let created: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(vars)
            .await
            .map(|mut response| response.take(0).unwrap());

        // Return the result.
        match created {
            Ok(_) => Ok("User registered successfully".to_string()),
            Err(error) => Err(From::from(error)),
        }
    }

    /// Finds a user by their email hash.
    ///
    /// # Arguments
    ///
    /// * `email` - The user's email address.
    ///
    /// # Returns
    ///
    /// A result containing the user's data or an error if the user is not found.
    pub async fn find_user_by_email_hash(
        &self,
        email: String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        // Hash the email.
        let (email_hash, _) = match hash(&email) {
            Ok(hash) => hash,
            Err(e) => return Err(From::from(e)),
        };

        // Create the SQL query.
        let sql = "SELECT *, encrypted_firstname, encrypted_lastname, encrypted_email FROM users WHERE email_hash = $email_hash";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email_hash".into(), Value::from(email_hash.as_str()));

        // Execute the query.
        let found: Result<Vec<String>, surrealdb::Error> = self
            .db
            .query(sql)
            .bind(vars)
            .await
            .map(|mut response| response.take(0).unwrap());

        // Return the result.
        match found {
            Ok(user) => Ok(user),
            Err(error) => Err(From::from(error)),
        }
    }

    /// Authenticates a user.
    ///
    /// # Arguments
    ///
    /// * `email` - The user's email address.
    /// * `password` - The user's password.
    ///
    /// # Returns
    ///
    /// A result containing the user's data or an error if authentication fails.
    pub async fn authenticate_user(
        &self,
        email: String,
        password: String,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        // Hash the email.
        let (email_hash, _) = match hash(&email) {
            Ok(hash) => hash,
            Err(e) => return Err(From::from(e)),
        };

        // Create the SQL query.
        let sql = "SELECT *, encrypted_firstname, encrypted_lastname, encrypted_email, password_hash, password_salt FROM users WHERE email_hash = $email_hash";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email_hash".into(), Value::from(email_hash.as_str()));

        // Execute the query.
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

                let password_hash = user.get(4).map(|s| s.clone()).unwrap_or_default();
                let _password_salt = user.get(5).map(|s| s.clone()).unwrap_or_default();

                let (combined_password, _) =
                    hash(&password).map_err(|e| format!("Error hashing password: {}", e))?;

                if SecretString::new(combined_password)
                    .ct_eq(&SecretString::new(password_hash))
                    .into()
                {
                    Ok(user)
                } else {
                    Err(From::from("Invalid password".to_string()))
                }
            }
            Err(error) => Err(From::from(error)),
        }
    }
}
