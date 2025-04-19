use crate::encryption::{encrypt_with_random_nonce, generate_key};
use crate::hashing::{hash_random_salt, verify_password};

use dotenvy::var;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;

use std::process::exit;
use surrealdb::{
    engine::local::{Db, RocksDb},
    sql::Value,
    Surreal,
};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: surrealdb::sql::Thing,
    pub encrypted_firstname: String,
    pub encrypted_lastname: String,
    pub username: String,
    pub password_hash: String,
    pub encrypted_email: String,
    pub email: String,
    pub created_at: String,
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
            Ok(_) => {}
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
    ) -> Result<bool, Box<dyn Error>> {
        let sql = "SELECT * FROM users WHERE email = $email";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email".into(), Value::from(email.as_str()));

        // Execute the query.
        let mut response = self.db.query(sql).bind(vars).await?;
        let mut users: Vec<User> = response.take(0)?;

        if let Some(_user) = users.pop() {
            return Err(From::from("User with that already Exists".to_string()));
        }

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
        let password_hash = match hash_random_salt(&password) {
            Ok(result) => result,
            Err(e) => return Err(From::from(e)),
        };

        // Create the SQL query.
        let sql = "CREATE users SET id = $id, encrypted_firstname = $encrypted_firstname, encrypted_lastname = $encrypted_lastname, username = $username, password_hash = $password_hash, encrypted_email = $encrypted_email, email = $email, created_at = time::now();";

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
        vars.insert(
            "encrypted_email".into(),
            Value::from(encrypted_email.as_str()),
        );
        vars.insert("email".into(), Value::from(email.as_str()));

        // Execute the query.
        let created: Result<surrealdb::Response, surrealdb::Error> =
            self.db.query(sql).bind(vars).await;

        // Return the result.
        match created {
            Ok(_) => Ok(true),
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
    ) -> Result<User, Box<dyn Error>> {
        // Hash the email.

        // Create the SQL query.
        let sql = "SELECT * FROM users WHERE email = $email";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email".into(), Value::from(email.as_str()));

        // Execute the query.
        let mut response = self.db.query(sql).bind(vars).await?;
        let mut users: Vec<User> = response.take(0)?;

        if let Some(user) = users.pop() {
            if verify_password(&password, &user.password_hash).is_ok() {
                Ok(user)
            } else {
                Err(From::from("Invalid password".to_string()))
            }
        } else {
            Err(From::from("User not found".to_string()))
        }
    }
}
