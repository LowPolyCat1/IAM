//! src/database.rs
//!
//! This module handles database interactions for the IAM project, using SurrealDB.

use crate::encryption::{encrypt_with_random_nonce, generate_key};
use crate::hashing::{hash_random_salt, verify_password};

use dotenvy::var;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use std::process::exit;
use surrealdb::{
    engine::local::{Db, RocksDb},
    sql::Value,
    Surreal,
};
use uuid::Uuid;

/// Represents a user in the database.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    /// The user's ID.
    pub id: surrealdb::sql::Thing,
    /// The user's encrypted first name.
    pub encrypted_firstname: String,
    /// The user's encrypted last name.
    pub encrypted_lastname: String,
    /// The user's username.
    pub username: String,
    /// The user's password hash.
    pub password_hash: String,
    /// The user's encrypted email.
    pub encrypted_email: String,
    /// The user's email address.
    pub email: String,
    /// The user's creation timestamp.
    pub created_at: String,
}

/// Represents the database connection.
#[derive(Clone)]
pub struct Database {
    /// The SurrealDB database connection.
    pub db: Surreal<Db>,
}

use crate::errors::custom_errors::CustomError;

impl Database {
    /// Creates a new database connection.
    ///
    /// This function initializes a connection to the SurrealDB database using the path, namespace,
    /// and database name specified in the environment variables. It also defines a unique index
    /// on the `users` table for the `id` field.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new database connection or an error if the connection fails.
    ///
    /// # Errors
    ///
    /// Returns a `CustomError` if:
    /// - The `DATABASE_PATH`, `DATABASE_NAMESPACE`, or `DATABASE_NAME` environment variables are not set.
    /// - The connection to the database fails.
    /// - Defining the unique index on the `users` table fails.
    pub async fn new() -> Result<Self, crate::errors::custom_errors::CustomError> {
        // Get the database path from the environment variables.
        let database_path = match var("DATABASE_PATH") {
            Ok(database_path) => database_path,
            Err(error) => {
                tracing::error!("Error getting Database path: {}", error);
                exit(1);
            }
        };

        // Connect to the database.
        let db = Surreal::new::<RocksDb>(database_path)
            .await
            .map_err(|e| CustomError::DatabaseError(e.to_string()))?;
        // Use the namespace and database from the environment variables.
        let database_namespace =
            var("DATABASE_NAMESPACE").map_err(|e| CustomError::DatabaseError(e.to_string()))?;
        let database_name =
            var("DATABASE_NAME").map_err(|e| CustomError::DatabaseError(e.to_string()))?;

        db.use_ns(&database_namespace)
            .use_db(&database_name)
            .await
            .map_err(|e| CustomError::DatabaseError(e.to_string()))?;

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

        Ok(Database { db })
    }

    /// Registers a new user in the database.
    ///
    /// This function takes user details as input, encrypts sensitive information, hashes the password,
    /// and stores the user data in the database.
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
    /// A `Result` containing a boolean indicating success or failure.
    ///
    /// # Errors
    ///
    /// Returns a `CustomError` if:
    /// - A user with the given email already exists.
    /// - Encryption fails.
    /// - Hashing the password fails.
    /// - Creating the user in the database fails.
    pub async fn register(
        &self,
        firstname: String,
        lastname: String,
        username: String,
        password: String,
        email: String,
    ) -> Result<bool, crate::errors::custom_errors::CustomError> {
        tracing::info!("Registering user with email: {}", email);
        let sql = "SELECT * FROM users WHERE email = $email";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("email".into(), Value::from(email.as_str()));

        // Execute the query.
        let mut response = self.db.query(sql).bind(vars).await?;
        let mut users: Vec<User> = response.take(0)?;

        if let Some(_user) = users.pop() {
            tracing::warn!("User with email {} already exists", email);
            return Err(crate::errors::custom_errors::CustomError::UserAlreadyExists);
        }

        // Generate a new UUID for the user.
        let uuid = Uuid::new_v4().to_string();
        // Generate a new encryption key.
        let key = match generate_key() {
            Ok(key) => key,
            Err(error) => {
                tracing::error!("Couldn't get key: {}", error);
                return Err(error);
            }
        };
        let key_bytes: [u8; 32] = key.into();

        // Encrypt the user's personal information.
        let encrypted_firstname = encrypt_with_random_nonce(&key_bytes, &firstname)
            .map_err(|_| crate::errors::custom_errors::CustomError::EncryptionError)?;
        let encrypted_lastname = encrypt_with_random_nonce(&key_bytes, &lastname)
            .map_err(|_| crate::errors::custom_errors::CustomError::EncryptionError)?;
        let encrypted_email = encrypt_with_random_nonce(&key_bytes, &email)
            .map_err(|_| crate::errors::custom_errors::CustomError::EncryptionError)?;

        // Hash the password and email.
        let password_hash = match hash_random_salt(&password) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Error hashing password: {}", e);
                return Err(crate::errors::custom_errors::CustomError::HashingError);
            }
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
            Ok(_) => {
                tracing::info!("User registered successfully with email: {}", email);
                Ok(true)
            }
            Err(error) => {
                tracing::error!("Error creating user: {}", error);
                Err(crate::errors::custom_errors::CustomError::DatabaseError(
                    error.to_string(),
                ))
            }
        }
    }

    /// Authenticates a user.
    ///
    /// This function authenticates a user by verifying the provided email and password against the
    /// stored user data in the database.
    ///
    /// # Arguments
    ///
    /// * `email` - The user's email address.
    /// * `password` - The user's password.
    ///
    /// # Returns
    ///
    /// A `Result` containing the user's data or a `CustomError` if authentication fails.
    ///
    /// # Errors
    ///
    /// Returns a `CustomError` if:
    /// - The user is not found.
    /// - The password is invalid.
    pub async fn authenticate_user(
        &self,
        email: String,
        password: String,
    ) -> Result<User, crate::errors::custom_errors::CustomError> {
        tracing::info!("Authenticating user with email: {}", email);
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
                tracing::info!("User authenticated successfully with email: {}", email);
                Ok(user)
            } else {
                tracing::warn!("Invalid password for user with email: {}", email);
                Err(crate::errors::custom_errors::CustomError::InvalidPassword)
            }
        } else {
            tracing::warn!("User not found with email: {}", email);
            Err(crate::errors::custom_errors::CustomError::UserNotFound)
        }
    }

    /// Changes the username of a user.
    ///
    /// This function updates the username of an existing user in the database.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to update.
    /// * `new_username` - The new username.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    ///
    /// # Errors
    ///
    /// Returns a `CustomError` if:
    /// - The update operation fails.
    pub async fn change_username(
        &self,
        user_id: String,
        new_username: String,
    ) -> Result<(), crate::errors::custom_errors::CustomError> {
        // Create the SQL query.
        let sql = "UPDATE users SET username = $new_username WHERE id = $user_id;";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("user_id".into(), Value::from(user_id.as_str()));
        vars.insert("new_username".into(), Value::from(new_username.as_str()));

        // Execute the query.
        self.db.query(sql).bind(vars).await?;
        Ok(())
    }

    /// Changes the password of a user.
    ///
    /// This function updates the password of an existing user in the database.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to update.
    /// * `new_password` - The new password.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    ///
    /// # Errors
    ///
    /// Returns a `CustomError` if:
    /// - The update operation fails.
    pub async fn change_password(
        &self,
        user_id: String,
        new_password: String,
    ) -> Result<(), crate::errors::custom_errors::CustomError> {
        // Create the SQL query.
        let sql = "UPDATE users SET username = $new_password WHERE id = $user_id;";

        // Bind the parameters to the query.
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        vars.insert("user_id".into(), Value::from(user_id.as_str()));
        vars.insert("new_password".into(), Value::from(new_password.as_str()));

        // Execute the query.
        self.db.query(sql).bind(vars).await?;
        Ok(())
    }
}
