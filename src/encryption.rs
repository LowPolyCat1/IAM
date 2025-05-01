//! src/encryption.rs
//!
//! This module provides encryption and decryption functionalities using the ChaCha20Poly1305 algorithm.

use base64::{engine::general_purpose, Engine as base64Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use dotenvy::var;
use rand::rng;
use rand::RngCore;

use crate::errors::custom_errors::CustomError;

/// Generates a new encryption key.
///
/// # Returns
///
/// A `Result` containing the new key or a `CustomError` if an error occurs.
pub fn generate_key() -> Result<Key, CustomError> {
    let mut key = [0u8; 32];
    let encryption_key = match var("ENCRYPTION_KEY") {
        Ok(key) => key,
        Err(error) => {
            tracing::error!("couldn't find ENCRYPTION_KEY: {}", error);
            return Err(CustomError::EnvironmentVariableError(error.to_string()));
        }
    };
    let encryption_key_bytes = encryption_key.as_bytes();

    if encryption_key_bytes.len() != 32 {
        tracing::warn!(
            "ENCRYPTION_KEY has length {}, expected 32. Padding or truncating.",
            encryption_key_bytes.len()
        );
    }

    for i in 0..32 {
        if i < encryption_key_bytes.len() {
            key[i] = encryption_key_bytes[i];
        }
    }

    Ok(*Key::from_slice(&key))
}

/// Represents encrypted data with its corresponding nonce.
pub struct EncryptedData {
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption.
    pub nonce: Nonce,
}

/// Encrypts the given plaintext with the given key.
///
/// # Arguments
///
/// * `key` - The encryption key.
/// * `plaintext` - The plaintext to encrypt.
///
/// # Returns
///
/// A `Result` containing the encrypted data or an `EncryptionError` if an error occurs.
pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<EncryptedData, CustomError> {
    let nonce = generate_nonce();
    let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("Invalid key length");
    let ciphertext = aead
        .encrypt(&nonce, plaintext)
        .map_err(|_e| CustomError::EncryptionError)?;
    Ok(EncryptedData { ciphertext, nonce })
}

/// Decrypts the given ciphertext with the given key and nonce.
///
/// # Arguments
///
/// * `key` - The encryption key.
/// * `ciphertext` - The ciphertext to decrypt.
/// * `nonce` - The nonce used to encrypt the ciphertext.
///
/// # Returns
///
/// A `Result` containing the decrypted data or an `EncryptionError` if an error occurs.
pub fn decrypt(key: &Key, ciphertext: &[u8], nonce: &Nonce) -> Result<Vec<u8>, CustomError> {
    let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("Invalid key length");
    let decrypted_data = aead
        .decrypt(nonce, ciphertext)
        .map_err(|_e| CustomError::DecryptionError)?;
    Ok(decrypted_data)
}

/// Generates a new nonce (number used once) for encryption.
fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    // let mut rng = OsRng::new().expect("Failed to get OS random number generator");
    rng().fill_bytes(&mut nonce);
    *Nonce::from_slice(&nonce)
}

/// Encrypts the given plaintext with a random nonce and returns a base64-encoded string.
///
/// # Arguments
///
/// * `key_bytes` - The encryption key.
/// * `plaintext` - The plaintext to encrypt.
///
/// # Returns
///
/// A `Result` containing the base64-encoded string or an `EncryptionError` if an error occurs.
pub fn encrypt_with_random_nonce(
    key_bytes: &[u8; 32],
    plaintext: &str,
) -> Result<String, CustomError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    // let mut rng = OsRng::new().expect("Failed to get OS random number generator");
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CustomError::EncryptionError)?;

    // Combine nonce + ciphertext
    let mut combined = Vec::new();
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // Encode combined data as Base64 for storage
    Ok(general_purpose::STANDARD.encode(combined))
}

/// Decrypts the given base64-encoded string with the given key.
///
/// # Arguments
///
/// * `key_bytes` - The encryption key.
/// * `combined_base64` - The base64-encoded string to decrypt.
///
/// # Returns
///
/// A `Result` containing the decrypted string or an `EncryptionError` if an error occurs.
pub fn decrypt_with_nonce(
    key_bytes: &[u8; 32],
    combined_base64: &str,
) -> Result<String, CustomError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

    // Decode from Base64
    let combined = general_purpose::STANDARD
        .decode(combined_base64)
        .map_err(|_| CustomError::DecryptionError)?;

    // Split into nonce + ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CustomError::DecryptionError)?;

    String::from_utf8(plaintext_bytes).map_err(|_| CustomError::DecryptionError)
}
