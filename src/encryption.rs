use base64::{engine::general_purpose, Engine as base64Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use dotenvy::var;
use rand::rng;
use rand::RngCore;
use thiserror::Error;

use crate::errors::custom_errors::CustomError;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption error")]
    EncryptionError,
    #[error("Decryption error")]
    DecryptionError,
}

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

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
}

pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<EncryptedData, EncryptionError> {
    let nonce = generate_nonce();
    let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("Invalid key length");
    let ciphertext = aead
        .encrypt(&nonce, plaintext)
        .map_err(|_e| EncryptionError::EncryptionError)?;
    Ok(EncryptedData { ciphertext, nonce })
}

pub fn decrypt(key: &Key, ciphertext: &[u8], nonce: &Nonce) -> Result<Vec<u8>, EncryptionError> {
    let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("Invalid key length");
    let decrypted_data = aead
        .decrypt(nonce, ciphertext)
        .map_err(|_e| EncryptionError::DecryptionError)?;
    Ok(decrypted_data)
}

fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    // let mut rng = OsRng::new().expect("Failed to get OS random number generator");
    rng().fill_bytes(&mut nonce);
    *Nonce::from_slice(&nonce)
}

/// Encrypts data with a random nonce. Returns base64-encoded string (nonce + ciphertext).
pub fn encrypt_with_random_nonce(
    key_bytes: &[u8; 32],
    plaintext: &str,
) -> Result<String, EncryptionError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    // let mut rng = OsRng::new().expect("Failed to get OS random number generator");
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| EncryptionError::EncryptionError)?;

    // Combine nonce + ciphertext
    let mut combined = Vec::new();
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // Encode combined data as Base64 for storage
    Ok(general_purpose::STANDARD.encode(combined))
}

/// Decrypts base64-encoded (nonce + ciphertext) string.
pub fn decrypt_with_nonce(
    key_bytes: &[u8; 32],
    combined_base64: &str,
) -> Result<String, EncryptionError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

    // Decode from Base64
    let combined = general_purpose::STANDARD
        .decode(combined_base64)
        .map_err(|_| EncryptionError::DecryptionError)?;

    // Split into nonce + ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EncryptionError::DecryptionError)?;

    String::from_utf8(plaintext_bytes).map_err(|_| EncryptionError::DecryptionError)
}
