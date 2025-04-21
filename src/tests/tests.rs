#[cfg(test)]
mod tests {
    use crate::encryption::{decrypt_with_nonce, encrypt_with_random_nonce, generate_key};
    use crate::hashing::{hash_random_salt, verify_password};
    use dotenvy::dotenv;
    use std::env;

    #[test]
    fn test_hashing() {
        let password = "password123";
        let hashed_password = hash_random_salt(password).unwrap();
        assert!(verify_password(password, &hashed_password).is_ok());
        assert!(verify_password("wrong_password", &hashed_password).is_err());
    }

    #[test]
    fn test_encryption() {
        dotenv().ok();
        let key = generate_key().unwrap();
        let key_bytes: [u8; 32] = key.into();
        let plaintext = "This is a secret message.";
        let encrypted = encrypt_with_random_nonce(&key_bytes, plaintext).unwrap();
        let decrypted = decrypt_with_nonce(&key_bytes, &encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encryption_key_length() {
        dotenv().ok();
        env::set_var("ENCRYPTION_KEY", "12345678901234567890123456789012");
        let key = generate_key().unwrap();
        let key_bytes: [u8; 32] = key.into();
        assert_eq!(key_bytes.len(), 32);
    }
}
