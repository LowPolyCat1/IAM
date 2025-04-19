#[cfg(test)]
mod hashing_tests {
    use crate::hashing::{hash_email, hash_password};

    #[test]
    fn test_hash_email() {
        // Set the STATIC_SALT environment variable for testing
        std::env::set_var("STATIC_SALT", "test_salt");

        let email = "test@example.com".to_string();
        let result = hash_email(&email);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert_eq!(hash.len(), 64); // SHA256 hash length is 64 characters
    }

    #[test]
    fn test_hash_password() {
        // Set the SALT environment variable for testing
        std::env::set_var("SALT", "test_salt");

        let password = "password".to_string();
        let uuid = "123e4567-e89b-12d3-a456-426614174000".to_string();
        let result = hash_password(password);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(!hash.0.is_empty());
        assert!(!hash.1.is_empty());
    }
}

#[cfg(test)]
mod encryption_tests {
    use crate::encryption::{
        decrypt, decrypt_with_nonce, encrypt, encrypt_with_random_nonce, generate_key,
    };

    #[test]
    fn test_encrypt_decrypt() {
        // Set the ENCRYPTION_KEY environment variable for testing
        std::env::set_var("ENCRYPTION_KEY", "test_encryption_key");

        let uuid = "123e4567-e89b-12d3-a456-426614174000".to_string();
        let key = generate_key(uuid);
        let plaintext = b"This is a secret message.";

        let encrypted_data = encrypt(&key, plaintext).unwrap();
        let decrypted_plaintext =
            decrypt(&key, &encrypted_data.ciphertext, &encrypted_data.nonce).unwrap();

        assert_eq!(plaintext, &decrypted_plaintext[..]);
    }

    #[test]
    fn test_encrypt_with_random_nonce_decrypt_with_nonce() {
        // Set the ENCRYPTION_KEY environment variable for testing
        std::env::set_var("ENCRYPTION_KEY", "test_encryption_key");

        let key_bytes: [u8; 32] = [0u8; 32];
        let plaintext = "This is a secret message.";

        let encrypted = encrypt_with_random_nonce(&key_bytes, plaintext);
        let decrypted = decrypt_with_nonce(&key_bytes, &encrypted);

        assert_eq!(plaintext, decrypted);
    }
}
