#[cfg(test)]
mod hashing_tests {
    use crate::hashing::hash_random_salt;

    #[test]
    fn test_hash_password() {
        let password = "password".to_string();
        let result = hash_random_salt(&password);
        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(!hash.is_empty());
        assert!(!hash.is_empty());
    }
}

#[cfg(test)]
mod encryption_tests {
    use crate::encryption::{
        decrypt, decrypt_with_nonce, encrypt, encrypt_with_random_nonce, generate_key,
    };

    #[test]
    fn test_encrypt_decrypt() {
        let encryption_key_var_key = "ENCRYPTION_KEY";
        // Set the ENCRYPTION_KEY environment variable for testing
        let original_key = std::env::var(encryption_key_var_key);
        std::env::set_var(encryption_key_var_key, "test_encryption_key");

        let key = generate_key().unwrap();
        let plaintext = b"This is a secret message.";

        let encrypted_data = encrypt(&key, plaintext).unwrap();
        let decrypted_plaintext =
            decrypt(&key, &encrypted_data.ciphertext, &encrypted_data.nonce).unwrap();

        assert_eq!(plaintext, &decrypted_plaintext[..]);

        // Restore the original ENCRYPTION_KEY environment variable
        if let Ok(key) = original_key {
            std::env::set_var(encryption_key_var_key, key);
        } else {
            std::env::remove_var(encryption_key_var_key);
        }
    }

    #[test]
    fn test_encrypt_with_random_nonce_decrypt_with_nonce() {
        let encryption_key_var_key = "ENCRYPTION_KEY";
        // Set the ENCRYPTION_KEY environment variable for testing
        let original_key = std::env::var(encryption_key_var_key);
        std::env::set_var(encryption_key_var_key, "test_encryption_key");

        let key_bytes: [u8; 32] = [0u8; 32];
        let plaintext = "This is a secret message.";

        let encrypted = encrypt_with_random_nonce(&key_bytes, plaintext).unwrap();
        let decrypted = decrypt_with_nonce(&key_bytes, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);

        // Restore the original ENCRYPTION_KEY environment variable
        if let Ok(key) = original_key {
            std::env::set_var(encryption_key_var_key, key);
        } else {
            std::env::remove_var(encryption_key_var_key);
        }
    }
}
