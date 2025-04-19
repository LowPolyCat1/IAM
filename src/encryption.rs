use chacha20poly1305::{
    aead::{Aead, Error, KeyInit},
    ChaCha20Poly1305,
    Key,
    Nonce, // Import the types you need
};
use rand::{rng, RngCore};

const ENCRYPTION_KEY: &str = "selFGAyJiaDuX3dauX2PeFFy6o8iX924JU4vh5isEC5aiECT23pfWCcw4u0nSQ3mNSsyySkoJrnxI79fEkQSUvAUBXSCp7RE4gpA";

pub fn generate_key(uuid: String) -> Key {
    let mut key = [0u8; 32];
    let encryption_key_bytes = ENCRYPTION_KEY.as_bytes();
    let uuid_bytes = uuid.as_bytes();

    for i in 0..32 {
        if i < encryption_key_bytes.len() {
            key[i] = encryption_key_bytes[i];
        }
    }

    for i in 0..(32 - encryption_key_bytes.len()).min(uuid_bytes.len()) {
        key[encryption_key_bytes.len() + i] = uuid_bytes[i];
    }

    *Key::from_slice(&key)
}

pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Nonce,
}

pub fn encrypt(key: &Key, plaintext: &[u8]) -> Result<EncryptedData, Error> {
    let nonce = generate_nonce();
    let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("Invalid key length");
    let ciphertext = aead.encrypt(&nonce, plaintext)?;
    Ok(EncryptedData { ciphertext, nonce })
}

pub fn decrypt(key: &Key, ciphertext: &[u8], nonce: &Nonce) -> Result<Vec<u8>, Error> {
    let aead = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("Invalid key length");
    let decrypted_data = aead.decrypt(nonce, ciphertext)?;
    Ok(decrypted_data)
}

fn generate_nonce() -> Nonce {
    let mut nonce = [0u8; 12];
    rng().fill_bytes(&mut nonce);
    *Nonce::from_slice(&nonce) // It is crucial to generate a unique nonce for each encryption operation, even with the same key, to ensure confidentiality.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000".to_string();
        let key = generate_key(uuid);
        let plaintext = b"This is a secret message.";

        let encrypted_data = encrypt(&key, plaintext).unwrap();
        let decrypted_plaintext =
            decrypt(&key, &encrypted_data.ciphertext, &encrypted_data.nonce).unwrap();

        assert_eq!(plaintext, &decrypted_plaintext[..]);
    }
}
