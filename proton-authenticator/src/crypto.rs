use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[derive(Clone, Debug)]
pub enum EncryptionTag {
    Entry,
    Unknown,
}

impl EncryptionTag {
    pub fn aad(&self) -> Vec<u8> {
        match self {
            EncryptionTag::Entry => b"entrycontent".to_vec(),
            EncryptionTag::Unknown => vec![],
        }
    }
}

const KEY_LENGTH: usize = 32;

pub fn generate_encryption_key() -> Vec<u8> {
    random_bytes(KEY_LENGTH)
}

pub fn encrypt(data: &[u8], key: &[u8], tag: EncryptionTag) -> Result<Vec<u8>, aes_gcm::Error> {
    // Initialize cipher from the 32-byte key.
    let cipher = Aes256Gcm::new(key.into());

    // Generate a random 12-byte nonce.
    let nonce_bytes = random_bytes(12);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data with the given AAD (or empty slice if None).
    let aad = tag.aad();
    let payload = Payload { msg: data, aad: &aad };
    let ciphertext = cipher.encrypt(nonce, payload)?;

    // Prepend nonce to the ciphertext.
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], tag: EncryptionTag) -> Result<Vec<u8>, aes_gcm::Error> {
    // Check that the ciphertext is at least large enough to contain the nonce.
    if ciphertext.len() < 12 {
        return Err(aes_gcm::Error);
    }

    // Extract nonce and actual ciphertext.
    let (nonce_bytes, cipherdata) = ciphertext.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let aad = tag.aad();
    let payload = Payload {
        msg: cipherdata,
        aad: &aad,
    };
    cipher.decrypt(nonce, payload)
}

fn random_bytes(count: usize) -> Vec<u8> {
    let mut random_bytes = vec![0; count];
    let mut rng = StdRng::from_os_rng();
    rng.fill_bytes(&mut random_bytes);
    random_bytes.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod key {
        use super::*;

        #[test]
        fn key_has_the_correct_length() {
            let key = generate_encryption_key();
            assert_eq!(key.len(), KEY_LENGTH);
        }
    }

    mod encryption {
        use super::*;

        #[test]
        fn test_encrypt_decrypt_with_aad() {
            let key = generate_encryption_key();
            let data = b"Secret message!";
            let aad = EncryptionTag::Entry;
            let ciphertext = encrypt(data, &key, aad.clone()).expect("encryption failed");
            let plaintext = decrypt(&ciphertext, &key, aad).expect("decryption failed");
            assert_eq!(data.to_vec(), plaintext);
        }

        #[test]
        fn test_wrong_key() {
            let key = generate_encryption_key();
            let wrong_key = generate_encryption_key();
            let data = b"Message to protect";
            let aad = EncryptionTag::Entry;
            let ciphertext = encrypt(data, &key, aad.clone()).expect("encryption failed");
            assert!(decrypt(&ciphertext, &wrong_key, aad).is_err());
        }

        #[test]
        fn test_wrong_aad() {
            let key = generate_encryption_key();
            let data = b"Message to protect";
            let ciphertext = encrypt(data, &key, EncryptionTag::Entry).expect("encryption failed");
            assert!(decrypt(&ciphertext, &key, EncryptionTag::Unknown).is_err());
        }

        #[test]
        fn test_tampered_ciphertext() {
            let key = generate_encryption_key();
            let data = b"Tamper me if you can";
            let aad = EncryptionTag::Entry;
            let mut ciphertext = encrypt(data, &key, aad.clone()).expect("encryption failed");
            // Flip one byte in the ciphertext (do not tamper with the nonce).
            if ciphertext.len() > 12 {
                ciphertext[15] ^= 0xff;
            }
            assert!(decrypt(&ciphertext, &key, aad).is_err());
        }

        #[test]
        fn test_invalid_ciphertext_length() {
            let key = generate_encryption_key();
            let invalid_ciphertext = b"short";
            assert!(decrypt(invalid_ciphertext, &key, EncryptionTag::Entry).is_err());
        }
    }
}
