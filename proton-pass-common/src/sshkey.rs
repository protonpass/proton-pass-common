use proton_pass_derive::{ffi_type, Error};
use ssh_key::private::{Ed25519Keypair, RsaKeypair};
use ssh_key::rand_core::OsRng;
use ssh_key::{LineEnding, PrivateKey, PublicKey};

#[derive(Debug, Error)]
pub enum SshKeyError {
    InvalidPublicKey(String),
    InvalidPrivateKey(String),
    GenerationFailed(String),
    InvalidPassword(String),
}

#[ffi_type]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshKeyType {
    RSA2048,
    RSA4096,
    Ed25519,
}

impl SshKeyType {
    pub fn bit_size(&self) -> usize {
        match self {
            SshKeyType::RSA2048 => 2048,
            SshKeyType::RSA4096 => 4096,
            SshKeyType::Ed25519 => 256,
        }
    }
}

#[ffi_type]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyPair {
    pub public_key: String,
    pub private_key: String,
}

pub fn validate_public_key(key: &str) -> Result<(), SshKeyError> {
    PublicKey::from_openssh(key)
        .map(|_| ())
        .map_err(|e| SshKeyError::InvalidPublicKey(e.to_string()))
}

pub fn validate_private_key(key: &str) -> Result<(), SshKeyError> {
    // Try OpenSSH format first
    if PrivateKey::from_openssh(key).is_ok() {
        return Ok(());
    }

    // Try as encrypted OpenSSH (will fail if wrong password, but format might be valid)
    // We will only receive an error if it's really an invalid key
    PrivateKey::from_openssh(key)
        .map(|_| ())
        .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))
}

pub fn decrypt_private_key(encrypted_key: &str, password: &str) -> Result<String, SshKeyError> {
    let private_key =
        PrivateKey::from_openssh(encrypted_key).map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))?;

    if !private_key.is_encrypted() {
        return private_key
            .to_openssh(LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()));
    }

    let decrypted = private_key
        .decrypt(password)
        .map_err(|e| SshKeyError::InvalidPassword(e.to_string()))?;

    decrypted
        .to_openssh(LineEnding::LF)
        .map(|s| s.to_string())
        .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))
}

pub fn generate_ssh_key(
    comment: String,
    key_type: SshKeyType,
    passphrase: Option<String>,
) -> Result<SshKeyPair, SshKeyError> {
    let mut private_key = match key_type {
        SshKeyType::RSA2048 | SshKeyType::RSA4096 => {
            let keypair = RsaKeypair::random(&mut OsRng, key_type.bit_size())
                .map_err(|e| SshKeyError::GenerationFailed(e.to_string()))?;
            PrivateKey::from(keypair)
        }
        SshKeyType::Ed25519 => {
            let keypair = Ed25519Keypair::random(&mut OsRng);
            PrivateKey::from(keypair)
        }
    };

    let sanitized_comment = comment.replace(['\n', '\r'], " ").trim().to_string();
    private_key.set_comment(sanitized_comment);

    let public_key = private_key.public_key();

    let public_key_str = public_key
        .to_openssh()
        .map_err(|e| SshKeyError::GenerationFailed(e.to_string()))?;

    let private_key_str = if let Some(pass) = passphrase {
        let encrypted = private_key
            .encrypt(&mut OsRng, pass)
            .map_err(|e| SshKeyError::GenerationFailed(e.to_string()))?;

        encrypted
            .to_openssh(LineEnding::LF)
            .map_err(|e| SshKeyError::GenerationFailed(e.to_string()))?
            .to_string()
    } else {
        private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| SshKeyError::GenerationFailed(e.to_string()))?
            .to_string()
    };

    Ok(SshKeyPair {
        public_key: public_key_str,
        private_key: private_key_str,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_ed25519_public_key() {
        let valid_key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rV/7xtXmXKm8zR0K1RpOFvC1mPfVgKjG7fLqJl5zp test@example.com";
        assert!(validate_public_key(valid_key).is_ok());
    }

    #[test]
    fn test_validate_invalid_public_key() {
        let invalid_key = "invalid-key";
        assert!(validate_public_key(invalid_key).is_err());
    }

    #[test]
    fn test_generate_ed25519_key() {
        let result = generate_ssh_key("Test User <test@example.com>".to_string(), SshKeyType::Ed25519, None);
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert!(key_pair.public_key.starts_with("ssh-ed25519"));
        assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
        assert!(key_pair.public_key.contains("Test User <test@example.com>"));
    }

    #[test]
    fn test_generate_rsa2048_key() {
        let result = generate_ssh_key("Test User <test@example.com>".to_string(), SshKeyType::RSA2048, None);
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert!(key_pair.public_key.starts_with("ssh-rsa"));
        assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_generate_key_with_passphrase() {
        let result = generate_ssh_key(
            "Test User <test@example.com>".to_string(),
            SshKeyType::Ed25519,
            Some("test-passphrase".to_string()),
        );
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_validate_generated_keys() {
        let key_pair = generate_ssh_key("Test User <test@example.com>".to_string(), SshKeyType::Ed25519, None).unwrap();

        assert!(validate_public_key(&key_pair.public_key).is_ok());
        assert!(validate_private_key(&key_pair.private_key).is_ok());
    }

    #[test]
    fn test_decrypt_rsa2048_key_with_passphrase() {
        let passphrase = "test-passphrase".to_string();
        let key_pair = generate_ssh_key(
            "Test User <test@example.com>".to_string(),
            SshKeyType::RSA2048,
            Some(passphrase.clone()),
        )
        .unwrap();

        let decrypted = decrypt_private_key(&key_pair.private_key, &passphrase).unwrap();

        assert!(decrypted.contains("OPENSSH PRIVATE KEY"));
        assert!(validate_private_key(&decrypted).is_ok());
    }

    #[test]
    fn test_decrypt_ed25519_key_with_passphrase() {
        let passphrase = "secure-password".to_string();
        let key_pair = generate_ssh_key(
            "Alice <alice@example.com>".to_string(),
            SshKeyType::Ed25519,
            Some(passphrase.clone()),
        )
        .unwrap();

        let decrypted = decrypt_private_key(&key_pair.private_key, &passphrase).unwrap();

        assert!(decrypted.contains("OPENSSH PRIVATE KEY"));
        assert!(validate_private_key(&decrypted).is_ok());
    }

    #[test]
    fn test_decrypt_with_wrong_password() {
        let passphrase = "correct-password".to_string();
        let key_pair = generate_ssh_key(
            "Bob <bob@example.com>".to_string(),
            SshKeyType::Ed25519,
            Some(passphrase),
        )
        .unwrap();

        let result = decrypt_private_key(&key_pair.private_key, "wrong-password");

        assert!(result.is_err());
        match result.unwrap_err() {
            SshKeyError::InvalidPassword(_) => (),
            _ => panic!("Expected InvalidPassword error"),
        }
    }

    #[test]
    fn test_decrypt_unencrypted_key() {
        let key_pair =
            generate_ssh_key("Charlie <charlie@example.com>".to_string(), SshKeyType::Ed25519, None).unwrap();

        let result = decrypt_private_key(&key_pair.private_key, "any-password").unwrap();

        assert_eq!(result, key_pair.private_key);
        assert!(validate_private_key(&result).is_ok());
    }

    #[test]
    fn test_decrypt_invalid_key() {
        let invalid_key = "invalid-private-key-data";
        let result = decrypt_private_key(invalid_key, "password");

        assert!(result.is_err());
        match result.unwrap_err() {
            SshKeyError::InvalidPrivateKey(_) => (),
            _ => panic!("Expected InvalidPrivateKey error"),
        }
    }
}
