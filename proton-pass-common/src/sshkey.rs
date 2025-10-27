use proton_pass_derive::Error;
use ssh_key::private::{Ed25519Keypair, RsaKeypair};
use ssh_key::rand_core::OsRng;
use ssh_key::{LineEnding, PrivateKey, PublicKey};

#[derive(Debug, Error)]
pub enum SshKeyError {
    InvalidPublicKey(String),
    InvalidPrivateKey(String),
    GenerationFailed(String),
}

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

pub fn generate_ssh_key(
    name: String,
    email: String,
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

    // Set the comment (name <email>)
    let comment = format!("{} <{}>", name, email);
    private_key.set_comment(comment);

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
        let result = generate_ssh_key(
            "Test User".to_string(),
            "test@example.com".to_string(),
            SshKeyType::Ed25519,
            None,
        );
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert!(key_pair.public_key.starts_with("ssh-ed25519"));
        assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
        assert!(key_pair.public_key.contains("Test User <test@example.com>"));
    }

    #[test]
    fn test_generate_rsa2048_key() {
        let result = generate_ssh_key(
            "Test User".to_string(),
            "test@example.com".to_string(),
            SshKeyType::RSA2048,
            None,
        );
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        assert!(key_pair.public_key.starts_with("ssh-rsa"));
        assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_generate_key_with_passphrase() {
        let result = generate_ssh_key(
            "Test User".to_string(),
            "test@example.com".to_string(),
            SshKeyType::Ed25519,
            Some("test-passphrase".to_string()),
        );
        assert!(result.is_ok());

        let key_pair = result.unwrap();
        // Encrypted keys still have the OPENSSH PRIVATE KEY header
        assert!(key_pair.private_key.contains("OPENSSH PRIVATE KEY"));
    }

    #[test]
    fn test_validate_generated_keys() {
        let key_pair = generate_ssh_key(
            "Test User".to_string(),
            "test@example.com".to_string(),
            SshKeyType::Ed25519,
            None,
        )
        .unwrap();

        assert!(validate_public_key(&key_pair.public_key).is_ok());
        assert!(validate_private_key(&key_pair.private_key).is_ok());
    }
}
