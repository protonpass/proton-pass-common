use proton_pass_common::sshkey::{
    decrypt_private_key as common_decrypt_private_key, generate_ssh_key as common_generate_ssh_key,
    validate_private_key as common_validate_private_key, validate_public_key as common_validate_public_key,
    SshKeyError as CommonSshKeyError, SshKeyPair as CommonSshKeyPair, SshKeyType as CommonSshKeyType,
};

#[derive(Debug, proton_pass_derive::Error)]
pub enum SshKeyError {
    InvalidPublicKey(String),
    InvalidPrivateKey(String),
    GenerationFailed(String),
    InvalidPassword(String),
}

impl From<CommonSshKeyError> for SshKeyError {
    fn from(e: CommonSshKeyError) -> Self {
        match e {
            CommonSshKeyError::InvalidPublicKey(s) => SshKeyError::InvalidPublicKey(s),
            CommonSshKeyError::InvalidPrivateKey(s) => SshKeyError::InvalidPrivateKey(s),
            CommonSshKeyError::GenerationFailed(s) => SshKeyError::GenerationFailed(s),
            CommonSshKeyError::InvalidPassword(s) => SshKeyError::InvalidPassword(s),
        }
    }
}

type Result<T> = std::result::Result<T, SshKeyError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshKeyType {
    RSA2048,
    RSA4096,
    Ed25519,
}

impl From<SshKeyType> for CommonSshKeyType {
    fn from(other: SshKeyType) -> Self {
        match other {
            SshKeyType::RSA2048 => CommonSshKeyType::RSA2048,
            SshKeyType::RSA4096 => CommonSshKeyType::RSA4096,
            SshKeyType::Ed25519 => CommonSshKeyType::Ed25519,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshKeyPair {
    pub public_key: String,
    pub private_key: String,
}

impl From<CommonSshKeyPair> for SshKeyPair {
    fn from(other: CommonSshKeyPair) -> Self {
        Self {
            public_key: other.public_key,
            private_key: other.private_key,
        }
    }
}

pub struct SshKeyManager;

impl SshKeyManager {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_public_key(&self, key: String) -> Result<()> {
        Ok(common_validate_public_key(&key)?)
    }

    pub fn validate_private_key(&self, key: String) -> Result<()> {
        Ok(common_validate_private_key(&key)?)
    }

    pub fn generate_ssh_key(
        &self,
        comment: String,
        key_type: SshKeyType,
        passphrase: Option<String>,
    ) -> Result<SshKeyPair> {
        let common_key_type = CommonSshKeyType::from(key_type);
        let result = common_generate_ssh_key(comment, common_key_type, passphrase)?;
        Ok(SshKeyPair::from(result))
    }

    pub fn decrypt_private_key(&self, encrypted_key: String, password: String) -> Result<String> {
        Ok(common_decrypt_private_key(&encrypted_key, &password)?)
    }
}
