// Re-export core types that now have uniffi bindings
pub use proton_pass_common::sshkey::{
    SshKeyError as MobileSshKeyError, SshKeyPair as MobileSshKeyPair, SshKeyType as MobileSshKeyType,
};

use proton_pass_common::sshkey::{
    decrypt_private_key, generate_ssh_key, validate_private_key, validate_public_key, SshKeyError, SshKeyPair,
    SshKeyType,
};

type Result<T> = std::result::Result<T, SshKeyError>;

#[derive(uniffi::Object)]
pub struct SshKeyManager;

#[uniffi::export]
impl SshKeyManager {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    pub fn validate_public_key(&self, key: String) -> Result<()> {
        validate_public_key(&key)
    }

    pub fn validate_private_key(&self, key: String) -> Result<()> {
        validate_private_key(&key)
    }

    pub fn generate_ssh_key(
        &self,
        comment: String,
        key_type: SshKeyType,
        passphrase: Option<String>,
    ) -> Result<SshKeyPair> {
        generate_ssh_key(comment, key_type, passphrase)
    }

    pub fn decrypt_private_key(&self, encrypted_key: String, password: String) -> Result<String> {
        decrypt_private_key(&encrypted_key, &password)
    }
}
