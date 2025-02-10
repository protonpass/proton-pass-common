use crate::AuthenticatorEntryModel;
use proton_authenticator::crypto::EncryptionTag;
use proton_pass_derive::Error;

#[derive(Clone, Debug, Error)]
pub enum AuthenticatorCryptoError {
    CryptoError,
}

pub struct AuthenticatorCrypto;

impl AuthenticatorCrypto {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_key(&self) -> Vec<u8> {
        proton_authenticator::crypto::generate_encryption_key()
    }

    pub fn encrypt_entry(
        &self,
        model: AuthenticatorEntryModel,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, AuthenticatorCryptoError> {
        let res = self.encrypt_many_entries(vec![model], key)?;
        Ok(res[0].clone())
    }

    pub fn encrypt_many_entries(
        &self,
        models: Vec<AuthenticatorEntryModel>,
        mut key: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, AuthenticatorCryptoError> {
        let mut res = Vec::with_capacity(models.len());
        for model in models {
            let as_entry = model.to_entry().map_err(|_| AuthenticatorCryptoError::CryptoError)?;
            let serialized = as_entry
                .serialize()
                .map_err(|_| AuthenticatorCryptoError::CryptoError)?;
            let decrypted = proton_authenticator::crypto::encrypt(&serialized, &key, EncryptionTag::Entry)
                .map_err(|_| AuthenticatorCryptoError::CryptoError)?;
            res.push(decrypted);
        }
        key.clear();
        Ok(res)
    }

    pub fn decrypt_entry(
        &self,
        ciphertext: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorCryptoError> {
        let res = self.decrypt_many_entries(vec![ciphertext], key)?;
        Ok(res[0].clone())
    }

    pub fn decrypt_many_entries(
        &self,
        ciphertexts: Vec<Vec<u8>>,
        mut key: Vec<u8>,
    ) -> Result<Vec<AuthenticatorEntryModel>, AuthenticatorCryptoError> {
        let mut res = Vec::with_capacity(ciphertexts.len());
        for ciphertext in ciphertexts {
            let decrypted = proton_authenticator::crypto::decrypt(&ciphertext, &key, EncryptionTag::Entry)
                .map_err(|_| AuthenticatorCryptoError::CryptoError)?;

            let deserialized = proton_authenticator::AuthenticatorEntry::deserialize(&decrypted)
                .map_err(|_| AuthenticatorCryptoError::CryptoError)?;

            let as_model = AuthenticatorEntryModel::from(deserialized);
            res.push(as_model);
        }
        key.clear();
        Ok(res)
    }
}
