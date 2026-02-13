use crate::AuthenticatorEntryModel;

#[derive(Clone, Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AuthenticatorCryptoError {
    CryptoError,
}

impl std::fmt::Display for AuthenticatorCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(uniffi::Object)]
pub struct AuthenticatorCrypto;

#[uniffi::export]
impl AuthenticatorCrypto {
    #[uniffi::constructor]
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
        key: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, AuthenticatorCryptoError> {
        let mut entries = Vec::with_capacity(models.len());
        for model in models {
            let as_entry = model.to_entry().map_err(|_| AuthenticatorCryptoError::CryptoError)?;
            entries.push(as_entry);
        }

        let encrypted = proton_authenticator::encrypt_entries(entries, key).map_err(|e| {
            proton_authenticator::emit_log_message(
                proton_authenticator::LogLevel::Error,
                format!("error encrypting authenticator entries: {e:?}"),
            );
            AuthenticatorCryptoError::CryptoError
        })?;
        Ok(encrypted)
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
        key: Vec<u8>,
    ) -> Result<Vec<AuthenticatorEntryModel>, AuthenticatorCryptoError> {
        let decrypted = proton_authenticator::decrypt_entries(ciphertexts, key).map_err(|e| {
            proton_authenticator::emit_log_message(
                proton_authenticator::LogLevel::Error,
                format!("error decrypting authenticator entries: {e:?}"),
            );
            AuthenticatorCryptoError::CryptoError
        })?;

        let mut res = Vec::with_capacity(decrypted.len());
        for entry in decrypted {
            let as_model = AuthenticatorEntryModel::from(entry);
            res.push(as_model);
        }
        Ok(res)
    }
}
