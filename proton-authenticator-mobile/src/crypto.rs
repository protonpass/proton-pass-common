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

    pub fn encrypt(
        &self,
        plaintext: Vec<u8>,
        mut key: Vec<u8>,
        tag: Option<String>,
    ) -> Result<Vec<u8>, AuthenticatorCryptoError> {
        let res = proton_authenticator::crypto::encrypt(&plaintext, &key, tag)
            .map_err(|_| AuthenticatorCryptoError::CryptoError)?;
        key.clear();
        Ok(res)
    }

    pub fn encrypt_many(
        &self,
        plaintexts: Vec<Vec<u8>>,
        mut key: Vec<u8>,
        tag: Option<String>,
    ) -> Result<Vec<Vec<u8>>, AuthenticatorCryptoError> {
        let mut res = Vec::with_capacity(plaintexts.len());
        for plaintext in plaintexts {
            let decrypted = proton_authenticator::crypto::encrypt(&plaintext, &key, tag.clone())
                .map_err(|_| AuthenticatorCryptoError::CryptoError)?;
            res.push(decrypted);
        }
        key.clear();
        Ok(res)
    }

    pub fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        mut key: Vec<u8>,
        tag: Option<String>,
    ) -> Result<Vec<u8>, AuthenticatorCryptoError> {
        let res = proton_authenticator::crypto::decrypt(&ciphertext, &key, tag)
            .map_err(|_| AuthenticatorCryptoError::CryptoError)?;
        key.clear();
        Ok(res)
    }

    pub fn decrypt_many(
        &self,
        ciphertexts: Vec<Vec<u8>>,
        mut key: Vec<u8>,
        tag: Option<String>,
    ) -> Result<Vec<Vec<u8>>, AuthenticatorCryptoError> {
        let mut res = Vec::with_capacity(ciphertexts.len());
        for ciphertext in ciphertexts {
            let decrypted = proton_authenticator::crypto::decrypt(&ciphertext, &key, tag.clone())
                .map_err(|_| AuthenticatorCryptoError::CryptoError)?;
            res.push(decrypted);
        }
        key.clear();
        Ok(res)
    }
}
