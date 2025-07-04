use crate::entry::export_entries;
use crate::{AuthenticatorEntry, AuthenticatorError};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use argon2::password_hash::rand_core::RngCore;
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct EncryptedExport {
    version: u8,
    salt: String,
    content: String,
}

pub(crate) fn export_entries_with_password(
    password: &str,
    entries: Vec<AuthenticatorEntry>,
) -> Result<String, Box<dyn std::error::Error>> {
    let exported_data = export_entries(entries)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let argon2_params = argon2::ParamsBuilder::new()
        .m_cost(19 * 1024)
        .t_cost(2)
        .p_cost(1)
        .build()
        .map_err(|e| AuthenticatorError::SerializationError(e.to_string()))?;
    let argon2 = Argon2::new(Argon2id, V0x13, argon2_params);
    let mut aes_key = [0u8; 32]; // Can be any desired size
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut aes_key)
        .map_err(|e| {
            AuthenticatorError::SerializationError(format!(
                "Error exporting authenticator entries, could not hash password: {:?}",
                e
            ))
        })?;

    let cipher = Aes256Gcm::new_from_slice(&aes_key)?;
    let payload = Payload {
        msg: exported_data.as_bytes(),
        aad: b"proton.authenticator.export.v1",
    };
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cypher_text = cipher.encrypt(&nonce, payload).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error exporting authenticator entries, could not encrypt data: {:?}",
            e
        ))
    })?;

    let encrypted_export = EncryptedExport {
        version: 1,
        salt: BASE64_STANDARD.encode(&salt),
        content: BASE64_STANDARD.encode(&cypher_text),
    };
    Ok(serde_json::to_string(&encrypted_export)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_encrypted() {
        let e1 = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15",
            None,
        )
        .unwrap();
        let e2 = AuthenticatorEntry::from_uri("steam://STEAMKEY", None).unwrap();

        let entries = vec![e1, e2];
        let password = "DummyPassword";
        let exported = export_entries_with_password(password, entries).unwrap();
        assert!(exported.len() > 10);
    }
}
