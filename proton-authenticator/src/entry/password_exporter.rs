use crate::crypto::EncryptionTag;
use crate::entry::{export_entries, import_authenticator_entries};
use crate::{crypto, AuthenticatorEntry, AuthenticatorError, ImportResult};
use argon2::password_hash::rand_core::RngCore;
use argon2::Algorithm::Argon2id;
use argon2::Version::V0x13;
use argon2::{password_hash::rand_core::OsRng, Argon2};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize)]
struct EncryptedExport {
    version: u8,
    salt: String,
    content: String,
}

pub fn export_entries_with_password(
    entries: Vec<AuthenticatorEntry>,
    password: &str,
) -> Result<String, AuthenticatorError> {
    let exported_data = export_entries(entries)?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let aes_key = derive_password_key(password, &salt).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error exporting authenticator entries, could not derive password: {:?}",
            e
        ))
    })?;

    let cipher_text =
        crypto::encrypt(&exported_data.into_bytes(), &aes_key, EncryptionTag::PasswordExport).map_err(|e| {
            AuthenticatorError::SerializationError(format!(
                "Error exporting authenticator entries, could not encrypt exported data: {:?}",
                e
            ))
        })?;

    let encrypted_export = EncryptedExport {
        version: 1,
        salt: BASE64_STANDARD.encode(salt),
        content: BASE64_STANDARD.encode(&cipher_text),
    };

    serde_json::to_string(&encrypted_export).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error exporting authenticator entries, could not serialize data to json: {:?}",
            e
        ))
    })
}

fn derive_password_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], Box<dyn Error>> {
    let argon2_params = argon2::ParamsBuilder::new()
        .m_cost(19 * 1024)
        .t_cost(2)
        .p_cost(1)
        .build()
        .map_err(|e| AuthenticatorError::SerializationError(e.to_string()))?;
    let argon2 = Argon2::new(Argon2id, V0x13, argon2_params);
    let mut aes_key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut aes_key)
        .map_err(|e| {
            AuthenticatorError::SerializationError(format!(
                "Error exporting authenticator entries, could not hash password: {:?}",
                e
            ))
        })?;
    Ok(aes_key)
}

pub fn import_entries_with_password(input: &str, password: &str) -> Result<ImportResult, AuthenticatorError> {
    let encrypted_export: EncryptedExport = serde_json::from_str(input).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could deserialize json: {:?}",
            e
        ))
    })?;
    if encrypted_export.version != 1 {
        return Err(AuthenticatorError::SerializationError(format!(
            "Only encrypted export version 1 is supported, got version {}",
            encrypted_export.version
        )));
    }
    let salt = BASE64_STANDARD.decode(&encrypted_export.salt).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not decode salt: {:?}",
            e
        ))
    })?;

    let salt_ref: &[u8; 16] = salt.as_slice().try_into().map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, salt does not have the proper length: {:?}",
            e
        ))
    })?;

    let aes_key = derive_password_key(password, salt_ref).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not derive password: {:?}",
            e
        ))
    })?;
    let cypher_text = BASE64_STANDARD.decode(&encrypted_export.content).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not decode contents: {:?}",
            e
        ))
    })?;
    let binary_export = crypto::decrypt(&cypher_text, &aes_key, EncryptionTag::PasswordExport).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not decrypt contents: {:?}",
            e
        ))
    })?;

    let plain_text = std::str::from_utf8(&binary_export).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not read contents: {:?}",
            e
        ))
    })?;

    import_authenticator_entries(plain_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthenticatorEntryContent;

    #[test]
    fn test_export_import_encrypted() {
        let uri1 = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";
        let uri2 = "steam://STEAMKEY";

        let entries = vec![
            AuthenticatorEntry::from_uri(uri1, None).unwrap(),
            AuthenticatorEntry::from_uri(uri2, None).unwrap(),
        ];
        let password = "DummyPassword";
        let exported = export_entries_with_password(entries, password).unwrap();
        let imported = import_entries_with_password(&exported, password).unwrap();
        assert_eq!(imported.entries.len(), 2);
        assert_eq!(
            imported.entries[0].content,
            AuthenticatorEntryContent::from_uri(uri1).unwrap()
        );
        assert_eq!(
            imported.entries[1].content,
            AuthenticatorEntryContent::from_uri(uri2).unwrap()
        );
        assert!(exported.len() > 10);
    }

    #[test]
    fn test_export_with_different_password_fails() {
        let uri1 = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15";

        let entries = vec![AuthenticatorEntry::from_uri(uri1, None).unwrap()];
        let exported = export_entries_with_password(entries, "ok").unwrap();
        let result = import_entries_with_password(&exported, "invalid");
        assert!(result.is_err());
    }
}
