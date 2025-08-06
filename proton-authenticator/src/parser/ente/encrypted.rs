use super::{chacha_decrypt, EnteImportError};
use crate::parser::ImportResult;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfParams {
    mem_limit: u64,
    ops_limit: u32,
    salt: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EnteEncryptedBackup {
    version: u32,
    kdf_params: KdfParams,
    encrypted_data: String,
    encryption_nonce: String,
}

fn derive_key(params: &KdfParams, password: &str) -> Result<[u8; 32], EnteImportError> {
    let salt_bytes = general_purpose::STANDARD.decode(&params.salt).map_err(|e| {
        warn!("Failed to decode ente salt: {e:?}");
        EnteImportError::BadContent
    })?;

    // Derive key using Argon2
    let params = Params::new(
        (params.mem_limit / 1024) as u32,
        params.ops_limit,
        1,        // parallelism
        Some(32), // output length for XChaCha20
    )
    .map_err(|e| {
        warn!("Failed to create ente encryption parameters: {e:?}");
        EnteImportError::BadContent
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_bytes)
        .map_err(|e| {
            warn!("Failed to hash password: {e:?}");
            EnteImportError::BadPassword
        })?;

    Ok(key_bytes)
}

fn decrypt_data(encrypted_data: &str, encoded_nonce: &str, key: [u8; 32]) -> Result<Vec<u8>, EnteImportError> {
    let encrypted_data = general_purpose::STANDARD.decode(encrypted_data).map_err(|e| {
        warn!("Failed to decode ente encrypted data: {e:?}");
        EnteImportError::BadContent
    })?;

    let nonce_bytes = general_purpose::STANDARD.decode(encoded_nonce).map_err(|e| {
        warn!("Failed to decode ente nonce: {e:?}");
        EnteImportError::BadContent
    })?;

    chacha_decrypt::decrypt_xchacha20poly1305(&encrypted_data, &key, &nonce_bytes)
}

fn decrypt_backup(input: &str, password: &str) -> Result<String, EnteImportError> {
    let backup: EnteEncryptedBackup = serde_json::from_str(input).map_err(|e| {
        warn!("failed to parse backup JSON: {e:?}");
        EnteImportError::BadContent
    })?;

    if backup.version != 1 {
        return Err(EnteImportError::Unsupported);
    }

    let key_bytes = derive_key(&backup.kdf_params, password).map_err(|e| {
        warn!("Failed to derive key: {e:?}");
        e
    })?;

    let decrypted = decrypt_data(&backup.encrypted_data, &backup.encryption_nonce, key_bytes)?;
    let plaintext_str = String::from_utf8(decrypted).map_err(|e| {
        warn!("Failed to decode ente encrypted data: {e:?}");
        EnteImportError::BadContent
    })?;

    Ok(plaintext_str)
}

pub fn parse_ente_encrypted(input: &str, password: &str) -> Result<ImportResult, EnteImportError> {
    let plaintext = decrypt_backup(input, password)?;
    super::txt::parse_ente_txt(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_file_contents;
    use crate::{setup_test_logs, AuthenticatorEntryContent};

    #[test]
    fn can_import_encrypted_file() {
        let content = get_file_contents("ente/encrypted.lowcomplexity.txt");
        let password = get_file_contents("ente/password");
        let imported = parse_ente_encrypted(&content, &password).expect("should be able to import");

        // 1 TOTP entry, 1 STEAM entry, 1 skipped HOTP entry
        assert_eq!(imported.entries.len(), 2);
        assert_eq!(imported.errors.len(), 1);

        // Check that we have one TOTP and one Steam entry
        let mut totp_count = 0;
        let mut steam_count = 0;

        for entry in &imported.entries {
            match &entry.content {
                AuthenticatorEntryContent::Totp(_) => totp_count += 1,
                AuthenticatorEntryContent::Steam(_) => steam_count += 1,
            }
        }

        assert_eq!(totp_count, 1);
        assert_eq!(steam_count, 1);

        assert!(imported.errors[0].message.contains("UnsupportedUri"));
    }

    #[test]
    fn wrong_password_gives_error() {
        setup_test_logs!();
        let content = get_file_contents("ente/encrypted.lowcomplexity.txt");
        let err = parse_ente_encrypted(&content, "wrong_password")
            .expect_err("should not be able to decrypt with wrong password");
        assert!(matches!(err, EnteImportError::BadPassword));
    }
}
