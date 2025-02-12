use super::TwoFasImportError;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};

use base64::{engine::general_purpose, Engine as _};

use crate::parser::{ImportError, ImportResult};
use crate::steam::SteamTotp;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use proton_pass_totp::algorithm::Algorithm;
use proton_pass_totp::totp::TOTP;
use sha2::Sha256;

const ITERATION_COUNT: u32 = 10_000;
const KEY_SIZE: usize = 32; // 256 bits

#[derive(Debug)]
enum TwoFasState {
    Decrypted(Vec<TwoFasEntry>),
    Encrypted {
        data: Vec<u8>, // ciphertext + auth tag
        salt: Vec<u8>,
        iv: Vec<u8>, // 12 bytes for GCM
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "tokenType")]
enum Otp {
    #[serde(rename = "TOTP")]
    Totp {
        issuer: String,
        digits: u32,
        period: u32,
        algorithm: String,
        source: String,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        account: Option<String>,
    },
    #[serde(rename = "STEAM")]
    Steam {
        issuer: String,
        digits: u32,
        period: u32,
        algorithm: String,
        source: String,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct TwoFasEntry {
    pub name: String,
    pub secret: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    pub otp: Otp,
}

fn parse_2fas_export(json_data: &str) -> Result<TwoFasState, TwoFasImportError> {
    let obj: serde_json::Value = serde_json::from_str(json_data).map_err(|_| TwoFasImportError::BadContent)?;
    let version = obj
        .get("schemaVersion")
        .ok_or(TwoFasImportError::BadContent)?
        .as_i64()
        .ok_or(TwoFasImportError::BadContent)?;
    if version > 4 {
        return Err(TwoFasImportError::Unsupported);
    }

    // If "servicesEncrypted" is present, parse it
    if let Some(encrypted_string) = obj.get("servicesEncrypted").and_then(|v| v.as_str()) {
        let parts: Vec<&str> = encrypted_string.split(':').collect();
        if parts.len() < 3 {
            return Err(TwoFasImportError::BadContent);
        }

        // ciphertext + GCM tag
        let data = general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|_| TwoFasImportError::BadContent)?;
        let salt = general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|_| TwoFasImportError::BadContent)?;
        let iv = general_purpose::STANDARD
            .decode(parts[2])
            .map_err(|_| TwoFasImportError::BadContent)?;

        Ok(TwoFasState::Encrypted { data, salt, iv })
    } else {
        // If not encrypted, parse the "services" array
        let arr = obj.get("services").ok_or(TwoFasImportError::BadContent)?;
        let parsed_arr: Vec<TwoFasEntry> =
            serde_json::from_value(arr.clone()).map_err(|_| TwoFasImportError::BadContent)?;

        Ok(TwoFasState::Decrypted(parsed_arr))
    }
}

/// Decrypt the `Encrypted` variant using AES-GCM with a PBKDF2-derived key.
fn decrypt_2fas_encrypted_state(
    state: &TwoFasState,
    password: Option<String>,
) -> Result<Vec<TwoFasEntry>, TwoFasImportError> {
    // We expect the Encrypted state
    let (data, salt, iv) = match state {
        TwoFasState::Encrypted { data, salt, iv } => (data, salt, iv),
        TwoFasState::Decrypted(_) => {
            return Err(TwoFasImportError::BadContent);
        }
    };

    let password = match password {
        Some(password) => password,
        None => return Err(TwoFasImportError::WrongPassword),
    };

    // 1. Derive the 256-bit AES key
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, ITERATION_COUNT, &mut derived_key)
        .map_err(|_| TwoFasImportError::UnableToDecrypt)?;

    // 2. Decrypt with AES-GCM. Nonce must be 12 bytes.
    //    If iv.len() != 12, you'll get an error. That means your data is not GCM or your IV is truncated.
    let cipher = Aes256Gcm::new_from_slice(&derived_key).map_err(|_| TwoFasImportError::UnableToDecrypt)?;

    // GCM calls its IV a 'nonce'
    if iv.len() != 12 {
        return Err(TwoFasImportError::UnableToDecrypt);
    }
    let nonce = Nonce::from_slice(iv);

    // The ciphertext in `data` should also include the 16-byte GCM authentication tag at the end.
    let decrypted = cipher
        .decrypt(nonce, data.as_ref())
        .map_err(|_| TwoFasImportError::WrongPassword)?;

    // 3. Parse the decrypted JSON array
    let decrypted_str = String::from_utf8(decrypted).map_err(|_| TwoFasImportError::BadContent)?;
    let decrypted_arr: Vec<TwoFasEntry> =
        serde_json::from_str(&decrypted_str).map_err(|_| TwoFasImportError::BadContent)?;

    Ok(decrypted_arr)
}

// Example entry parser
fn parse_entry(obj: TwoFasEntry) -> Result<AuthenticatorEntry, TwoFasImportError> {
    let content = match obj.otp {
        Otp::Totp {
            issuer,
            digits,
            period,
            algorithm,
            label,
            ..
        } => AuthenticatorEntryContent::Totp(TOTP {
            label: label.or(Some(obj.name)),
            secret: obj.secret,
            issuer: Some(issuer),
            algorithm: match Algorithm::try_from(algorithm.as_str()) {
                Ok(a) => Some(a),
                Err(_) => return Err(TwoFasImportError::Unsupported),
            },
            digits: Some(digits as u8),
            period: Some(period as u16),
        }),
        Otp::Steam { .. } => {
            let mut steam_totp = SteamTotp::new(&obj.secret)
                .map_err(|_| TwoFasImportError::BadContent)?;
            if !obj.name.trim().is_empty() {
                steam_totp.set_name(Some(obj.name.trim().to_string()));
            }

            AuthenticatorEntryContent::Steam(steam_totp)
        }
    };

    Ok(AuthenticatorEntry { content, note: None })
}

pub fn parse_2fas_file(json_data: &str, password: Option<String>) -> Result<ImportResult, TwoFasImportError> {
    let state = parse_2fas_export(json_data)?;

    let parsed = match state {
        TwoFasState::Decrypted(entries) => entries,
        TwoFasState::Encrypted { .. } => decrypt_2fas_encrypted_state(&state, password)?,
    };

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, entry) in parsed.into_iter().enumerate() {
        match parse_entry(entry.clone()) {
            Ok(e) => entries.push(e),
            Err(e) => {
                errors.push(ImportError {
                    context: format!("Error parsing entry {idx}"),
                    message: format!("Error parsing entry {:?}: {:?}", entry, e),
                });
            }
        }
    }
    Ok(ImportResult { entries, errors })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_file_contents;

    #[test]
    fn can_import_encrypted() {
        let contents = get_file_contents("2fas/encrypted.2fas");
        let res = parse_2fas_file(&contents, Some("test".to_string())).expect("error parsing");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 2);
    }

    #[test]
    fn can_import_unencrypted() {
        let contents = get_file_contents("2fas/decrypted.2fas");
        let res = parse_2fas_file(&contents, None).expect("error parsing");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 2);
    }
}
