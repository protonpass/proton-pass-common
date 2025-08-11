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
struct Otp {
    issuer: Option<String>,
    #[serde(default)]
    digits: Option<u32>,
    #[serde(default)]
    period: Option<u32>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(rename = "tokenType")]
    token_type: String,
    source: String,
    #[serde(default)]
    link: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct TwoFasEntry {
    pub name: String,
    pub secret: String,
    pub otp: Otp,
}

fn parse_2fas_export(json_data: &str) -> Result<TwoFasState, TwoFasImportError> {
    let obj: serde_json::Value = serde_json::from_str(json_data).map_err(|e| {
        warn!("Error parsing 2FAS export: {e:?}");
        TwoFasImportError::BadContent
    })?;

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
        let parsed_arr: Vec<TwoFasEntry> = serde_json::from_value(arr.clone()).map_err(|e| {
            warn!("Error parsing unencrypted 2FAS export: {}", e);
            TwoFasImportError::BadContent
        })?;

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
        None => return Err(TwoFasImportError::MissingPassword),
    };

    // 1. Derive the 256-bit AES key
    let mut derived_key = [0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, ITERATION_COUNT, &mut derived_key)
        .map_err(|_| TwoFasImportError::UnableToDecrypt)?;

    // 2. Decrypt with AES-GCM. Nonce must be 12 bytes.
    //    If iv.len() != 12, you'll get an error. That means your data is not GCM or your IV is truncated.
    let cipher = Aes256Gcm::new_from_slice(&derived_key).map_err(|e| {
        warn!("Error creating Aes256Gcm: {}", e);
        TwoFasImportError::UnableToDecrypt
    })?;

    // GCM calls its IV a 'nonce'
    if iv.len() != 12 {
        return Err(TwoFasImportError::UnableToDecrypt);
    }
    let nonce = Nonce::from_slice(iv);

    // The ciphertext in `data` should also include the 16-byte GCM authentication tag at the end.
    let decrypted = cipher.decrypt(nonce, data.as_ref()).map_err(|e| {
        warn!("Error decrypting 2FAS encrypted backup data: {}", e);
        TwoFasImportError::WrongPassword
    })?;

    // 3. Parse the decrypted JSON array
    let decrypted_str = String::from_utf8(decrypted).map_err(|e| {
        warn!("Error parsing decrypted 2FAS backup data: {}", e);
        TwoFasImportError::BadContent
    })?;
    let decrypted_arr: Vec<TwoFasEntry> = serde_json::from_str(&decrypted_str).map_err(|e| {
        warn!("Error parsing decrypted 2FAS encrypted backup data: {}", e);
        TwoFasImportError::BadContent
    })?;

    Ok(decrypted_arr)
}

fn calculate_label(label: Option<String>, account: Option<String>, obj_name: String) -> String {
    if let Some(label_value) = label {
        if !label_value.is_empty() {
            return label_value;
        }
    }

    if let Some(account_value) = account {
        if !account_value.is_empty() {
            return account_value;
        }
    }

    obj_name
}

fn get_content_from_entry(obj: TwoFasEntry) -> Result<AuthenticatorEntryContent, TwoFasImportError> {
    match obj.otp.token_type.as_str() {
        "STEAM" => {
            let mut steam_totp = SteamTotp::new(&obj.secret).map_err(|_| TwoFasImportError::BadContent)?;
            if !obj.name.trim().is_empty() {
                steam_totp.set_name(Some(obj.name.trim().to_string()));
            }

            Ok(AuthenticatorEntryContent::Steam(steam_totp))
        }
        "TOTP" => {
            let otp = obj.otp;
            if otp.source == "Link" {
                if let Some(ref uri) = otp.link {
                    if let Ok(mut totp) = TOTP::from_uri(uri) {
                        let override_label = otp.label.or(otp.account);
                        if let Some(overriden) = override_label {
                            if !overriden.is_empty() {
                                totp.label = Some(overriden);
                            }
                        }

                        return Ok(AuthenticatorEntryContent::Totp(totp));
                    }
                }
            }

            let issuer = match &otp.issuer {
                Some(issuer) => {
                    if issuer.is_empty() {
                        obj.name.to_string()
                    } else {
                        issuer.to_string()
                    }
                }
                None => obj.name.to_string(),
            };

            let label = calculate_label(otp.label, otp.account, obj.name.to_string());

            Ok(AuthenticatorEntryContent::Totp(TOTP {
                label: Some(label),
                secret: obj.secret,
                issuer: Some(issuer),
                algorithm: match otp.algorithm {
                    Some(algo) => match Algorithm::try_from(algo.as_str()) {
                        Ok(a) => Some(a),
                        Err(_) => {
                            warn!("Unsupported algorithm for 2FAS entry: {algo}");
                            return Err(TwoFasImportError::Unsupported);
                        }
                    },
                    None => None,
                },
                digits: otp.digits.map(|v| v as u8),
                period: otp.period.map(|v| v as u16),
            }))
        }
        _ => {
            // Can be a HOTP or another unsupported entry
            warn!("Unsupported OTP token type: {}", obj.otp.token_type);
            Err(TwoFasImportError::Unsupported)
        }
    }
}

fn parse_entry(obj: TwoFasEntry) -> Result<AuthenticatorEntry, TwoFasImportError> {
    let content = get_content_from_entry(obj)?;

    Ok(AuthenticatorEntry {
        content,
        note: None,
        id: AuthenticatorEntry::generate_id(),
    })
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
                    message: format!("Error parsing entry {}: {:?}", entry.name, e),
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

    #[test]
    fn can_import_unencrypted_ios() {
        let contents = get_file_contents("2fas/decrypted_ios.2fas");
        let res = parse_2fas_file(&contents, None).expect("error parsing");
        assert!(res.errors.is_empty());
        assert_eq!(res.entries.len(), 2);
    }

    #[test]
    fn returns_missing_password_if_encrypted_with_no_password_provided() {
        let contents = get_file_contents("2fas/encrypted.2fas");
        let err = parse_2fas_file(&contents, None).expect_err("should return an error");
        assert!(matches!(err, TwoFasImportError::MissingPassword));
    }

    #[test]
    fn skips_htop_entries() {
        let contents = get_file_contents("2fas/decrypted_with_hotp.2fas");
        let res = parse_2fas_file(&contents, None).expect("error parsing");
        assert_eq!(res.entries.len(), 1);

        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Unsupported"));
    }

    #[test]
    fn skips_entries_with_unsupported_algorithms() {
        let content = get_file_contents("2fas/decrypted_with_hotp_and_unsupported_algorithms.2fas");

        let res = parse_2fas_file(&content, None).expect("error parsing");
        assert!(res.entries.is_empty());
        assert_eq!(res.errors.len(), 2);

        assert!(res.errors[0].message.contains("Unsupported"));
        assert!(res.errors[1].message.contains("Unsupported"));
    }

    #[test]
    fn skips_hotp_entries_with_missing_period_property() {
        let content = get_file_contents("2fas/decrypted_with_hotp_missing_period.2fas");

        let res = parse_2fas_file(&content, None).expect("error parsing");
        assert_eq!(res.entries.len(), 3);
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Unsupported"));
    }

    #[test]
    fn handles_missing_fields() {
        let content = get_file_contents("2fas/decrypted_with_missing_fields.2fas");
        let res = parse_2fas_file(&content, None).expect("error parsing");
        assert_eq!(res.entries.len(), 1);
        assert_eq!(res.errors.len(), 0);
    }

    #[test]
    fn handles_manual_entries() {
        let content = get_file_contents("2fas/decrypted_with_manual_entries.2fas");
        let res = parse_2fas_file(&content, None).expect("error parsing");
        assert_eq!(res.entries.len(), 11);

        let entries = res.entries;
        // [0]
        assert_eq!("Amazon", entries[0].issuer());
        // URI: some@random.email
        // User-edited: some@test.email <-- Should prevail
        assert_eq!("some@test.email", entries[0].name());

        // [1]
        assert_eq!("GitHub", entries[1].issuer());
        assert_eq!("Test-acc", entries[1].name());

        // [2]
        assert_eq!("Facebook", entries[2].issuer());
        assert_eq!("random.sometest", entries[2].name());

        // [3]
        assert_eq!("Google", entries[3].issuer());
        // URI: some@random.email
        // User-edited: some@test.email <-- Should prevail
        assert_eq!("some@test.email", entries[3].name());

        // [4]
        assert_eq!("LinkedIn", entries[4].issuer());
        assert_eq!("some@test.email", entries[4].name());

        // [5]
        assert_eq!("Binance.com", entries[5].issuer());
        assert_eq!("some@test.email", entries[5].name());

        // [6]
        assert_eq!("kick", entries[6].issuer());
        assert_eq!("some@test.email", entries[6].name());

        // [7]
        assert_eq!("Proton", entries[7].issuer());
        assert_eq!("sometestaccount@proton.me", entries[7].name());

        // [8]
        assert_eq!("Reddit", entries[8].issuer());
        assert_eq!("Some-Account1234", entries[8].name());

        // [9]
        assert_eq!("20", entries[9].issuer());
        assert_eq!("20", entries[9].name());

        // [10]
        assert_eq!("Manual", entries[10].issuer());
        assert_eq!("Manual", entries[10].name());

        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Unsupported"));
    }
}
