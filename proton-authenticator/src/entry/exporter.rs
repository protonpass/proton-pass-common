use crate::parser::{ImportError, ImportResult};
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorError, ThirdPartyImportError};
use proton_pass_totp::totp::TOTP;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum ExportedAuthenticatorEntryType {
    Totp,
    Steam,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ExportedAuthenticatorEntryContent {
    pub uri: String,
    pub entry_type: ExportedAuthenticatorEntryType,
    pub name: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ExportedAuthenticatorEntry {
    pub id: String,
    pub content: ExportedAuthenticatorEntryContent,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AuthenticatorEntriesExport {
    pub version: u8,
    pub entries: Vec<ExportedAuthenticatorEntry>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct AuthenticatorEntriesExportHeader {
    pub version: u8,
}

impl From<AuthenticatorEntryContent> for ExportedAuthenticatorEntryContent {
    fn from(content: AuthenticatorEntryContent) -> Self {
        match content {
            AuthenticatorEntryContent::Totp(totp) => ExportedAuthenticatorEntryContent {
                uri: totp.to_uri(None, None),
                entry_type: ExportedAuthenticatorEntryType::Totp,
                name: match totp.label {
                    Some(label) => Some(label),
                    None => totp.issuer,
                },
            },
            AuthenticatorEntryContent::Steam(steam) => ExportedAuthenticatorEntryContent {
                uri: steam.uri(),
                entry_type: ExportedAuthenticatorEntryType::Steam,
                name: steam.name,
            },
        }
    }
}

impl From<AuthenticatorEntry> for ExportedAuthenticatorEntry {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            id: entry.id,
            note: entry.note,
            content: ExportedAuthenticatorEntryContent::from(entry.content),
        }
    }
}

impl TryFrom<ExportedAuthenticatorEntryContent> for AuthenticatorEntryContent {
    type Error = AuthenticatorError;
    fn try_from(content: ExportedAuthenticatorEntryContent) -> Result<Self, Self::Error> {
        match content.entry_type {
            ExportedAuthenticatorEntryType::Totp => {
                let totp = TOTP::from_uri(&content.uri)
                    .map_err(|e| AuthenticatorError::SerializationError(format!("error parsing TOTP uri: {e:?}")))?;
                Ok(AuthenticatorEntryContent::Totp(totp))
            }
            ExportedAuthenticatorEntryType::Steam => {
                let mut steam = SteamTotp::new_from_uri(&content.uri)
                    .map_err(|e| AuthenticatorError::SerializationError(format!("error parsing Steam uri: {e:?}")))?;
                steam.set_name(content.name);

                Ok(AuthenticatorEntryContent::Steam(steam))
            }
        }
    }
}

impl TryFrom<ExportedAuthenticatorEntry> for AuthenticatorEntry {
    type Error = AuthenticatorError;
    fn try_from(entry: ExportedAuthenticatorEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            content: AuthenticatorEntryContent::try_from(entry.content)
                .map_err(|e| AuthenticatorError::SerializationError(format!("error parsing entry content: {e:?}")))?,
            note: entry.note,
            id: entry.id,
        })
    }
}

pub fn export_entries(entries: Vec<AuthenticatorEntry>) -> Result<String, AuthenticatorError> {
    let export = AuthenticatorEntriesExport {
        version: 1,
        entries: entries.into_iter().map(ExportedAuthenticatorEntry::from).collect(),
    };

    serde_json::to_string(&export)
        .map_err(|e| AuthenticatorError::SerializationError(format!("Error exporting entries: {e:?}")))
}

fn ensure_json_format(input: &str) -> Result<(), AuthenticatorError> {
    let parsed: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| AuthenticatorError::SerializationError(format!("Error parsing JSON: {e:?}")))?;

    match parsed {
        serde_json::Value::Object(obj) => match (obj.get("salt"), obj.get("entries")) {
            (Some(_), None) => {
                // Password-protected export
                Err(AuthenticatorError::Import(ThirdPartyImportError::MissingPassword))
            }
            (None, Some(_)) => Ok(()),
            _ => {
                // Either has both salt and entries, which is weird, or has none, which means BadContent
                Err(AuthenticatorError::Import(ThirdPartyImportError::BadContent))
            }
        },
        _ => Err(AuthenticatorError::Import(ThirdPartyImportError::BadContent)),
    }
}

fn import_authenticator_entries_v1(input: &str) -> Result<ImportResult, AuthenticatorError> {
    ensure_json_format(input)?;
    let parsed: AuthenticatorEntriesExport = serde_json::from_str(input)
        .map_err(|e| AuthenticatorError::SerializationError(format!("Error importing entries: {e:?}")))?;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, entry) in parsed.entries.into_iter().enumerate() {
        match AuthenticatorEntry::try_from(entry.clone()) {
            Ok(entry) => entries.push(entry),
            Err(e) => errors.push(ImportError {
                context: format!("Error in entry {idx}"),
                message: format!("Error importing entry {entry:?}: {e:?}"),
            }),
        }
    }
    Ok(ImportResult { entries, errors })
}

pub fn import_authenticator_entries(input: &str) -> Result<ImportResult, AuthenticatorError> {
    let header: AuthenticatorEntriesExportHeader = serde_json::from_str(input).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not detect header: {e:?}"
        ))
    })?;

    match header.version {
        1 => import_authenticator_entries_v1(input),
        _ => Err(AuthenticatorError::SerializationError(format!(
            "Unsupported version: {}",
            header.version
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_import_preserves_ids() {
        let e1 = AuthenticatorEntry::from_uri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15",
            None,
        )
        .unwrap();
        let e2 = AuthenticatorEntry::from_uri("steam://STEAMKEY", None).unwrap();

        let e1_id = e1.id.clone();
        let e2_id = e2.id.clone();
        let entries = vec![e1, e2];
        let exported = export_entries(entries).unwrap();
        let imported = import_authenticator_entries_v1(&exported).unwrap();
        assert_eq!(imported.entries.len(), 2);
        assert!(imported.errors.is_empty());

        assert_eq!(e1_id, imported.entries[0].id);
        assert_eq!(e2_id, imported.entries[1].id);
    }

    #[test]
    fn test_export_import_preserves_data() {
        let totp_label = "MY_LABEL";
        let totp_uri =
            format!("otpauth://totp/{totp_label}?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15");
        let totp_note = "A note";
        let totp_entry = AuthenticatorEntry::from_uri(&totp_uri, Some(totp_note.to_string())).unwrap();

        let steam_name = "STEAM_NAME";
        let mut steam_content = SteamTotp::new_from_uri("steam://STEAMKEY").unwrap();
        steam_content.set_name(Some(steam_name.to_string()));
        let steam_note = "STEAM NOTE";
        let steam_entry = AuthenticatorEntry {
            id: AuthenticatorEntry::generate_id(),
            content: AuthenticatorEntryContent::Steam(steam_content),
            note: Some(steam_note.to_string()),
        };

        let totp_id = totp_entry.id.clone();
        let steam_id = steam_entry.id.clone();
        let entries = vec![totp_entry, steam_entry];
        let exported = export_entries(entries).unwrap();
        let imported = import_authenticator_entries_v1(&exported).unwrap();
        assert_eq!(imported.entries.len(), 2);
        assert!(imported.errors.is_empty());

        assert_eq!(totp_id, imported.entries[0].id);
        assert_eq!(Some(totp_note.to_string()), imported.entries[0].note);
        assert_eq!(totp_label.to_string(), imported.entries[0].name());

        assert_eq!(steam_id, imported.entries[1].id);
        assert_eq!(Some(steam_note.to_string()), imported.entries[1].note);
        assert_eq!(steam_name.to_string(), imported.entries[1].name());
    }

    #[test]
    fn can_detect_password_protected_export() {
        let input = r#"
        { "version": 1, "salt": "abcdefg", "content": "abcdefg" }
        "#;

        let err = import_authenticator_entries_v1(input).expect_err("should return an error");
        assert!(matches!(
            err,
            AuthenticatorError::Import(ThirdPartyImportError::MissingPassword)
        ));
    }
}
