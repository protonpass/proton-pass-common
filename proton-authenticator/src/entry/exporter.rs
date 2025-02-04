use crate::parser::{ImportError, ImportResult};
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorError};
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
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ExportedAuthenticatorEntry {
    pub content: ExportedAuthenticatorEntryContent,
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
            },
            AuthenticatorEntryContent::Steam(steam) => ExportedAuthenticatorEntryContent {
                uri: steam.uri(),
                entry_type: ExportedAuthenticatorEntryType::Steam,
            },
        }
    }
}

impl From<AuthenticatorEntry> for ExportedAuthenticatorEntry {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
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
                    .map_err(|e| AuthenticatorError::SerializationError(format!("error parsing TOTP uri: {:?}", e)))?;
                Ok(AuthenticatorEntryContent::Totp(totp))
            }
            ExportedAuthenticatorEntryType::Steam => {
                let steam = SteamTotp::new_from_uri(&content.uri)
                    .map_err(|e| AuthenticatorError::SerializationError(format!("error parsing Steam uri: {:?}", e)))?;
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
                .map_err(|e| AuthenticatorError::SerializationError(format!("error parsing entry content: {:?}", e)))?,
            note: entry.note,
        })
    }
}

pub fn export_entries(entries: Vec<AuthenticatorEntry>) -> Result<String, AuthenticatorError> {
    let export = AuthenticatorEntriesExport {
        version: 1,
        entries: entries.into_iter().map(ExportedAuthenticatorEntry::from).collect(),
    };

    serde_json::to_string(&export)
        .map_err(|e| AuthenticatorError::SerializationError(format!("Error exporting entries: {:?}", e)))
}

fn import_authenticator_entries_v1(input: &str) -> Result<ImportResult, AuthenticatorError> {
    let parsed: AuthenticatorEntriesExport = serde_json::from_str(input)
        .map_err(|e| AuthenticatorError::SerializationError(format!("Error importing entries: {:?}", e)))?;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, entry) in parsed.entries.into_iter().enumerate() {
        match AuthenticatorEntry::try_from(entry.clone()) {
            Ok(entry) => entries.push(entry),
            Err(e) => errors.push(ImportError {
                context: format!("Error in entry {idx}"),
                message: format!("Error importing entry {:?}: {:?}", entry, e),
            }),
        }
    }
    Ok(ImportResult { entries, errors })
}

pub fn import_authenticator_entries(input: &str) -> Result<ImportResult, AuthenticatorError> {
    let header: AuthenticatorEntriesExportHeader = serde_json::from_str(input).map_err(|e| {
        AuthenticatorError::SerializationError(format!(
            "Error importing authenticator entries, could not detect header: {:?}",
            e
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
