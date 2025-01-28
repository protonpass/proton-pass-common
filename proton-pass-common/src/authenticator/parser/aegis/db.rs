use crate::authenticator::parser::aegis::AegisImportError;
use crate::authenticator::steam::SteamTotp;
use crate::authenticator::{AuthenticatorEntry, AuthenticatorEntryContent};
use crate::totp::algorithm::Algorithm;
use crate::totp::totp::TOTP;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Info {
    pub secret: String,
    pub algo: String,
    pub digits: i64,
    pub period: i64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DbEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    pub uuid: String,
    pub name: String,
    pub issuer: String,
    pub note: String,
    pub favorite: bool,
    pub icon: Option<String>,
    pub info: Info,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AegisDbRoot {
    pub version: i64,
    pub entries: Vec<DbEntry>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CommonRootWithDb {
    pub db: AegisDbRoot,
}

impl TryFrom<DbEntry> for TOTP {
    type Error = AegisImportError;
    fn try_from(entry: DbEntry) -> Result<Self, Self::Error> {
        Ok(Self {
            secret: entry.info.secret,
            label: Some(entry.name),
            issuer: Some(entry.issuer),
            algorithm: match Algorithm::try_from(entry.info.algo.as_str()) {
                Ok(a) => Some(a),
                Err(_) => return Err(AegisImportError::Unsupported),
            },
            digits: Some(entry.info.digits as u8),
            period: Some(entry.info.period as u16),
        })
    }
}

impl TryFrom<DbEntry> for AuthenticatorEntry {
    type Error = AegisImportError;

    fn try_from(entry: DbEntry) -> Result<Self, Self::Error> {
        let trimmed_note = entry.note.trim();
        let note = if trimmed_note.is_empty() {
            None
        } else {
            Some(trimmed_note.to_string())
        };

        let content = match entry.entry_type.as_str() {
            "steam" => {
                let steam = SteamTotp::new(&entry.info.secret).map_err(|_| AegisImportError::BadContent)?;
                AuthenticatorEntryContent::Steam(steam)
            }
            "totp" => {
                let totp = TOTP::try_from(entry)?;
                AuthenticatorEntryContent::Totp(totp)
            }
            _ => return Err(AegisImportError::Unsupported),
        };

        Ok(AuthenticatorEntry { content, note })
    }
}

pub fn parse_aegis_db(db: AegisDbRoot, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>, AegisImportError> {
    let mut entries = Vec::new();
    for entry in db.entries {
        match AuthenticatorEntry::try_from(entry) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                if fail_on_error {
                    return Err(AegisImportError::BadContent);
                }
            }
        }
    }
    Ok(entries)
}
