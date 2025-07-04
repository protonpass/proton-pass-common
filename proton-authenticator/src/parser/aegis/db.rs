use crate::parser::aegis::AegisImportError;
use crate::parser::{ImportError, ImportResult};
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};
use proton_pass_totp::algorithm::Algorithm;
use proton_pass_totp::totp::TOTP;

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
                Err(e) => {
                    warn!("Unsupported algorithm [{}]: {:?}", entry.info.algo, e);
                    return Err(AegisImportError::Unsupported(format!(
                        "unsupported algorithm: {:?}",
                        entry.info.algo
                    )));
                }
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
                let mut steam = SteamTotp::new(&entry.info.secret).map_err(|_| AegisImportError::BadContent)?;
                if !entry.name.trim().is_empty() {
                    steam.set_name(Some(entry.name.trim().to_string()));
                }
                AuthenticatorEntryContent::Steam(steam)
            }
            "totp" => {
                let totp = TOTP::try_from(entry)?;
                AuthenticatorEntryContent::Totp(totp)
            }
            _ => {
                return Err(AegisImportError::Unsupported(format!(
                    "unsupported entry type: {:?}",
                    entry.entry_type
                )))
            }
        };

        Ok(AuthenticatorEntry {
            content,
            note,
            id: Self::generate_id(),
        })
    }
}

pub fn parse_aegis_db(db: AegisDbRoot) -> Result<ImportResult, AegisImportError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, entry) in db.entries.into_iter().enumerate() {
        match AuthenticatorEntry::try_from(entry.clone()) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                warn!("error importing entry {:?}: {:?}", entry, e);
                errors.push(ImportError {
                    context: format!("Error importing entry {idx}"),
                    message: format!("Error importing entry {entry:?}, {e:?}"),
                })
            }
        }
    }
    Ok(ImportResult { entries, errors })
}
