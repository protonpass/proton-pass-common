use crate::parser::aegis::AegisImportError;
use crate::parser::{ImportError, ImportResult};
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent};
use proton_pass_totp::algorithm::Algorithm;
use proton_pass_totp::totp::TOTP;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TotpInfo {
    pub secret: String,
    pub algo: String,
    pub digits: u32,
    pub period: u32,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct HotpInfo {
    pub secret: String,
    pub algo: String,
    pub digits: u32,
    pub counter: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TotpEntry {
    uuid: String,
    name: String,
    issuer: String,
    note: String,
    favorite: bool,
    icon: Option<String>,
    info: TotpInfo,
    groups: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct SteamEntry {
    uuid: String,
    name: String,
    issuer: String,
    note: String,
    favorite: bool,
    icon: Option<String>,
    info: TotpInfo,
    groups: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct HotpEntry {
    uuid: String,
    name: String,
    issuer: String,
    note: String,
    favorite: bool,
    icon: Option<String>,
    info: HotpInfo,
    groups: Vec<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DbEntry {
    Totp {
        #[serde(flatten)]
        entry: TotpEntry,
    },
    Steam {
        #[serde(flatten)]
        entry: SteamEntry,
    },
    Hotp {
        #[serde(flatten)]
        entry: HotpEntry,
    },
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

impl TryFrom<TotpEntry> for TOTP {
    type Error = AegisImportError;
    fn try_from(entry: TotpEntry) -> Result<Self, Self::Error> {
        let issuer = if entry.issuer.is_empty() {
            entry.name.to_string()
        } else {
            entry.issuer
        };

        Ok(Self {
            secret: entry.info.secret,
            label: Some(entry.name),
            issuer: Some(issuer),
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

impl TryFrom<TotpEntry> for AuthenticatorEntry {
    type Error = AegisImportError;

    fn try_from(entry: TotpEntry) -> Result<Self, Self::Error> {
        let trimmed_note = entry.note.trim();
        let note = if trimmed_note.is_empty() {
            None
        } else {
            Some(trimmed_note.to_string())
        };
        let totp = TOTP::try_from(entry)?;

        Ok(AuthenticatorEntry {
            content: AuthenticatorEntryContent::Totp(totp),
            note,
            id: Self::generate_id(),
        })
    }
}

impl TryFrom<SteamEntry> for AuthenticatorEntry {
    type Error = AegisImportError;

    fn try_from(entry: SteamEntry) -> Result<Self, Self::Error> {
        let trimmed_note = entry.note.trim();
        let note = if trimmed_note.is_empty() {
            None
        } else {
            Some(trimmed_note.to_string())
        };

        let mut steam = SteamTotp::new(&entry.info.secret).map_err(|e| {
            warn!("Error parsing Steam secret: {e:?}");
            AegisImportError::BadContent
        })?;
        if !entry.name.trim().is_empty() {
            steam.set_name(Some(entry.name.trim().to_string()));
        }

        Ok(AuthenticatorEntry {
            content: AuthenticatorEntryContent::Steam(steam),
            note,
            id: Self::generate_id(),
        })
    }
}

pub fn parse_aegis_db(db: AegisDbRoot) -> Result<ImportResult, AegisImportError> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (idx, entry) in db.entries.into_iter().enumerate() {
        match entry {
            DbEntry::Totp { entry: totp } => match AuthenticatorEntry::try_from(totp.clone()) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Error importing entry {}: {:?}", totp.name, e);
                    errors.push(ImportError {
                        context: format!("Error importing entry {idx}"),
                        message: format!("Error importing entry {totp:?}, {e:?}"),
                    })
                }
            },
            DbEntry::Steam { entry: steam } => match AuthenticatorEntry::try_from(steam.clone()) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    warn!("Error importing entry {}: {:?}", steam.name, e);
                    errors.push(ImportError {
                        context: format!("Error importing entry {idx}"),
                        message: format!("Error importing entry {steam:?}, {e:?}"),
                    })
                }
            },
            DbEntry::Hotp { entry: hotp } => {
                errors.push(ImportError {
                    context: format!("Error parsing entry {idx}"),
                    message: format!("Error parsing entry {}: Unsupported entry type", hotp.name),
                });
            }
        }
    }
    Ok(ImportResult { entries, errors })
}
