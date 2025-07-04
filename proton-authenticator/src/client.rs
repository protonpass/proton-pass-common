use crate::steam::PERIOD as STEAM_PERIOD;
use crate::{entry, AuthenticatorEntry, AuthenticatorEntryContent, ThirdPartyImportError};

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum AuthenticatorError {
    CodeGenerationError(String),
    SerializationError(String),
    Unknown(String),
    Import(ThirdPartyImportError),
}

type Result<T> = std::result::Result<T, AuthenticatorError>;

#[derive(Clone)]
pub struct AuthenticatorCodeResponse {
    pub current_code: String,
    pub next_code: String,
    pub entry: AuthenticatorEntry,
}

#[derive(Default)]
pub struct AuthenticatorClient;

impl AuthenticatorClient {
    pub fn new() -> Self {
        Self
    }

    pub fn entry_from_uri(&self, uri: String) -> Result<AuthenticatorEntry> {
        AuthenticatorEntry::from_uri(&uri, None)
            .map_err(|e| AuthenticatorError::Unknown(format!("cannot parse uri: {:?}", e)))
    }

    pub fn generate_codes(&self, entries: &[AuthenticatorEntry], time: u64) -> Result<Vec<AuthenticatorCodeResponse>> {
        let mut result = Vec::new();
        for entry in entries {
            let uri = entry.uri();
            match Self::generate_code(entry, time) {
                Ok(code) => result.push(code),
                Err(e) => {
                    warn!("Error generating code [uri={}]: {:?}", uri, e);
                    return Err(e);
                }
            }
        }
        Ok(result)
    }

    pub fn deserialize_entries(&self, entries: Vec<Vec<u8>>) -> Result<Vec<AuthenticatorEntry>> {
        let mut result = Vec::new();
        for entry in entries {
            match AuthenticatorEntry::deserialize(&entry) {
                Ok(entry) => result.push(entry),
                Err(e) => {
                    let msg = format!("error deserializing entry: {:?}", e);
                    warn!("{}", msg);
                    return Err(AuthenticatorError::SerializationError(msg));
                }
            }
        }
        Ok(result)
    }

    pub fn serialize_entries(&self, entries: Vec<AuthenticatorEntry>) -> Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        for entry in entries {
            let uri = entry.uri();
            result.push(entry.serialize().map_err(|e| {
                let msg = format!("error serializing entry [uri={}]: {:?}", uri, e);
                warn!("{}", msg);
                AuthenticatorError::SerializationError(msg)
            })?);
        }

        Ok(result)
    }

    pub fn export_entries(&self, entries: Vec<AuthenticatorEntry>) -> Result<String> {
        entry::export_entries(entries).map_err(|e| {
            let msg = format!("error exporting entries: {:?}", e);
            warn!("{}", msg);
            AuthenticatorError::SerializationError(msg)
        })
    }

    pub fn export_entries_with_password(&self, password: &str, entries: Vec<AuthenticatorEntry>) -> Result<String> {
        entry::export_entries_with_password(password, entries).map_err(|e| {
            let msg = format!("error exporting entries: {:?}", e);
            warn!("{}", msg);
            AuthenticatorError::SerializationError(msg)
        })
    }

    pub(crate) fn generate_code(entry: &AuthenticatorEntry, time: u64) -> Result<AuthenticatorCodeResponse> {
        match &entry.content {
            AuthenticatorEntryContent::Totp(t) => {
                let period = t.get_period();
                let next_time = time + period as u64;
                let current = t.generate_token(time).map_err(|e| {
                    let msg = format!("error generating token: {:?}", e);
                    warn!("{}", msg);
                    AuthenticatorError::CodeGenerationError(msg)
                })?;
                let next = t.generate_token(next_time).map_err(|e| {
                    let msg = format!("error generating token: {:?}", e);
                    warn!("{}", msg);
                    AuthenticatorError::CodeGenerationError(msg)
                })?;

                Ok(AuthenticatorCodeResponse {
                    current_code: current,
                    next_code: next,
                    entry: entry.clone(),
                })
            }
            AuthenticatorEntryContent::Steam(steam) => {
                let current = steam.generate(time);
                let next = steam.generate(time + STEAM_PERIOD as u64);
                Ok(AuthenticatorCodeResponse {
                    current_code: current,
                    next_code: next,
                    entry: entry.clone(),
                })
            }
        }
    }
}
