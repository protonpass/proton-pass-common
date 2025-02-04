use crate::steam::PERIOD as STEAM_PERIOD;
use crate::{entry, AuthenticatorEntry, AuthenticatorEntryContent, ThirdPartyImportError};

#[derive(Clone, Debug)]
pub enum AuthenticatorError {
    CodeGenerationError(String),
    SerializationError(String),
    Unknown(String),
    Import(ThirdPartyImportError),
}

type Result<T> = std::result::Result<T, AuthenticatorError>;

pub struct AuthenticatorCodeResponse {
    pub current_code: String,
    pub next_code: String,
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
            result.push(Self::generate_code(entry, time)?);
        }
        Ok(result)
    }

    pub fn deserialize_entries(&self, entries: Vec<Vec<u8>>, fail_on_error: bool) -> Result<Vec<AuthenticatorEntry>> {
        let mut result = Vec::new();
        for entry in entries {
            match AuthenticatorEntry::deserialize(&entry) {
                Ok(entry) => result.push(entry),
                Err(e) => {
                    if fail_on_error {
                        return Err(AuthenticatorError::SerializationError(format!(
                            "error deserializing entry: {:?}",
                            e
                        )));
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn serialize_entries(&self, entries: Vec<AuthenticatorEntry>) -> Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        for entry in entries {
            result.push(
                entry
                    .serialize()
                    .map_err(|e| AuthenticatorError::SerializationError(format!("{:?}", e)))?,
            );
        }

        Ok(result)
    }

    pub fn export_entries(&self, entries: Vec<AuthenticatorEntry>) -> Result<String> {
        entry::export_entries(entries)
            .map_err(|e| AuthenticatorError::SerializationError(format!("error exporting entries: {:?}", e)))
    }

    fn generate_code(entry: &AuthenticatorEntry, time: u64) -> Result<AuthenticatorCodeResponse> {
        match &entry.content {
            AuthenticatorEntryContent::Totp(t) => {
                let period = t.get_period();
                let next_time = time + period as u64;
                let current = t
                    .generate_token(time)
                    .map_err(|e| AuthenticatorError::CodeGenerationError(format!("{:?}", e)))?;
                let next = t
                    .generate_token(next_time)
                    .map_err(|e| AuthenticatorError::CodeGenerationError(format!("{:?}", e)))?;

                Ok(AuthenticatorCodeResponse {
                    current_code: current,
                    next_code: next,
                })
            }
            AuthenticatorEntryContent::Steam(steam) => {
                let current = steam.generate(time as i64);
                let next = steam.generate((time + STEAM_PERIOD as u64) as i64);
                Ok(AuthenticatorCodeResponse {
                    current_code: current,
                    next_code: next,
                })
            }
        }
    }
}
