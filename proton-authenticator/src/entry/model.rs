// Flattened DTO version of AuthenticatorEntry for FFI bindings
use crate::{AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorEntryError, AuthenticatorEntryType};
use proton_pass_derive::ffi_type;

#[ffi_type(web_name = "WasmAuthenticatorEntryModel")]
#[derive(Clone, Debug)]
pub struct AuthenticatorEntryModel {
    pub id: String,
    pub name: String,
    pub uri: String,
    pub period: u16,
    pub issuer: String,
    pub secret: String,
    pub note: Option<String>,
    pub entry_type: AuthenticatorEntryType,
}

impl AuthenticatorEntryModel {
    pub fn to_entry(&self) -> Result<AuthenticatorEntry, AuthenticatorEntryError> {
        let mut entry = AuthenticatorEntry::from_uri_and_id(&self.uri, self.note.clone(), self.id.clone())?;

        if let AuthenticatorEntryContent::Steam(ref mut steam) = entry.content {
            if !self.name.trim().is_empty() {
                steam.set_name(Some(self.name.trim().to_string()));
            }
        }

        Ok(entry)
    }
}

impl From<AuthenticatorEntry> for AuthenticatorEntryModel {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            id: entry.id.to_string(),
            name: entry.name(),
            note: entry.note.clone(),
            uri: entry.uri(),
            issuer: entry.issuer(),
            period: entry.period(),
            secret: entry.secret(),
            entry_type: match entry.content {
                AuthenticatorEntryContent::Totp(_) => AuthenticatorEntryType::Totp,
                AuthenticatorEntryContent::Steam(_) => AuthenticatorEntryType::Steam,
            },
        }
    }
}

#[ffi_type(web_name = "WasmAuthenticatorCodeResponseModel")]
#[derive(Clone, Debug)]
pub struct AuthenticatorCodeResponseModel {
    pub current_code: String,
    pub next_code: String,
    pub entry: AuthenticatorEntryModel,
}

impl From<crate::AuthenticatorCodeResponse> for AuthenticatorCodeResponseModel {
    fn from(value: crate::AuthenticatorCodeResponse) -> Self {
        Self {
            current_code: value.current_code,
            next_code: value.next_code,
            entry: AuthenticatorEntryModel::from(value.entry),
        }
    }
}
