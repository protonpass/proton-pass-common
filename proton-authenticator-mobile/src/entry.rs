use crate::AuthenticatorError;
use proton_authenticator::AuthenticatorEntry;

#[derive(Clone, Debug)]
pub struct AuthenticatorEntryModel {
    pub name: String,
    pub uri: String,
    pub period: u16,
    pub issuer: String,
    pub note: Option<String>,
    pub entry_type: AuthenticatorEntryType,
}

#[derive(Clone, Debug)]
pub enum AuthenticatorEntryType {
    TOTP,
    Steam,
}

impl AuthenticatorEntryModel {
    pub fn to_entry(&self) -> Result<AuthenticatorEntry, AuthenticatorError> {
        Ok(AuthenticatorEntry::from_uri(&self.uri, self.note.clone())
            .map_err(|e| proton_authenticator::AuthenticatorError::Unknown(format!("cannot parse uri: {:?}", e)))?)
    }
}
