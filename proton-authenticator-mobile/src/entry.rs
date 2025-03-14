use crate::AuthenticatorError;
use proton_authenticator::AuthenticatorEntry;

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

#[derive(Clone, Debug)]
pub enum AuthenticatorEntryType {
    TOTP,
    Steam,
}

impl AuthenticatorEntryModel {
    pub fn to_entry(&self) -> Result<AuthenticatorEntry, AuthenticatorError> {
        Ok(
            AuthenticatorEntry::from_uri_and_id(&self.uri, self.note.clone(), self.id.clone())
                .map_err(|e| proton_authenticator::AuthenticatorError::Unknown(format!("cannot parse uri: {:?}", e)))?,
        )
    }
}
