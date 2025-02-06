use crate::{AuthenticatorEntryActions, AuthenticatorEntryModel};
pub use proton_authenticator::AuthenticatorCodeResponse;
use proton_authenticator::{AuthenticatorClient, AuthenticatorEntry};
use proton_pass_derive::Error;
use std::sync::Arc;

#[derive(Debug, Error)]
pub struct AuthenticatorError {
    pub e: proton_authenticator::AuthenticatorError,
}

impl AuthenticatorError {
    pub fn message(&self) -> String {
        format!("{:?}", self.e)
    }
}

impl From<proton_authenticator::AuthenticatorError> for AuthenticatorError {
    fn from(e: proton_authenticator::AuthenticatorError) -> Self {
        AuthenticatorError { e }
    }
}

impl From<AuthenticatorEntry> for AuthenticatorEntryModel {
    fn from(entry: AuthenticatorEntry) -> Self {
        Self {
            name: entry.name(),
            note: entry.note.clone(),
            uri: entry.uri(),
            period: entry.period(),
            actions: Arc::new(AuthenticatorEntryActions::new(entry)),
        }
    }
}

pub struct AuthenticatorMobileClient {
    inner: AuthenticatorClient,
}

impl AuthenticatorMobileClient {
    pub fn new() -> Self {
        Self {
            inner: AuthenticatorClient::new(),
        }
    }

    pub fn entry_from_uri(&self, uri: String) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let entry = self.inner.entry_from_uri(uri)?;
        Ok(entry.into())
    }

    pub fn generate_codes(
        &self,
        entries: Vec<AuthenticatorEntryModel>,
        time: u64,
    ) -> Result<Vec<AuthenticatorCodeResponse>, AuthenticatorError> {
        let as_entries: Vec<AuthenticatorEntry> = entries.iter().map(|m| m.actions.entry()).collect();
        Ok(self.inner.generate_codes(&as_entries, time)?)
    }

    pub fn serialize_entries(&self, entries: Vec<AuthenticatorEntryModel>) -> Result<Vec<Vec<u8>>, AuthenticatorError> {
        let as_entries: Vec<AuthenticatorEntry> = entries.iter().map(|m| m.actions.entry()).collect();
        Ok(self.inner.serialize_entries(as_entries)?)
    }

    pub fn deserialize_entries(
        &self,
        entries: Vec<Vec<u8>>,
    ) -> Result<Vec<AuthenticatorEntryModel>, AuthenticatorError> {
        let deserialized = self.inner.deserialize_entries(entries, false)?;
        Ok(deserialized.into_iter().map(|m| m.into()).collect())
    }

    pub fn export_entries(&self, entries: Vec<AuthenticatorEntryModel>) -> Result<String, AuthenticatorError> {
        let as_entries: Vec<AuthenticatorEntry> = entries.iter().map(|m| m.actions.entry()).collect();
        Ok(self.inner.export_entries(as_entries)?)
    }
}
