use crate::AuthenticatorError;
use proton_authenticator::{
    AuthenticatorClient, AuthenticatorCodeResponse, AuthenticatorEntry, AuthenticatorEntryContent,
};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AuthenticatorEntryModel {
    pub name: String,
    pub uri: String,
    pub period: u16,
    pub note: Option<String>,
    pub actions: Arc<AuthenticatorEntryActions>,
}

#[derive(Clone, Debug)]
pub enum AuthenticatorEntryType {
    TOTP,
    Steam,
}

#[derive(Clone, Debug)]
pub struct AuthenticatorEntryActions {
    inner: AuthenticatorEntry,
}

impl AuthenticatorEntryActions {
    pub fn new(entry: AuthenticatorEntry) -> Self {
        Self { inner: entry }
    }

    pub fn entry_type(&self) -> AuthenticatorEntryType {
        match &self.inner.content {
            AuthenticatorEntryContent::Totp(_) => AuthenticatorEntryType::TOTP,
            AuthenticatorEntryContent::Steam(_) => AuthenticatorEntryType::Steam,
        }
    }

    pub(crate) fn entry(&self) -> AuthenticatorEntry {
        self.inner.clone()
    }

    pub fn generate_code(&self, time: u64) -> Result<AuthenticatorCodeResponse, AuthenticatorError> {
        let res = AuthenticatorClient::new().generate_codes(&[self.inner.clone()], time)?;
        if let Some(code) = res.into_iter().next() {
            Ok(code)
        } else {
            Err(AuthenticatorError {
                e: proton_authenticator::AuthenticatorError::CodeGenerationError("Could not generate code".to_string()),
            })
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, AuthenticatorError> {
        let res = AuthenticatorClient::new().serialize_entries(vec![self.inner.clone()])?;
        if let Some(code) = res.into_iter().next() {
            Ok(code)
        } else {
            Err(AuthenticatorError {
                e: proton_authenticator::AuthenticatorError::CodeGenerationError(
                    "Could not serialize entry".to_string(),
                ),
            })
        }
    }
}
