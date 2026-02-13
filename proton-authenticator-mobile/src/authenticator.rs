use crate::AuthenticatorEntryModel;
use proton_authenticator::entry::AuthenticatorInvalidDataParam;
use proton_authenticator::{warn, AuthenticatorClient, AuthenticatorEntry};

#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AuthenticatorError {
    NoEntries,
    UnsupportedUri,
    ParseError,
    SerializationError,
    Unknown,
    InvalidName,
    InvalidSecret,
    CodeGenerationError,
    ImportBadContent,
    ImportBadPassword,
    ImportMissingPassword,
    ImportDecryptionFailed,
}

impl std::fmt::Display for AuthenticatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<proton_authenticator::AuthenticatorError> for AuthenticatorError {
    fn from(e: proton_authenticator::AuthenticatorError) -> Self {
        warn!("AuthenticatorError: {:?}", e);
        match e {
            proton_authenticator::AuthenticatorError::CodeGenerationError(_) => AuthenticatorError::CodeGenerationError,
            proton_authenticator::AuthenticatorError::SerializationError(_) => AuthenticatorError::SerializationError,
            proton_authenticator::AuthenticatorError::Unknown(_) => AuthenticatorError::Unknown,
            proton_authenticator::AuthenticatorError::Import(import_err) => AuthenticatorError::from(import_err),
        }
    }
}

impl From<proton_authenticator::AuthenticatorEntryError> for AuthenticatorError {
    fn from(e: proton_authenticator::AuthenticatorEntryError) -> Self {
        warn!("AuthenticatorEntryError: {:?}", e);
        match e {
            proton_authenticator::AuthenticatorEntryError::UnsupportedUri => AuthenticatorError::UnsupportedUri,
            proton_authenticator::AuthenticatorEntryError::ParseError => AuthenticatorError::ParseError,
            proton_authenticator::AuthenticatorEntryError::SerializationError(_) => {
                AuthenticatorError::SerializationError
            }
            proton_authenticator::AuthenticatorEntryError::Unknown(_) => AuthenticatorError::Unknown,
            proton_authenticator::AuthenticatorEntryError::InvalidData(param) => match param {
                AuthenticatorInvalidDataParam::Name => AuthenticatorError::InvalidName,
                AuthenticatorInvalidDataParam::Secret => AuthenticatorError::InvalidSecret,
            },
        }
    }
}

// Re-export core types directly
pub use proton_authenticator::{
    Algorithm as AuthenticatorTotpAlgorithm, AuthenticatorEntrySteamCreateParameters,
    AuthenticatorEntryTotpCreateParameters, AuthenticatorEntryTotpParameters, AuthenticatorEntryType,
    AuthenticatorEntryUpdateContents,
};

// Re-export the model version from core
pub use proton_authenticator::AuthenticatorCodeResponseModel as AuthenticatorCodeResponse;

// These types are now re-exported from the core crate above

#[derive(uniffi::Object)]
pub struct AuthenticatorMobileClient {
    inner: AuthenticatorClient,
}

#[uniffi::export]
impl AuthenticatorMobileClient {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: AuthenticatorClient::new(),
        }
    }

    pub fn entry_from_uri(&self, uri: String) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let entry = self.inner.entry_from_uri(uri)?;
        Ok(entry.into())
    }

    pub fn new_totp_entry_from_params(
        &self,
        params: AuthenticatorEntryTotpCreateParameters,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let entry = AuthenticatorEntry::new_totp_entry_from_params(params)?;
        Ok(entry.into())
    }

    pub fn new_steam_entry_from_params(
        &self,
        params: AuthenticatorEntrySteamCreateParameters,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let entry = AuthenticatorEntry::new_steam_entry_from_params(params)?;
        Ok(entry.into())
    }

    pub fn generate_codes(
        &self,
        entries: Vec<AuthenticatorEntryModel>,
        time: u64,
    ) -> Result<Vec<AuthenticatorCodeResponse>, AuthenticatorError> {
        let mut mapped = vec![];
        for entry in entries {
            mapped.push(entry.to_entry()?);
        }
        let codes = self.inner.generate_codes(&mapped, time)?;
        let mapped = codes.into_iter().map(AuthenticatorCodeResponse::from).collect();
        Ok(mapped)
    }

    pub fn serialize_entry(&self, entry: AuthenticatorEntryModel) -> Result<Vec<u8>, AuthenticatorError> {
        if let Some(serialized) = self.serialize_entries(vec![entry])?.into_iter().next() {
            Ok(serialized)
        } else {
            Err(AuthenticatorError::NoEntries)
        }
    }

    pub fn serialize_entries(&self, entries: Vec<AuthenticatorEntryModel>) -> Result<Vec<Vec<u8>>, AuthenticatorError> {
        let mut mapped = vec![];
        for entry in entries {
            mapped.push(entry.to_entry()?);
        }
        Ok(self.inner.serialize_entries(mapped)?)
    }

    pub fn deserialize_entry(&self, entry: Vec<u8>) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        if let Some(deserialized) = self.deserialize_entries(vec![entry])?.into_iter().next() {
            Ok(deserialized)
        } else {
            Err(AuthenticatorError::NoEntries)
        }
    }

    pub fn deserialize_entries(
        &self,
        entries: Vec<Vec<u8>>,
    ) -> Result<Vec<AuthenticatorEntryModel>, AuthenticatorError> {
        let deserialized = self.inner.deserialize_entries(entries)?;
        Ok(deserialized.into_iter().map(|m| m.into()).collect())
    }

    pub fn export_entries(&self, entries: Vec<AuthenticatorEntryModel>) -> Result<String, AuthenticatorError> {
        let mut mapped = vec![];
        for entry in entries {
            mapped.push(entry.to_entry()?);
        }
        Ok(self.inner.export_entries(mapped)?)
    }

    pub fn export_entries_with_password(
        &self,
        entries: Vec<AuthenticatorEntryModel>,
        password: String,
    ) -> Result<String, AuthenticatorError> {
        let mut mapped = vec![];
        for entry in entries {
            mapped.push(entry.to_entry()?);
        }
        Ok(self.inner.export_entries_with_password(mapped, &password)?)
    }

    pub fn get_totp_params(
        &self,
        entry: AuthenticatorEntryModel,
    ) -> Result<AuthenticatorEntryTotpParameters, AuthenticatorError> {
        let as_entry = entry.to_entry()?;
        let parameters = as_entry.get_totp_parameters()?;
        Ok(parameters)
    }

    pub fn update_entry(
        &self,
        entry: AuthenticatorEntryModel,
        update: AuthenticatorEntryUpdateContents,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let mut as_entry = entry.to_entry()?;
        as_entry.update(update)?;

        Ok(as_entry.into())
    }
}
