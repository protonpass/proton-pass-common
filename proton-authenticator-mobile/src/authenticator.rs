use crate::{AuthenticatorEntryModel, AuthenticatorEntryType};
use proton_authenticator::entry::AuthenticatorInvalidDataParam;
use proton_authenticator::{
    warn, Algorithm, AuthenticatorClient, AuthenticatorCodeResponse as CommonAuthenticatorCodeResponse,
    AuthenticatorEntry, AuthenticatorEntryContent,
    AuthenticatorEntrySteamCreateParameters as CommonSteamCreateParameters,
    AuthenticatorEntryTotpCreateParameters as CommonTotpCreateParameters,
    AuthenticatorEntryTotpParameters as CommonTotpParameters, AuthenticatorEntryUpdateContents as CommonUpdateContents,
};
use proton_pass_derive::Error;

#[derive(Debug, Error)]
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
                AuthenticatorEntryContent::Totp(_) => AuthenticatorEntryType::TOTP,
                AuthenticatorEntryContent::Steam(_) => AuthenticatorEntryType::Steam,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticatorTotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl From<AuthenticatorTotpAlgorithm> for Algorithm {
    fn from(value: AuthenticatorTotpAlgorithm) -> Self {
        match value {
            AuthenticatorTotpAlgorithm::SHA1 => Algorithm::SHA1,
            AuthenticatorTotpAlgorithm::SHA256 => Algorithm::SHA256,
            AuthenticatorTotpAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }
}

impl From<Algorithm> for AuthenticatorTotpAlgorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::SHA1 => AuthenticatorTotpAlgorithm::SHA1,
            Algorithm::SHA256 => AuthenticatorTotpAlgorithm::SHA256,
            Algorithm::SHA512 => AuthenticatorTotpAlgorithm::SHA512,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorEntryTotpCreateParameters {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub period: Option<u16>,
    pub digits: Option<u8>,
    pub algorithm: Option<AuthenticatorTotpAlgorithm>,
    pub note: Option<String>,
}

impl From<AuthenticatorEntryTotpCreateParameters> for CommonTotpCreateParameters {
    fn from(value: AuthenticatorEntryTotpCreateParameters) -> Self {
        Self {
            name: value.name,
            secret: value.secret,
            issuer: value.issuer,
            period: value.period,
            digits: value.digits,
            algorithm: value.algorithm.map(Algorithm::from),
            note: value.note,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorEntrySteamCreateParameters {
    pub name: String,
    pub secret: String,
    pub note: Option<String>,
}

impl From<AuthenticatorEntrySteamCreateParameters> for CommonSteamCreateParameters {
    fn from(value: AuthenticatorEntrySteamCreateParameters) -> Self {
        Self {
            name: value.name,
            secret: value.secret,
            note: value.note,
        }
    }
}

pub struct AuthenticatorCodeResponse {
    pub current_code: String,
    pub next_code: String,
    pub entry: AuthenticatorEntryModel,
}

impl From<CommonAuthenticatorCodeResponse> for AuthenticatorCodeResponse {
    fn from(value: CommonAuthenticatorCodeResponse) -> Self {
        Self {
            current_code: value.current_code,
            next_code: value.next_code,
            entry: AuthenticatorEntryModel::from(value.entry),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatorEntryTotpParameters {
    pub secret: String,
    pub issuer: String,
    pub period: u16,
    pub digits: u8,
    pub algorithm: AuthenticatorTotpAlgorithm,
}

impl From<CommonTotpParameters> for AuthenticatorEntryTotpParameters {
    fn from(value: CommonTotpParameters) -> Self {
        Self {
            secret: value.secret,
            issuer: value.issuer.unwrap_or_default(),
            period: value.period,
            digits: value.digits,
            algorithm: AuthenticatorTotpAlgorithm::from(value.algorithm),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatorEntryUpdateContents {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub period: u16,
    pub digits: u8,
    pub algorithm: AuthenticatorTotpAlgorithm,
    pub note: Option<String>,
    pub entry_type: AuthenticatorEntryType,
}

impl From<AuthenticatorEntryUpdateContents> for CommonUpdateContents {
    fn from(value: AuthenticatorEntryUpdateContents) -> Self {
        Self {
            name: value.name,
            secret: value.secret,
            issuer: value.issuer,
            period: value.period,
            digits: value.digits,
            algorithm: Algorithm::from(value.algorithm),
            note: value.note,
            entry_type: proton_authenticator::AuthenticatorEntryType::from(value.entry_type),
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

    pub fn new_totp_entry_from_params(
        &self,
        params: AuthenticatorEntryTotpCreateParameters,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let mapped_params = CommonTotpCreateParameters::from(params);
        let entry = AuthenticatorEntry::new_totp_entry_from_params(mapped_params)?;
        Ok(entry.into())
    }

    pub fn new_steam_entry_from_params(
        &self,
        params: AuthenticatorEntrySteamCreateParameters,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let mapped_params = CommonSteamCreateParameters::from(params);
        let entry = AuthenticatorEntry::new_steam_entry_from_params(mapped_params)?;
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
        Ok(AuthenticatorEntryTotpParameters::from(parameters))
    }

    pub fn update_entry(
        &self,
        entry: AuthenticatorEntryModel,
        update: AuthenticatorEntryUpdateContents,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let mapped_update = CommonUpdateContents::from(update);
        let mut as_entry = entry.to_entry()?;
        as_entry.update(mapped_update)?;

        Ok(as_entry.into())
    }
}
