use crate::{AuthenticatorEntryModel, AuthenticatorEntryType};
use proton_authenticator::steam::SteamTotp;
use proton_authenticator::{
    Algorithm, AuthenticatorClient, AuthenticatorCodeResponse as CommonAuthenticatorCodeResponse, AuthenticatorEntry,
    AuthenticatorEntryContent, AuthenticatorEntryTotpParameters as CommonTotpParameters,
};
use proton_pass_derive::Error;

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
            id: entry.id.to_string(),
            name: entry.name(),
            note: entry.note.clone(),
            uri: entry.uri(),
            issuer: entry.issuer(),
            period: entry.period(),
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
    pub issuer: Option<String>,
    pub period: Option<u16>,
    pub digits: Option<u8>,
    pub algorithm: Option<AuthenticatorTotpAlgorithm>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorEntrySteamCreateParameters {
    pub name: String,
    pub secret: String,
    pub note: Option<String>,
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
    pub issuer: Option<String>,
    pub period: u16,
    pub digits: u8,
    pub algorithm: AuthenticatorTotpAlgorithm,
}

impl From<CommonTotpParameters> for AuthenticatorEntryTotpParameters {
    fn from(value: CommonTotpParameters) -> Self {
        Self {
            secret: value.secret,
            issuer: value.issuer,
            period: value.period,
            digits: value.digits,
            algorithm: AuthenticatorTotpAlgorithm::from(value.algorithm),
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
        let entry = AuthenticatorEntry {
            id: AuthenticatorEntry::generate_id(),
            content: AuthenticatorEntryContent::Totp(proton_authenticator::TOTP {
                label: Some(params.name),
                secret: params.secret,
                issuer: params.issuer,
                algorithm: params.algorithm.map(proton_authenticator::Algorithm::from),
                digits: params.digits,
                period: params.period,
            }),
            note: params.note,
        };
        Ok(entry.into())
    }

    pub fn new_steam_entry_from_params(
        &self,
        params: AuthenticatorEntrySteamCreateParameters,
    ) -> Result<AuthenticatorEntryModel, AuthenticatorError> {
        let mut steam = SteamTotp::new(&params.secret).map_err(|_| AuthenticatorError {
            e: proton_authenticator::AuthenticatorError::Unknown("Invalid secret".to_string()),
        })?;

        steam.set_name(Some(params.name));
        let entry = AuthenticatorEntry {
            id: AuthenticatorEntry::generate_id(),
            content: AuthenticatorEntryContent::Steam(steam),
            note: params.note,
        };
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
            Err(AuthenticatorError {
                e: proton_authenticator::AuthenticatorError::Unknown("No entries".to_string()),
            })
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
            Err(AuthenticatorError {
                e: proton_authenticator::AuthenticatorError::Unknown("No entries".to_string()),
            })
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

    pub fn get_totp_params(
        &self,
        entry: AuthenticatorEntryModel,
    ) -> Result<AuthenticatorEntryTotpParameters, AuthenticatorError> {
        let as_entry = entry.to_entry()?;
        let parameters = as_entry.get_totp_parameters().map_err(|e| AuthenticatorError {
            e: proton_authenticator::AuthenticatorError::Unknown(e.to_string()),
        })?;
        Ok(AuthenticatorEntryTotpParameters::from(parameters))
    }
}
