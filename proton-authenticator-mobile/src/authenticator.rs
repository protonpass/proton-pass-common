use crate::{AuthenticatorEntryModel, AuthenticatorEntryType};
use proton_authenticator::steam::SteamTotp;
use proton_authenticator::{
    AuthenticatorClient, AuthenticatorCodeResponse as CommonAuthenticatorCodeResponse, AuthenticatorEntry,
    AuthenticatorEntryContent,
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
            name: entry.name(),
            note: entry.note.clone(),
            uri: entry.uri(),
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

impl From<AuthenticatorTotpAlgorithm> for proton_authenticator::Algorithm {
    fn from(value: AuthenticatorTotpAlgorithm) -> Self {
        match value {
            AuthenticatorTotpAlgorithm::SHA1 => proton_authenticator::Algorithm::SHA1,
            AuthenticatorTotpAlgorithm::SHA256 => proton_authenticator::Algorithm::SHA256,
            AuthenticatorTotpAlgorithm::SHA512 => proton_authenticator::Algorithm::SHA512,
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
}

impl From<CommonAuthenticatorCodeResponse> for AuthenticatorCodeResponse {
    fn from(value: CommonAuthenticatorCodeResponse) -> Self {
        Self {
            current_code: value.current_code,
            next_code: value.next_code,
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

    pub fn serialize_entries(&self, entries: Vec<AuthenticatorEntryModel>) -> Result<Vec<Vec<u8>>, AuthenticatorError> {
        let mut mapped = vec![];
        for entry in entries {
            mapped.push(entry.to_entry()?);
        }
        Ok(self.inner.serialize_entries(mapped)?)
    }

    pub fn deserialize_entries(
        &self,
        entries: Vec<Vec<u8>>,
    ) -> Result<Vec<AuthenticatorEntryModel>, AuthenticatorError> {
        let deserialized = self.inner.deserialize_entries(entries, false)?;
        Ok(deserialized.into_iter().map(|m| m.into()).collect())
    }

    pub fn export_entries(&self, entries: Vec<AuthenticatorEntryModel>) -> Result<String, AuthenticatorError> {
        let mut mapped = vec![];
        for entry in entries {
            mapped.push(entry.to_entry()?);
        }
        Ok(self.inner.export_entries(mapped)?)
    }
}
