mod exporter;
mod gen;
mod serializer;

use crate::steam::{SteamTotp, PERIOD as STEAM_PERIOD};
use proton_pass_totp::totp::TOTP;

pub use exporter::{export_entries, import_authenticator_entries};
use proton_pass_totp::Algorithm;

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum AuthenticatorEntryError {
    UnsupportedUri,
    ParseError,
    SerializationError(String),
    Unknown(String),
}

#[derive(Clone, Debug)]
pub enum AuthenticatorEntryContent {
    Totp(TOTP),
    Steam(SteamTotp),
}

impl AuthenticatorEntryContent {
    pub fn from_uri(uri: &str) -> Result<AuthenticatorEntryContent, AuthenticatorEntryError> {
        let parsed = url::Url::parse(uri).map_err(|_| AuthenticatorEntryError::UnsupportedUri)?;
        match parsed.scheme() {
            "otpauth" => {
                if parsed.host_str() == Some("steam") {
                    let steam_parsed =
                        SteamTotp::new_from_otp_uri(&parsed).map_err(|_| AuthenticatorEntryError::ParseError)?;
                    Ok(AuthenticatorEntryContent::Steam(steam_parsed))
                } else {
                    let totp = TOTP::from_uri(uri).map_err(|_| AuthenticatorEntryError::ParseError)?;
                    Ok(AuthenticatorEntryContent::Totp(totp))
                }
            }
            "steam" => {
                let steam_parsed =
                    SteamTotp::new_from_parsed_uri(&parsed, true).map_err(|_| AuthenticatorEntryError::ParseError)?;
                Ok(AuthenticatorEntryContent::Steam(steam_parsed))
            }
            _ => Err(AuthenticatorEntryError::UnsupportedUri),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatorEntry {
    pub id: String,
    pub content: AuthenticatorEntryContent,
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthenticatorEntryTotpParameters {
    pub secret: String,
    pub issuer: Option<String>,
    pub period: u16,
    pub digits: u8,
    pub algorithm: Algorithm,
}

impl AuthenticatorEntry {
    pub fn generate_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn from_uri(uri: &str, note: Option<String>) -> Result<Self, AuthenticatorEntryError> {
        Self::from_uri_and_id(uri, note, Self::generate_id())
    }

    pub fn from_uri_and_id(uri: &str, note: Option<String>, id: String) -> Result<Self, AuthenticatorEntryError> {
        let content = AuthenticatorEntryContent::from_uri(uri)?;
        Ok(AuthenticatorEntry { content, note, id })
    }

    pub fn serialize(self) -> Result<Vec<u8>, AuthenticatorEntryError> {
        serializer::serialize_entry(self)
            .map_err(|e| AuthenticatorEntryError::SerializationError(format!("error serializing entry: {}", e)))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, AuthenticatorEntryError> {
        serializer::deserialize_entry(data)
            .map_err(|e| AuthenticatorEntryError::SerializationError(format!("error deserializing entry: {:?}", e)))
    }

    pub fn uri(&self) -> String {
        match &self.content {
            AuthenticatorEntryContent::Totp(totp) => totp.to_uri(None, None),
            AuthenticatorEntryContent::Steam(steam_totp) => steam_totp.uri(),
        }
    }

    pub fn period(&self) -> u16 {
        match &self.content {
            AuthenticatorEntryContent::Totp(totp) => totp.get_period(),
            AuthenticatorEntryContent::Steam(_) => STEAM_PERIOD,
        }
    }

    pub fn name(&self) -> String {
        match &self.content {
            AuthenticatorEntryContent::Totp(totp) => match &totp.label {
                Some(label) => label.to_string(),
                None => "".to_string(),
            },
            AuthenticatorEntryContent::Steam(steam) => steam.name(),
        }
    }

    pub fn issuer(&self) -> String {
        match self.content {
            AuthenticatorEntryContent::Totp(ref totp) => match totp.issuer {
                Some(ref issuer) => issuer.to_string(),
                None => "".to_string(),
            },
            AuthenticatorEntryContent::Steam(_) => "Steam".to_string(),
        }
    }

    pub fn get_totp_parameters(&self) -> Result<AuthenticatorEntryTotpParameters, AuthenticatorEntryError> {
        match self.content {
            AuthenticatorEntryContent::Totp(ref totp) => {
                let period = totp.get_period();
                let digits = totp.get_digits();
                let algorithm = totp.get_algorithm();
                Ok(AuthenticatorEntryTotpParameters {
                    secret: totp.secret.clone(),
                    issuer: totp.issuer.clone(),
                    period,
                    digits,
                    algorithm,
                })
            }
            AuthenticatorEntryContent::Steam(_) => Err(AuthenticatorEntryError::Unknown(
                "Cannot get TOTP parameters from an entry that is not TOTP".to_string(),
            )),
        }
    }
}
