mod create;
mod crypto;
mod exporter;
mod gen;
mod password_exporter;
mod serializer;
mod update;

use crate::steam::{SteamTotp, PERIOD as STEAM_PERIOD, STEAM_DIGITS, STEAM_ISSUER};
pub use create::{AuthenticatorEntrySteamCreateParameters, AuthenticatorEntryTotpCreateParameters};
pub use crypto::{decrypt_entries, encrypt_entries};
pub use exporter::{export_entries, import_authenticator_entries};
pub use password_exporter::{export_entries_with_password, import_entries_with_password};
use proton_pass_totp::{Algorithm, TOTP};
pub use update::{AuthenticatorEntryType, AuthenticatorEntryUpdateContents};

#[derive(Clone, Debug)]
pub enum AuthenticatorInvalidDataParam {
    Name,
    Secret,
}

#[derive(Clone, Debug, proton_pass_derive::Error)]
pub enum AuthenticatorEntryError {
    UnsupportedUri,
    ParseError,
    SerializationError(String),
    Unknown(String),
    InvalidData(AuthenticatorInvalidDataParam),
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthenticatorEntryContent {
    Totp(TOTP),
    Steam(SteamTotp),
}

impl AuthenticatorEntryContent {
    pub fn from_uri(uri: &str) -> Result<AuthenticatorEntryContent, AuthenticatorEntryError> {
        let parsed = url::Url::parse(uri).map_err(|_| AuthenticatorEntryError::UnsupportedUri)?;
        let host = parsed.host_str();
        match parsed.scheme() {
            "otpauth" => {
                if host == Some("steam") {
                    let steam_parsed =
                        SteamTotp::new_from_otp_uri(&parsed).map_err(|_| AuthenticatorEntryError::ParseError)?;
                    Ok(AuthenticatorEntryContent::Steam(steam_parsed))
                } else if host == Some("hotp") {
                    warn!("Received a HOTP uri, which we don't support");
                    Err(AuthenticatorEntryError::UnsupportedUri)
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

impl PartialEq for AuthenticatorEntry {
    fn eq(&self, other: &Self) -> bool {
        if !self.id.eq(&other.id) || !self.content.eq(&other.content) {
            return false;
        }

        match (&self.note, &other.note) {
            (None, None) => true,
            (None, Some(other)) => other.is_empty(),
            (Some(this), None) => this.is_empty(),
            (Some(this), Some(other)) => this == other,
        }
    }
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
            .map_err(|e| AuthenticatorEntryError::SerializationError(format!("error serializing entry: {e}")))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, AuthenticatorEntryError> {
        serializer::deserialize_entry(data)
            .map_err(|e| AuthenticatorEntryError::SerializationError(format!("error deserializing entry: {e:?}")))
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

    pub fn secret(&self) -> String {
        match self.content {
            AuthenticatorEntryContent::Totp(ref totp) => totp.secret.to_string(),
            AuthenticatorEntryContent::Steam(ref steam) => steam.secret(),
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
            AuthenticatorEntryContent::Steam(ref steam) => Ok(AuthenticatorEntryTotpParameters {
                secret: steam.secret(),
                issuer: Some(STEAM_ISSUER.to_string()),
                period: STEAM_PERIOD,
                digits: STEAM_DIGITS as u8,
                algorithm: Algorithm::SHA1,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_handle_colon_in_label_when_parsing() {
        let input =
            "otpauth://totp/issuer:label%3Awith%3Acolons?secret=MYSECRET&issuer=issuer&algorithm=SHA256&digits=8&period=15";
        let parsed = AuthenticatorEntry::from_uri(input, None).expect("Should be able to parse");
        assert_eq!("label:with:colons", parsed.name());
        assert_eq!("issuer", parsed.issuer());

        // Same uri without the repeated issuer in the path
        let expected =
            "otpauth://totp/label%3Awith%3Acolons?secret=MYSECRET&issuer=issuer&algorithm=SHA256&digits=8&period=15";
        let uri = parsed.uri();
        assert_eq!(expected, uri);
    }

    #[test]
    fn handles_colon_when_creating_from_params() {
        let input = AuthenticatorEntryTotpCreateParameters {
            name: "label:withcolon".to_string(),
            secret: "MYSECRET".to_string(),
            issuer: "issuer".to_string(),
            period: None,
            digits: None,
            algorithm: None,
            note: None,
        };
        let entry = AuthenticatorEntry::new_totp_entry_from_params(input.clone()).expect("Should be able to create");
        assert_eq!("label:withcolon", entry.name());

        let expected =
            "otpauth://totp/label%3Awithcolon?secret=MYSECRET&issuer=issuer&algorithm=SHA1&digits=6&period=30";
        let uri = entry.uri();
        assert_eq!(expected, uri);
    }

    #[test]
    fn handles_colon_when_updating() {
        let input = AuthenticatorEntryTotpCreateParameters {
            name: "label".to_string(),
            secret: "MYSECRET".to_string(),
            issuer: "issuer".to_string(),
            period: None,
            digits: None,
            algorithm: None,
            note: None,
        };
        let mut entry =
            AuthenticatorEntry::new_totp_entry_from_params(input.clone()).expect("Should be able to create");

        entry
            .update(AuthenticatorEntryUpdateContents {
                name: "label:withcolon".to_string(),
                secret: "MYSECRET".to_string(),
                issuer: "issuer".to_string(),
                period: 30,
                digits: 6,
                algorithm: Algorithm::SHA1,
                note: None,
                entry_type: AuthenticatorEntryType::Totp,
            })
            .expect("Should be able to update");

        let expected =
            "otpauth://totp/label%3Awithcolon?secret=MYSECRET&issuer=issuer&algorithm=SHA1&digits=6&period=30";
        let uri = entry.uri();
        assert_eq!(expected, uri);
    }
}
