use crate::entry::AuthenticatorInvalidDataParam;
use crate::steam::SteamTotp;
use crate::{AuthenticatorEntry, AuthenticatorEntryContent, AuthenticatorEntryError};
use proton_pass_totp::{Algorithm, TOTP};

#[derive(Debug, Clone)]
pub struct AuthenticatorEntryTotpCreateParameters {
    pub name: String,
    pub secret: String,
    pub issuer: String,
    pub period: Option<u16>,
    pub digits: Option<u8>,
    pub algorithm: Option<Algorithm>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthenticatorEntrySteamCreateParameters {
    pub name: String,
    pub secret: String,
    pub note: Option<String>,
}

impl AuthenticatorEntry {
    pub fn new_totp_entry_from_params(
        params: AuthenticatorEntryTotpCreateParameters,
    ) -> Result<Self, AuthenticatorEntryError> {
        let (name, secret) = Self::validate_name_secret(params.name, params.secret)?;
        let totp = TOTP {
            secret,
            label: Some(name),
            issuer: Some(params.issuer),
            algorithm: params.algorithm,
            digits: params.digits,
            period: params.period,
        };
        Ok(Self {
            id: AuthenticatorEntry::generate_id(),
            content: AuthenticatorEntryContent::Totp(totp),
            note: params.note,
        })
    }

    pub fn new_steam_entry_from_params(
        params: AuthenticatorEntrySteamCreateParameters,
    ) -> Result<Self, AuthenticatorEntryError> {
        let (name, secret) = Self::validate_name_secret(params.name, params.secret)?;
        let mut steam = SteamTotp::new(&secret)
            .map_err(|_| AuthenticatorEntryError::InvalidData(AuthenticatorInvalidDataParam::Secret))?;
        steam.set_name(Some(name));
        Ok(Self {
            id: AuthenticatorEntry::generate_id(),
            content: AuthenticatorEntryContent::Steam(steam),
            note: params.note,
        })
    }

    fn validate_name_secret(name: String, secret: String) -> Result<(String, String), AuthenticatorEntryError> {
        if name.trim().is_empty() {
            return Err(AuthenticatorEntryError::InvalidData(
                AuthenticatorInvalidDataParam::Name,
            ));
        }
        if secret.trim().is_empty() {
            return Err(AuthenticatorEntryError::InvalidData(
                AuthenticatorInvalidDataParam::Secret,
            ));
        }

        Ok((name.trim().to_string(), secret.trim().to_string()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_name_returns_error() {
        let entry = AuthenticatorEntry::new_totp_entry_from_params(AuthenticatorEntryTotpCreateParameters {
            name: "".to_string(),
            secret: "NON_EMPTY".to_string(),
            issuer: "NON_EMPTY".to_string(),
            period: None,
            digits: None,
            algorithm: None,
            note: None,
        });

        assert!(matches!(
            entry,
            Err(AuthenticatorEntryError::InvalidData(
                AuthenticatorInvalidDataParam::Name
            ))
        ));
    }

    #[test]
    fn empty_secret_returns_error() {
        let entry = AuthenticatorEntry::new_totp_entry_from_params(AuthenticatorEntryTotpCreateParameters {
            name: "NON_EMPTY".to_string(),
            secret: "".to_string(),
            issuer: "NON_EMPTY".to_string(),
            period: None,
            digits: None,
            algorithm: None,
            note: None,
        });

        assert!(matches!(
            entry,
            Err(AuthenticatorEntryError::InvalidData(
                AuthenticatorInvalidDataParam::Secret
            ))
        ));
    }
}
