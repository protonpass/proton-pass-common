use crate::authenticator::steam::SteamTotp;
use crate::totp::totp::TOTP;

#[derive(Clone, Debug)]
pub enum AuthenticatorEntryError {
    UnsupportedUri,
    ParseError,
}

#[derive(Clone, Debug)]
pub enum AuthenticatorEntryContent {
    Totp(TOTP),
    Steam(SteamTotp),
}

#[derive(Clone, Debug)]
pub struct AuthenticatorEntry {
    pub content: AuthenticatorEntryContent,
    pub note: Option<String>,
}

impl AuthenticatorEntry {
    pub fn from_uri(uri: &str, note: Option<String>) -> Result<Self, AuthenticatorEntryError> {
        let parsed = url::Url::parse(uri).map_err(|_| AuthenticatorEntryError::UnsupportedUri)?;
        let content = match parsed.scheme() {
            "otpauth" => {
                if parsed.host_str() == Some("steam") {
                    let steam_parsed =
                        SteamTotp::new_from_otp_uri(&parsed).map_err(|_| AuthenticatorEntryError::ParseError)?;
                    AuthenticatorEntryContent::Steam(steam_parsed)
                } else {
                    let totp = TOTP::from_uri(uri).map_err(|_| AuthenticatorEntryError::ParseError)?;
                    AuthenticatorEntryContent::Totp(totp)
                }
            }
            "steam" => {
                let steam_parsed =
                    SteamTotp::new_from_parsed_uri(&parsed, true).map_err(|_| AuthenticatorEntryError::ParseError)?;
                AuthenticatorEntryContent::Steam(steam_parsed)
            }
            _ => return Err(AuthenticatorEntryError::UnsupportedUri),
        };

        Ok(AuthenticatorEntry { content, note })
    }
}
